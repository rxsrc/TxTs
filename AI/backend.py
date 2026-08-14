import asyncio
import json
import os
import time
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _fingerprint(pub_key) -> str:
    """Short, public, non-secret identifier derived from an EC public key."""
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


def _load_or_create_ec_key(path: str) -> ec.EllipticCurvePrivateKey:
    """Persist an EC identity key to disk so it survives restarts.
    NOTE: stored unencrypted here for demo purposes. Before shipping this,
    wrap it with an OS keychain (Keychain/DPAPI/libsecret) or at least a
    passphrase-derived key -- a plaintext private key on disk defeats the
    point of passwordless identity."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Add an instance check to satisfy strict typing and ensure runtime safety
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise TypeError("The loaded key is not an EllipticCurvePrivateKey.")
            
            return key
            
    key = ec.generate_private_key(ec.SECP256R1())
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX perms
    return key


class SecureP2PNode:
    """
    Async P2P node. Two cryptographic domains are kept deliberately separate:

      - local_cipher: encrypts flat files at rest on THIS device only.
      - per-peer cipher: a unique Fernet key derived per peer via
        ECDH + HKDF from a persisted static EC keypair, used for messages
        in transit (and their locally-stored copies).

    The original draft used one Fernet key for both, generated fresh on
    every launch. That meant (a) two different nodes could never decrypt
    each other's messages at all, and (b) local storage and network
    transport shared one trust boundary. Both are fixed below.
    """

    def __init__(self, host='127.0.0.1', port=8888, retention_hours=24,
                 data_dir="p2p_data"):
        self.host = host
        self.port = port
        self.data_dir = data_dir
        self.storage_dir = os.path.join(data_dir, "ephemeral_store")
        self.retention_seconds = retention_hours * 3600
        os.makedirs(self.storage_dir, exist_ok=True)

        # --- local at-rest encryption key (persisted across restarts,
        #     otherwise every relaunch orphans all previously stored
        #     messages) ---
        local_key_path = os.path.join(data_dir, "local_store.key")
        if os.path.exists(local_key_path):
            with open(local_key_path, "rb") as f:
                self.local_key = f.read()
        else:
            self.local_key = Fernet.generate_key()
            with open(local_key_path, "wb") as f:
                f.write(self.local_key)
        self.local_cipher = Fernet(self.local_key)

        # --- static EC identity used ONLY for ECDH key agreement.
        #     Deliberately a *different* key from PasskeyAuth's signing
        #     key -- signing and key-agreement should never share one
        #     EC keypair. ---
        enc_key_path = os.path.join(data_dir, "encryption_identity.pem")
        self.enc_private_key = _load_or_create_ec_key(enc_key_path)
        self.enc_public_key = self.enc_private_key.public_key()
        self.my_id = _fingerprint(self.enc_public_key)

        self.known_peers = {}    # peer_id -> EllipticCurvePublicKey
        self._peer_ciphers = {}  # peer_id -> Fernet (cached derived key)

    # ---------- peer key exchange ----------

    def export_public_key(self) -> str:
        """Share this string with a peer out-of-band (paste, QR, etc.)
        so they can add you as a contact."""
        pub_bytes = self.enc_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(pub_bytes).decode('utf-8')

    def add_peer(self, peer_pubkey_b64: str) -> str:
        """Register a peer's static public key. Returns the peer_id to use
        when addressing them in send_message()."""
        pub_bytes = base64.b64decode(peer_pubkey_b64)
        pub_key = serialization.load_pem_public_key(pub_bytes)
        peer_id = _fingerprint(pub_key)
        self.known_peers[peer_id] = pub_key
        self._peer_ciphers.pop(peer_id, None)
        return peer_id

    def _cipher_for_peer(self, peer_id: str) -> Fernet:
        if peer_id in self._peer_ciphers:
            return self._peer_ciphers[peer_id]
        peer_pub = self.known_peers.get(peer_id)
        if peer_pub is None:
            raise ValueError(f"Unknown peer '{peer_id}' -- exchange public keys first.")
        shared_secret = self.enc_private_key.exchange(ec.ECDH(), peer_pub)
        derived = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"secure-p2p-messenger/v1",
        ).derive(shared_secret)
        cipher = Fernet(base64.urlsafe_b64encode(derived))
        self._peer_ciphers[peer_id] = cipher
        return cipher

    # ---------- networking ----------

    async def handle_peer(self, reader, writer):
        data = await reader.read(65536)
        if data:
            try:
                envelope = json.loads(data.decode())
                peer_id = envelope["from"]
                ct = base64.b64decode(envelope["ct"])
                cipher = self._cipher_for_peer(peer_id)
                message_obj = json.loads(cipher.decrypt(ct).decode())
                message_obj["peer_id"] = peer_id
                message_obj["direction"] = "in"
                self._save_message(message_obj)
            except Exception as e:
                print(f"Decryption/Parsing error: {e}")
        writer.close()
        await writer.wait_closed()

    def _save_message(self, msg):
        filename = os.path.join(
            self.storage_dir, f"{msg.get('timestamp', time.time())}.enc"
        )
        payload = self.local_cipher.encrypt(json.dumps(msg).encode())
        with open(filename, 'wb') as f:
            f.write(payload)
        self.purge_expired_messages()

    def purge_expired_messages(self):
        now = time.time()
        if not os.path.exists(self.storage_dir):
            return
        for f in os.listdir(self.storage_dir):
            filepath = os.path.join(self.storage_dir, f)
            if os.path.isfile(filepath):
                try:
                    # rsplit so a timestamp like 1699999999.123456 (which
                    # itself contains a '.') doesn't get truncated by a
                    # naive split on the first dot.
                    file_time = float(f.rsplit('.', 1)[0])
                    if now - file_time > self.retention_seconds:
                        os.remove(filepath)
                except ValueError:
                    pass

    async def start_server(self):
        server = await asyncio.start_server(self.handle_peer, self.host, self.port)
        addr = server.sockets[0].getsockname()
        print(f"P2P Server active on {addr} -- my_id={self.my_id}")
        async with server:
            await server.serve_forever()

    async def send_message(self, peer_id, peer_host, peer_port, message_text, sender="Me"):
        cipher = self._cipher_for_peer(peer_id)  # raises ValueError if unknown peer
        msg = {"sender": sender, "text": message_text, "timestamp": time.time()}
        ct = cipher.encrypt(json.dumps(msg).encode())
        envelope = json.dumps({
            "from": self.my_id,
            "ct": base64.b64encode(ct).decode(),
        }).encode()

        self._save_message({**msg, "peer_id": peer_id, "direction": "out"})
        try:
            reader, writer = await asyncio.open_connection(peer_host, peer_port)
            writer.write(envelope)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            print(f"Failed to send to peer: {e}")
            return False


class PasskeyAuth:
    """FIDO2-style challenge/response identity, backed by a persisted
    ECDSA keypair kept separate from SecureP2PNode's ECDH key."""

    def __init__(self, data_dir="p2p_data"):
        os.makedirs(data_dir, exist_ok=True)
        key_path = os.path.join(data_dir, "signing_identity.pem")
        self.private_key = _load_or_create_ec_key(key_path)
        self.public_key = self.private_key.public_key()

    def export_passkey_credential(self):
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(pub_bytes).decode('utf-8')

    def authenticate_challenge(self, challenge_str: str) -> str:
        challenge_bytes = challenge_str.encode('utf-8')
        signature = self.private_key.sign(challenge_bytes, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode('utf-8')

    def verify_challenge(self, challenge_str: str, signature_b64: str, pub_key=None) -> bool:
        """Verify a signed challenge -- needed once you're checking a
        peer's identity rather than just your own (e.g. mutual auth)."""
        pub_key = pub_key or self.public_key
        try:
            pub_key.verify(
                base64.b64decode(signature_b64),
                challenge_str.encode('utf-8'),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except Exception:
            return False
