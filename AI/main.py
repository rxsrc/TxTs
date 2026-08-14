import sys
import asyncio
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QStackedWidget,
    QLineEdit, QTextEdit, QComboBox, QMessageBox
)
import qasync
from backend import SecureP2PNode, PasskeyAuth

TELEGRAM_IOS_STYLE = """
    QMainWindow { background-color: #0e1621; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto; }
    QWidget { background-color: #0e1621; color: #ffffff; }
    QPushButton { background-color: #2b5278; color: #ffffff; border-radius: 12px; padding: 10px; font-weight: bold; font-size: 14px; border: none; }
    QPushButton:hover { background-color: #3b6b9d; }
    QPushButton#danger { background-color: #a83232; }
    QPushButton#danger:hover { background-color: #c93b3b; }
    QLabel { font-size: 15px; color: #f5f5f5; }
    QStackedWidget { background-color: #17212b; border-radius: 14px; }
    QLineEdit, QTextEdit, QComboBox { background-color: #18222d; color: #ffffff; border: 1px solid #2b5278; border-radius: 8px; padding: 8px; font-size: 14px; }
    QTextEdit { background-color: #0e1621; }
"""


class TelegramWindow(QMainWindow):
    def __init__(self, node: SecureP2PNode, auth: PasskeyAuth):
        super().__init__()
        self.node = node
        self.auth = auth
        # "ip:port" -> peer_id, populated once you've exchanged/added a
        # peer's public key. Needed because send_message() now requires
        # a peer_id to pick the right derived shared-secret key.
        self.peer_ids = {}

        self.setWindowTitle("Secure P2P Messenger")
        self.setFixedSize(420, 720)
        self.setStyleSheet(TELEGRAM_IOS_STYLE)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.stack = QStackedWidget()
        self.init_chats_page()
        self.init_profile_page()
        self.init_settings_page()

        self.stack.addWidget(self.chats_page)
        self.stack.addWidget(self.profile_page)
        self.stack.addWidget(self.settings_page)
        main_layout.addWidget(self.stack)

        nav_layout = QHBoxLayout()
        btn_chats = QPushButton("Chats")
        btn_profile = QPushButton("Profile")
        btn_settings = QPushButton("Settings")

        btn_chats.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        btn_profile.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        btn_settings.clicked.connect(lambda: self.stack.setCurrentIndex(2))

        nav_layout.addWidget(btn_chats)
        nav_layout.addWidget(btn_profile)
        nav_layout.addWidget(btn_settings)
        main_layout.addLayout(nav_layout)

    def init_chats_page(self):
        self.chats_page = QWidget()
        layout = QVBoxLayout(self.chats_page)

        title = QLabel("\U0001F4AC Active P2P Chat Feed")
        title.setStyleSheet("font-weight: bold; font-size: 18px; color: #5288c1;")
        layout.addWidget(title)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.append(f"System: Your node id is {self.node.my_id}")
        self.chat_display.append("System: Add a peer's public key below before sending.")
        layout.addWidget(self.chat_display)

        peer_layout = QHBoxLayout()
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.setPlaceholderText("Peer IP")
        self.port_input = QLineEdit("8888")
        self.port_input.setPlaceholderText("Port")
        peer_layout.addWidget(self.ip_input)
        peer_layout.addWidget(self.port_input)
        layout.addLayout(peer_layout)

        self.peer_key_input = QLineEdit()
        self.peer_key_input.setPlaceholderText("Paste peer's public key here")
        layout.addWidget(self.peer_key_input)

        add_peer_btn = QPushButton("Add / Update Peer")
        add_peer_btn.clicked.connect(self.handle_add_peer)
        layout.addWidget(add_peer_btn)

        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type encrypted message...")
        layout.addWidget(self.msg_input)

        send_btn = QPushButton("Send Secure Message")
        send_btn.clicked.connect(self.handle_send_message)
        layout.addWidget(send_btn)

    def init_profile_page(self):
        self.profile_page = QWidget()
        layout = QVBoxLayout(self.profile_page)

        title = QLabel("\U0001F464 Decentralized Profile")
        title.setStyleSheet("font-weight: bold; font-size: 18px; color: #5288c1;")
        layout.addWidget(title)

        cred = self.auth.export_passkey_credential()
        self.cred_label = QLabel(f"Passkey Credential ID:\n{cred[:40]}...")
        self.cred_label.setWordWrap(True)
        layout.addWidget(self.cred_label)

        share_label = QLabel("Your Public Key (share this with peers so they can message you):")
        share_label.setWordWrap(True)
        layout.addWidget(share_label)

        self.my_key_display = QTextEdit()
        self.my_key_display.setReadOnly(True)
        self.my_key_display.setPlainText(self.node.export_public_key())
        self.my_key_display.setFixedHeight(90)
        layout.addWidget(self.my_key_display)

        copy_btn = QPushButton("Copy My Public Key")
        copy_btn.clicked.connect(self.handle_copy_key)
        layout.addWidget(copy_btn)

        auth_test_btn = QPushButton("Simulate Passkey Authentication")
        auth_test_btn.clicked.connect(self.handle_passkey_auth)
        layout.addWidget(auth_test_btn)
        layout.addStretch()

    def init_settings_page(self):
        self.settings_page = QWidget()
        layout = QVBoxLayout(self.settings_page)

        title = QLabel("\u2699\uFE0F Ephemeral Settings")
        title.setStyleSheet("font-weight: bold; font-size: 18px; color: #5288c1;")
        layout.addWidget(title)

        retention_label = QLabel("Message Retention Window:")
        layout.addWidget(retention_label)

        self.retention_combo = QComboBox()
        self.retention_combo.addItems(["24 Hours", "7 Days", "1 Month"])
        self.retention_combo.currentIndexChanged.connect(self.update_retention_policy)
        layout.addWidget(self.retention_combo)

        purge_btn = QPushButton("Purge All Local Encrypted Storage Now")
        purge_btn.setObjectName("danger")
        purge_btn.clicked.connect(self.manual_purge)
        layout.addWidget(purge_btn)
        layout.addStretch()

    def handle_add_peer(self):
        ip = self.ip_input.text().strip()
        try:
            port = int(self.port_input.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Error", "Invalid port number.")
            return

        pubkey_b64 = self.peer_key_input.text().strip()
        if not pubkey_b64:
            QMessageBox.warning(self, "Error", "Paste the peer's public key first.")
            return

        try:
            peer_id = self.node.add_peer(pubkey_b64)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Invalid public key: {e}")
            return

        self.peer_ids[f"{ip}:{port}"] = peer_id
        self.chat_display.append(f"System: Linked peer {peer_id} to {ip}:{port}.")

    def handle_send_message(self):
        text = self.msg_input.text().strip()
        if not text:
            return
        ip = self.ip_input.text().strip()
        try:
            port = int(self.port_input.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Error", "Invalid port number.")
            return

        addr_key = f"{ip}:{port}"
        peer_id = self.peer_ids.get(addr_key)
        if not peer_id:
            QMessageBox.warning(
                self, "No peer key",
                "Add this peer's public key first (Chats page) before sending."
            )
            return

        self.chat_display.append(f"Me: {text}")
        self.msg_input.clear()
        asyncio.ensure_future(self.node.send_message(peer_id, ip, port, text))

    def handle_copy_key(self):
        QApplication.clipboard().setText(self.node.export_public_key())
        QMessageBox.information(self, "Copied", "Public key copied to clipboard.")

    def handle_passkey_auth(self):
        challenge = "telegram-ios-secure-challenge-12345"
        sig = self.auth.authenticate_challenge(challenge)
        QMessageBox.information(self, "Passkey Verified", f"Cryptographic signature successfully generated:\n{sig[:30]}...")

    def update_retention_policy(self, index):
        hours_map = {0: 24, 1: 168, 2: 730}
        self.node.retention_seconds = hours_map.get(index, 24) * 3600
        QMessageBox.information(self, "Updated", "Ephemeral expiration window updated.")

    def manual_purge(self):
        self.node.purge_expired_messages()
        QMessageBox.information(self, "Purged", "All non-compliant ephemeral records wiped.")


def run_app():
    app = QApplication(sys.argv)

    # qasync bridges Qt's event loop with asyncio so PyQt6 and
    # asyncio.start_server / open_connection can share one loop.
    # This replaces the old asyncio.get_event_loop() call, which raises
    # RuntimeError on Python 3.12+ when no loop is already running.
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    splash = QLabel("\nSecure P2P Client", alignment=Qt.AlignmentFlag.AlignCenter)
    splash.setStyleSheet("background-color: #000000; color: white; font-size: 22px; font-weight: bold;")
    splash.setFixedSize(420, 720)
    splash.show()

    auth = PasskeyAuth()
    node = SecureP2PNode(retention_hours=24)

    with loop:
        loop.create_task(node.start_server())

        window = TelegramWindow(node, auth)

        def show_main():
            splash.close()
            window.show()

        QTimer.singleShot(1500, show_main)
        loop.run_forever()


if __name__ == "__main__":
    run_app()
