

import sys
import os
import json
import socket
import queue
import threading
import time
import hashlib

LOCAL_SPAM_THRESHOLD = 5
import html
from datetime import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QStackedWidget, QLineEdit, QPushButton, QLabel, QListWidget,
    QListWidgetItem, QTextEdit, QMessageBox, QFrame, QScrollArea,
    QDialog, QFormLayout
)
from PySide6.QtCore import Qt, QTimer, Signal, QObject, QSize
from PySide6.QtGui import QFont, QIcon, QPixmap, QColor, QTextCursor, QTextBlockFormat
from firebase_config import firebase
# Fernet key handling: either from env `FERNET_KEY`, from `fernet.key`,
# or generated once and written to `fernet.key` for convenience.

FERNET = None
try:
    from cryptography.fernet import Fernet
    _fkey = os.getenv("FERNET_KEY", "").strip()
    if not _fkey:
        if os.path.exists("fernet.key"):
            try:
                with open("fernet.key", "r", encoding="utf-8") as fk:
                    _fkey = fk.read().strip()
            except Exception:
                _fkey = ""

    # If no key provided or found, generate one and persist to fernet.key (ONLY if file doesn't exist)
    if not _fkey:
        if not os.path.exists("fernet.key"):
            try:
                _fkey = Fernet.generate_key().decode()
                try:
                    with open("fernet.key", "w", encoding="utf-8") as fk:
                        fk.write(_fkey)
                    print("[SEC] Yeni fernet.key oluşturuldu ve kaydedildi")
                except Exception as e:
                    print(f"[SEC] fernet.key kaydedilemedi: {e}")
            except Exception as e:
                print(f"[SEC] Fernet anahtari olusturulamadi: {e}")
                _fkey = ""

    if _fkey:
        try:
            FERNET = Fernet(_fkey.encode() if isinstance(_fkey, str) else _fkey)
            print("[SEC] Fernet aktif")
        except Exception as e:
            print(f"[SEC] Fernet anahtari ile baslatilamadi: {e}")
    else:
        print("[SEC] Fernet anahtari bulunamadi; sifreleme devre disi.")
except Exception:
    print("[SEC] cryptography kütüphanesi yok veya import edilemedi; Fernet devre disi.")


def _encrypt_text_if_needed(text: str) -> str:
    if not FERNET or not isinstance(text, str) or not text:
        return text
    try:
        token = FERNET.encrypt(text.encode("utf-8"))
        return f"enc:v1:{token.decode('utf-8')}"
    except Exception:
        return text


def _maybe_decrypt_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    if not text.startswith("enc:v1:"):
        return text
    if not FERNET:
        return "[Encrypted message - no key available]"
    try:
        token = text.split(":", 2)[2]
        plain = FERNET.decrypt(token.encode("utf-8"))
        return plain.decode("utf-8")
    except Exception:
        # Decryption failed (likely wrong/missing key or corrupted token).
        # Show a clearer message so user can troubleshoot key sync.
        return "[Encrypted message could not be decrypted]"


def _normalize_host(raw_host: str) -> str:
    host = str(raw_host or "").strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    return host.rstrip("/")


def _load_socket_config_from_file(file_path: str = "socket_endpoint.json"):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        host = _normalize_host(data.get("host", ""))
        port = int(data.get("port", 0))
        if host and port > 0:
            return host, port
    except Exception:
        pass
    return None


# Priority: env vars > socket_endpoint.json > fallback
_env_host = _normalize_host(os.getenv("CHAT_SOCKET_HOST", ""))
_env_port = os.getenv("CHAT_SOCKET_PORT", "").strip()

if _env_host and _env_port:
    SOCKET_HOST = _env_host
    SOCKET_PORT = int(_env_port)
else:
    file_cfg = _load_socket_config_from_file()
    if file_cfg:
        SOCKET_HOST, SOCKET_PORT = file_cfg
    else:
        SOCKET_HOST = _normalize_host("tcp://2.tcp.ngrok.io")
        SOCKET_PORT = 29718

print(f"[CONFIG] CHAT_SOCKET_HOST={SOCKET_HOST} CHAT_SOCKET_PORT={SOCKET_PORT}")


class SocketChatClient:
    """Background socket bridge for real-time message delivery."""

    def __init__(self, host: str, port: int, event_queue: queue.Queue):
        self.host = host
        self.port = port
        self.event_queue = event_queue
        self.sock = None
        self.reader = None
        self.running = False
        self.thread = None
        self._sock_lock = threading.Lock()

    def connect(self, uid: str, username: str, token: str = "") -> bool:
        self.disconnect(close_only=True)

        try:
            with self._sock_lock:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(8)
                self.sock.connect((self.host, self.port))
                self.sock.settimeout(None)
                self.reader = self.sock.makefile("r", encoding="utf-8", newline="\n")
            self.running = True
            self._send_packet({
                "type": "auth",
                "uid": uid,
                "name": username,
                "token": token,
            })
            self.thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.thread.start()
            self.event_queue.put({"type": "connection", "connected": True})
            return True
        except Exception as exc:
            self.event_queue.put({"type": "connection", "connected": False, "error": str(exc)})
            self.disconnect(close_only=True)
            return False

    def _send_packet(self, payload: dict) -> None:
        message = json.dumps(payload, ensure_ascii=False) + "\n"
        try:
            with self._sock_lock:
                if not self.sock:
                    return
                self.sock.sendall(message.encode("utf-8"))
        except Exception as exc:
            self.event_queue.put({"type": "connection", "connected": False, "error": str(exc)})

    def send_message(self, sender_uid: str, sender_name: str, receiver_uid: str, text: str, fingerprint: str = None) -> None:
        payload = {
            "type": "message",
            "sender_uid": sender_uid,
            "sender_name": sender_name,
            "receiver_uid": receiver_uid,
            "text": text,
            "timestamp": datetime.now().isoformat(),
        }
        if fingerprint:
            payload["fingerprint"] = fingerprint
        self._send_packet(payload)

    def _receive_loop(self) -> None:
        try:
            while self.running and self.reader:
                line = self.reader.readline()
                if not line:
                    break

                text = line.strip()
                if not text:
                    continue

                try:
                    packet = json.loads(text)
                except Exception:
                    packet = {"type": "text", "text": text}

                self.event_queue.put(packet)
        except Exception as exc:
            # Ignore expected operation-on-closed-socket noise during disconnect/reconnect.
            is_win_10038 = isinstance(exc, OSError) and getattr(exc, "winerror", None) == 10038
            if self.running and not is_win_10038:
                self.event_queue.put({"type": "connection", "connected": False, "error": str(exc)})
        finally:
            self.running = False
            self.event_queue.put({"type": "connection", "connected": False})
            self.disconnect(close_only=True)

    def disconnect(self, close_only: bool = False) -> None:
        self.running = False

        with self._sock_lock:
            try:
                if self.reader:
                    self.reader.close()
            except Exception:
                pass
            self.reader = None

            try:
                if self.sock:
                    self.sock.close()
            except Exception:
                pass
            self.sock = None

        if not close_only:
            self.event_queue.put({"type": "connection", "connected": False})


class MessageSignals(QObject):
    """Message signals"""
    new_message = Signal(str, str, str)
    # chat_updated: emits dict {users, friends, recent_chats}
    chat_updated = Signal(dict)
    # chat_loaded: emits dict {messages, other_username}
    chat_loaded = Signal(dict)
    # profile_loaded: emits dict {uid, name, tag}
    profile_loaded = Signal(dict)
    connection_changed = Signal(bool)


class LoginWindow(QWidget):
    """Login / Signup screen (mobile style)"""
    login_result = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self._login_in_progress = False
        # Brute-force login tracking (client-side) per-account
        self.failed_login_counts = {}  # email -> count
        self.login_blocked_untils = {}  # email -> timestamp
        self.failed_login_reset_time = {}  # email -> timestamp (optional)
        self.login_result.connect(self._on_login_result)
        self.init_ui()
        

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(14)
        layout.setContentsMargins(28, 28, 28, 28)

        # Header
        title = QLabel("🔒 Secure Chat")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Log in or Sign up")
        subtitle.setFont(QFont("Arial", 10))
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        layout.addSpacing(24)

        login_label = QLabel("LOGIN")
        login_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(login_label)

        self.login_email = QLineEdit()
        self.login_email.setPlaceholderText("Email")
        self.login_email.setMinimumHeight(40)
        layout.addWidget(self.login_email)

        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Password")
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_password.setMinimumHeight(40)
        layout.addWidget(self.login_password)

        self.login_btn = QPushButton("Log In")
        self.login_btn.setMinimumHeight(46)
        self.login_btn.setFont(QFont("Arial", 11, QFont.Bold))
        self.login_btn.setStyleSheet(
            "QPushButton { background-color: #128C7E; color: white; border: none; border-radius: 23px; padding: 10px 14px; }"
            "QPushButton:hover { background-color: #0f7f72; }"
            "QPushButton:pressed { background-color: #0d6f64; }"
        )
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)

        layout.addSpacing(14)

        signup_label = QLabel("SIGN UP")
        signup_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(signup_label)

        self.signup_username = QLineEdit()
        self.signup_username.setPlaceholderText("Username")
        self.signup_username.setMinimumHeight(40)
        layout.addWidget(self.signup_username)

        self.signup_email = QLineEdit()
        self.signup_email.setPlaceholderText("Email")
        self.signup_email.setMinimumHeight(40)
        layout.addWidget(self.signup_email)

        self.signup_password = QLineEdit()
        self.signup_password.setPlaceholderText("Password")
        self.signup_password.setEchoMode(QLineEdit.Password)
        self.signup_password.setMinimumHeight(40)
        layout.addWidget(self.signup_password)

        self.signup_btn = QPushButton("Sign Up")
        self.signup_btn.setMinimumHeight(46)
        self.signup_btn.setFont(QFont("Arial", 11, QFont.Bold))
        self.signup_btn.setStyleSheet(
            "QPushButton { background-color: #25D366; color: white; border: none; border-radius: 23px; padding: 10px 14px; }"
            "QPushButton:hover { background-color: #20bf5a; }"
            "QPushButton:pressed { background-color: #19a64d; }"
        )
        self.signup_btn.clicked.connect(self.handle_signup)
        layout.addWidget(self.signup_btn)

        layout.addStretch()

        self.setLayout(layout)
        self.setObjectName("loginRoot")
        self.setStyleSheet(
            "#loginRoot {"
            " background: qlineargradient(x1:0 y1:0, x2:1 y2:1, stop:0 #eaf7f4, stop:1 #f8fbff);"
            "}"
            "QLineEdit { background: rgba(255,255,255,0.98); border: 1px solid #d9e6e2; border-radius: 18px; padding: 11px 14px; font-size: 14px; }"
            "QLineEdit:focus { border: 1px solid #25D366; }"
            "QLabel { color: #18342e; }"
        )

    def handle_login(self):
        if self._login_in_progress:
            return

        email = self.login_email.text().strip()
        password = self.login_password.text()

        # Check client-side login block for this email
        now_ts = time.time()
        blocked_until = self.login_blocked_untils.get(email, 0)
        if now_ts < blocked_until:
            remain = int(blocked_until - now_ts)
            QMessageBox.warning(self, "Blocked", f"Too many failed attempts for this account. Try again in {remain}s")
            return

        if not email or not password:
            QMessageBox.warning(self, "Error", "Email and password required!")
            return

        self._login_in_progress = True
        self.login_btn.setEnabled(False)
        self.login_btn.setText("Logging in...")

        def _login_worker(user_email, user_password):
            try:
                result = firebase.login_user(user_email, user_password)
                if isinstance(result, dict):
                    result["email"] = user_email
                    self.login_result.emit(result)
                else:
                    self.login_result.emit({"success": False, "message": "Invalid login response", "email": user_email})
            except Exception as e:
                self.login_result.emit({"success": False, "message": f"Login error: {str(e)}", "email": user_email})

        threading.Thread(target=_login_worker, args=(email, password), daemon=True).start()

    def _on_login_result(self, result: dict):
        self._login_in_progress = False
        self.login_btn.setEnabled(True)
        self.login_btn.setText("Log In")

        if result.get("success"):
            email = result.get("email") or self.login_email.text().strip()
            # Reset failed login tracking on success for this account
            try:
                self.failed_login_counts[email] = 0
                self.login_blocked_untils[email] = 0.0
            except Exception:
                pass
            self.parent_window.login(result.get("uid", ""), email, result.get("token", ""))
            return

        # On failure, increment failed count for this email and possibly block for 5 minutes
        try:
            email = result.get("email") or self.login_email.text().strip()
            count = self.failed_login_counts.get(email, 0) + 1
            self.failed_login_counts[email] = count
            if count >= 5:
                self.login_blocked_untils[email] = time.time() + 300  # 5 minutes
                self.failed_login_counts[email] = 0
                QMessageBox.warning(self, "Blocked", "Too many incorrect attempts for this account. Login blocked for 5 minutes.")
                return
        except Exception:
            pass

        QMessageBox.warning(self, "Error", result.get("message", "Login failed"))

    def handle_signup(self):
        username = self.signup_username.text().strip()
        email = self.signup_email.text().strip()
        password = self.signup_password.text()

        if not username or not email or not password:
            QMessageBox.warning(self, "Error", "Please fill all fields!")
            return

        if len(password) < 6:
            QMessageBox.warning(self, "Error", "Password must be at least 6 characters!")
            return

        try:
            result = firebase.register_user(email, password, username)
            if result["success"]:
                QMessageBox.information(self, "Success", "Registration successful! Please log in.")
                self.login_email.setText(email)
                self.login_password.setText(password)
                self.signup_username.clear()
                self.signup_email.clear()
                self.signup_password.clear()
            else:
                QMessageBox.warning(self, "Error", result["message"])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Registration error: {str(e)}")


class ChatWindow(QWidget):
    """Chat window"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.current_chat_uid = None
        self.current_user_uid = None
        self.current_user_name = None
        self.current_user_tag = None
        self.current_user_token = ""
        self.message_queue = queue.Queue()
        self.socket_client = SocketChatClient(SOCKET_HOST, SOCKET_PORT, self.message_queue)
        # signals for background thread results
        self.signals = MessageSignals()
        self.signals.chat_updated.connect(self._apply_contacts)
        self.signals.chat_loaded.connect(self._apply_chat_messages)
        self.signals.profile_loaded.connect(self._apply_user_profile)
        self._refresh_thread = None
        self._load_chat_thread = None
        self._socket_connect_thread = None
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        left_panel = QVBoxLayout()
        left_panel.setContentsMargins(0, 0, 0, 0)
        left_panel.setSpacing(0)

        header = QFrame()
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(16, 16, 16, 14)
        header_layout.setSpacing(8)

        title = QLabel("💬 Chats")
        title.setFont(QFont("Arial", 17, QFont.Bold))
        header_layout.addWidget(title)

        btn_layout = QHBoxLayout()
        
        logout_btn = QPushButton("Logout")
        logout_btn.setMaximumWidth(80)
        logout_btn.setStyleSheet(
            "QPushButton { background-color: #ff4444; color: white; border: none; border-radius: 12px; padding: 6px 12px; font-size: 11px; }"
            "QPushButton:hover { background-color: #dd3333; }"
        )
        logout_btn.clicked.connect(self.handle_logout)
        btn_layout.addWidget(logout_btn)

        add_friend_btn = QPushButton("➕ Add Friend")
        add_friend_btn.setMaximumWidth(140)
        add_friend_btn.setStyleSheet(
            "QPushButton { background-color: #25D366; color: white; border: none; border-radius: 12px; padding: 6px 12px; font-size: 11px; }"
            "QPushButton:hover { background-color: #20bf5a; }"
        )
        add_friend_btn.clicked.connect(self.handle_add_friend)
        btn_layout.addWidget(add_friend_btn)

        requests_btn = QPushButton("Requests")
        requests_btn.setMaximumWidth(110)
        requests_btn.setStyleSheet(
            "QPushButton { background-color: #ffffff; color: #075E54; border: 1px solid #cfe4df; border-radius: 12px; padding: 6px 12px; font-size: 11px; }"
            "QPushButton:hover { background-color: #f3faf8; }"
            "QPushButton:pressed { background-color: #e1f1ed; }"
        )
        requests_btn.clicked.connect(self.handle_friend_requests)
        btn_layout.addWidget(requests_btn)
        
        btn_layout.addStretch()
        header_layout.addLayout(btn_layout)

        header.setLayout(header_layout)
        header.setStyleSheet("background-color: #075E54; color: white;")
        left_panel.addWidget(header)

        self.contact_list = QListWidget()
        self.contact_list.itemClicked.connect(self.on_contact_selected)
        self.contact_list.setSpacing(4)
        self.contact_list.setStyleSheet("""
            QListWidget {
                background-color: #ECE5DD;
                border: none;
                outline: none;
            }
            QListWidget::item {
                padding: 12px 14px;
                margin: 3px 6px;
                border-radius: 12px;
                background: transparent;
                border: 1px solid transparent;
            }
            QListWidget::item:selected {
                background-color: #d9e6e2;
                border: 1px solid #b9d6cf;
            }
            QListWidget::item:hover {
                background-color: #f0f0f0;
                border: 1px solid #d7e4e0;
            }
            QListWidget::item:pressed {
                background-color: #c9ddd7;
                border: 1px solid #9fc4bb;
            }
        """)
        left_panel.addWidget(self.contact_list)

        left_container = QWidget()
        left_container.setLayout(left_panel)
        left_container.setMaximumWidth(280)
        left_container.setStyleSheet("background-color: #ECE5DD;")

        main_layout.addWidget(left_container)

        # RIGHT PANEL: Chat
        right_panel = QVBoxLayout()

        self.chat_header = QFrame()
        chat_header_layout = QVBoxLayout()
        chat_header_layout.setContentsMargins(15, 15, 15, 15)
        chat_header_layout.setSpacing(6)

        self.chat_name_label = QLabel("Select a contact")
        self.chat_name_label.setFont(QFont("Arial", 14, QFont.Bold))
        chat_header_layout.addWidget(self.chat_name_label)

        self.user_tag_label = QLabel("Your tag: -")
        self.user_tag_label.setFont(QFont("Arial", 8))
        chat_header_layout.addWidget(self.user_tag_label)

        self.invite_code_label = QLabel("Invite code: -")
        self.invite_code_label.setFont(QFont("Arial", 8))
        chat_header_layout.addWidget(self.invite_code_label)

        self.chat_header.setLayout(chat_header_layout)
        self.chat_header.setStyleSheet("background-color: #075E54; color: white;")
        right_panel.addWidget(self.chat_header)

        # Alert frame (kırmızı kutu) - initially hidden
        self.alert_frame = QFrame()
        alert_layout = QVBoxLayout()
        alert_layout.setContentsMargins(12, 10, 12, 10)
        self.alert_label = QLabel("")
        self.alert_label.setFont(QFont("Arial", 10, QFont.Bold))
        self.alert_label.setStyleSheet("color: black;")
        self.alert_label.setWordWrap(True)
        alert_layout.addWidget(self.alert_label)
        self.alert_frame.setLayout(alert_layout)
        self.alert_frame.setStyleSheet("background-color: #ff4444; border-radius: 8px; padding: 10px;")
        self.alert_frame.setVisible(False)
        self.alert_frame.setMaximumHeight(80)
        right_panel.addWidget(self.alert_frame)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setStyleSheet("""
            QTextEdit {
                background-color: #f0f0f0;
                border: none;
                font-family: Arial;
                padding: 10px;
            }
            QScrollBar:vertical {
                background: transparent;
                width: 10px;
                margin: 10px 4px 10px 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: rgba(18, 140, 126, 0.45);
                min-height: 36px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(18, 140, 126, 0.7);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
                background: none;
                border: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: transparent;
            }
        """)
        right_panel.addWidget(self.chat_display)

        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(10, 10, 10, 10)
        input_layout.setSpacing(10)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setMinimumHeight(40)
        self.message_input.setStyleSheet(
            "QLineEdit { background: white; border: 1px solid #d9d9d9; border-radius: 20px; padding: 10px 15px; }"
            "QLineEdit:focus { border: 1px solid #128C7E; }"
        )
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)

        self.send_btn = QPushButton("📤 Send")
        self.send_btn.setMaximumWidth(110)
        self.send_btn.setMinimumHeight(40)
        self.send_btn.setStyleSheet(
            "QPushButton { background-color: #128C7E; color: white; border: none; border-radius: 20px; padding: 8px 14px; }"
            "QPushButton:hover { background-color: #0f7f72; }"
            "QPushButton:pressed { background-color: #0d6f64; }"
        )
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)

        input_frame = QFrame()
        input_frame.setLayout(input_layout)
        input_frame.setStyleSheet("background-color: #f0f0f0; border-top: 1px solid #e2e8ef;")
        right_panel.addWidget(input_frame)

        right_container = QWidget()
        right_container.setLayout(right_panel)

        main_layout.addWidget(right_container, 1)

        self.setLayout(main_layout)
        self.setStyleSheet("background-color: #dfe7e2;")

        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_contacts)
        self.update_timer.start(3000)

        self.socket_timer = QTimer()
        self.socket_timer.timeout.connect(self.process_socket_events)
        self.socket_timer.start(300)

        self.chat_blocked_until = 0.0
        self.chat_block_reason = ""
        self._local_spam_last_fingerprint = ""
        self._local_spam_repeat_count = 0

    def _set_message_controls_enabled(self, enabled: bool):
        self.message_input.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)

    def _sync_message_block_state(self):
        now_ts = time.time()
        if now_ts < self.chat_blocked_until:
            remain = max(1, int(self.chat_blocked_until - now_ts))
            self._set_message_controls_enabled(False)
            if self.chat_block_reason == "spam":
                self.message_input.setPlaceholderText(f"Spam nedeniyle engellendi ({remain}s)")
            else:
                self.message_input.setPlaceholderText(f"Mesaj gönderme engellendi ({remain}s)")
        else:
            self.chat_blocked_until = 0.0
            self.chat_block_reason = ""
            self._set_message_controls_enabled(True)
            self.message_input.setPlaceholderText("Type a message...")

    def _is_alert_for_current_user(self, packet: dict) -> bool:
        target_uid = str(packet.get("target_uid", "")).strip()
        target_username = str(packet.get("target_username", "")).strip()
        if target_uid and self.current_user_uid and target_uid == self.current_user_uid:
            return True
        if target_username:
            current_name = (self.current_user_name or self.current_user_tag or "").strip()
            return bool(current_name and target_username == current_name)
        return False

    def _register_local_spam_signal(self, fingerprint: str):
        if not fingerprint:
            return False

        if fingerprint == self._local_spam_last_fingerprint:
            self._local_spam_repeat_count += 1
        else:
            self._local_spam_last_fingerprint = fingerprint
            self._local_spam_repeat_count = 1

        if self._local_spam_repeat_count >= LOCAL_SPAM_THRESHOLD:
            self.chat_blocked_until = time.time() + 30
            self.chat_block_reason = "spam"
            self.show_alert("[SPAM] Çok hızlı tekrar mesaj gönderiyorsun. 30s engellendi.", duration_ms=5000)
            self._sync_message_block_state()
            return True

        return False

    def load_user_data(self, uid, email, token=""):
        """Load user data"""
        self.current_user_uid = uid
        self.current_user_token = token or ""
        fallback_name = email.split("@")[0]
        self.current_user_name = fallback_name
        self.current_user_tag = fallback_name

        def _fetch_profile(user_uid, default_name):
            try:
                profile = firebase.get_user_profile(user_uid)
                name = profile.get("username", default_name)
                tag = profile.get("tag") or name
                self.signals.profile_loaded.emit({"uid": user_uid, "name": name, "tag": tag})
            except Exception as e:
                print(f"Profile load error: {e}")

        threading.Thread(target=_fetch_profile, args=(uid, fallback_name), daemon=True).start()

        self.user_tag_label.setText(f"Your tag: {self.current_user_tag}")
        self.invite_code_label.setText(f"Invite code: {uid}")
        self.chat_display.clear()
        if not self.update_timer.isActive():
            self.update_timer.start(3000)
        if not self.socket_timer.isActive():
            self.socket_timer.start(300)
        self.connect_socket()
        self.refresh_contacts()

    def _apply_user_profile(self, data: dict):
        uid = data.get("uid")
        if uid != self.current_user_uid:
            return
        self.current_user_name = data.get("name") or self.current_user_name
        self.current_user_tag = data.get("tag") or self.current_user_tag
        self.user_tag_label.setText(f"Your tag: {self.current_user_tag}")

    def show_alert(self, message: str, duration_ms: int = 5000):
        """Show alert with red background, auto-dismiss after duration_ms."""
        self.alert_label.setText(message)
        self.alert_frame.setVisible(True)
        # Auto-hide after duration
        QTimer.singleShot(duration_ms, self.alert_frame.hide)

    def connect_socket(self):
        if not self.current_user_uid:
            return

        if self._socket_connect_thread and self._socket_connect_thread.is_alive():
            return

        uid = self.current_user_uid
        name = self.current_user_name or self.current_user_tag or self.current_user_uid
        token = self.current_user_token

        def _connect():
            connected = self.socket_client.connect(uid, name, token)
            if not connected:
                print(f"Socket connection failed: {SOCKET_HOST}:{SOCKET_PORT}")

        self._socket_connect_thread = threading.Thread(target=_connect, daemon=True)
        self._socket_connect_thread.start()

    def process_socket_events(self):
        while True:
            try:
                packet = self.message_queue.get_nowait()
            except queue.Empty:
                break

            packet_type = packet.get("type")

            if packet_type == "connection":
                if packet.get("connected"):
                    print("Socket connected")
                else:
                    error = packet.get("error")
                    if error:
                        print(f"Socket disconnected: {error}")
                continue

            # Handle alert packets
            if packet_type == "alert":
                alert_text = packet.get("text", "Alert!")
                self.show_alert(alert_text, duration_ms=5000)
                if self._is_alert_for_current_user(packet):
                    self.chat_block_reason = str(packet.get("block_reason") or "")
                    blocked_until = float(packet.get("blocked_until") or 0.0)
                    if blocked_until <= 0:
                        block_seconds = float(packet.get("block_seconds") or 0)
                        blocked_until = time.time() + max(1.0, block_seconds)
                    self.chat_blocked_until = blocked_until
                    self._sync_message_block_state()
                print(f"[ALERT] {alert_text}")
                continue

            if packet_type != "message":
                continue

            sender_uid = str(packet.get("sender_uid", "")).strip()
            receiver_uid = str(packet.get("receiver_uid", "")).strip()

            if sender_uid == self.current_user_uid:
                continue

            if not self.current_chat_uid:
                continue

            if sender_uid == self.current_chat_uid and receiver_uid == self.current_user_uid:
                self.load_chat_messages()

        self._sync_message_block_state()

    def refresh_contacts(self):
        """Refresh contact list"""
        if not self.current_user_uid:
            return
        # perform firebase operations in a background thread to avoid UI blocking
        if self._refresh_thread and getattr(self._refresh_thread, "is_alive", lambda: False)():
            return

        def _fetch():
            try:
                users = firebase.get_all_users(self.current_user_uid)
                friends = firebase.get_friends(self.current_user_uid)
                recent_chats = firebase.get_recent_chats(self.current_user_uid)
                self.signals.chat_updated.emit({
                    "users": users,
                    "friends": friends,
                    "recent_chats": recent_chats,
                })
            except Exception as e:
                print(f"Contact load error: {e}")

        self._refresh_thread = threading.Thread(target=_fetch, daemon=True)
        self._refresh_thread.start()

    def _apply_contacts(self, data: dict):
        try:
            users = data.get("users", {}) or {}
            friends = data.get("friends", {}) or {}
            recent_chats = data.get("recent_chats", {}) or {}

            self.contact_list.clear()

            # Only show friends in the left-side chats list. friends can be dict or iterable.
            friend_ids = set()
            if friends:
                try:
                    friend_ids = set(friends.keys())
                except Exception:
                    try:
                        friend_ids = set(friends)
                    except Exception:
                        friend_ids = set()

            if not friend_ids:
                # no friends yet; show a placeholder item that opens Add Friend on click
                placeholder = QListWidgetItem("Arkadaş ekle")
                placeholder.setData(Qt.UserRole, None)
                placeholder.setToolTip("Henüz arkadaşınız yok. Arkadaş eklemek için tıklayın.")
                placeholder.setForeground(QColor("#777777"))
                f = placeholder.font()
                f.setItalic(True)
                placeholder.setFont(f)
                self.contact_list.addItem(placeholder)
                return

            for uid in sorted(friend_ids):
                user_info = users.get(uid, {})
                username = user_info.get("username", "Unknown")
                tag = user_info.get("tag", "")
                status = user_info.get("status", "offline")
                unread = recent_chats.get(uid, {}).get("unread", 0)

                item_text = tag or username
                if unread > 0:
                    item_text += f" ({unread})"

                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, uid)
                item.setToolTip(tag or username)

                if status == "online":
                    item.setForeground(QColor("#25D366"))
                else:
                    item.setForeground(QColor("#999999"))

                self.contact_list.addItem(item)
        except Exception as e:
            print(f"Contact UI update error: {e}")

    def on_contact_selected(self, item):
        """When a contact is selected"""
        uid = item.data(Qt.UserRole)
        if not uid:
            # placeholder clicked -> open add friend dialog
            self.handle_add_friend()
            return

        self.current_chat_uid = uid
        username = item.text().split(" (")[0]

        self.chat_name_label.setText(f"💬 {username}")
        self.message_input.setFocus()

        self.load_chat_messages()

    def handle_add_friend(self):
        if not self.current_user_uid:
            QMessageBox.warning(self, "Error", "Please log in first")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Add Friend")
        form = QFormLayout(dialog)

        own_tag_label = QLabel(f"Your tag: {self.current_user_tag or '-'}")
        own_tag_label.setWordWrap(True)
        form.addRow(own_tag_label)

        identifier_input = QLineEdit()
        identifier_input.setPlaceholderText("Friend's email, tag or invite code")
        form.addRow("Email / tag / code:", identifier_input)

        btn_box = QHBoxLayout()
        ok_btn = QPushButton("Add")
        cancel_btn = QPushButton("Cancel")
        btn_box.addWidget(ok_btn)
        btn_box.addWidget(cancel_btn)
        form.addRow(btn_box)

        def on_ok():
            friend_identifier = identifier_input.text().strip()
            if not friend_identifier:
                QMessageBox.warning(dialog, "Error", "Please enter an email, tag or code")
                return

            res = firebase.add_friend(self.current_user_uid, friend_identifier)
            if res.get("success"):
                QMessageBox.information(dialog, "Success", res.get("message", "Friend added"))
                dialog.accept()
                QTimer.singleShot(300, self.refresh_contacts)
            else:
                QMessageBox.warning(dialog, "Error", res.get("message", "Could not add friend"))

        ok_btn.clicked.connect(on_ok)
        cancel_btn.clicked.connect(dialog.reject)

        dialog.exec()

    def handle_friend_requests(self):
        if not self.current_user_uid:
            QMessageBox.warning(self, "Error", "Please log in first")
            return

        requests = firebase.get_friend_requests(self.current_user_uid)

        dialog = QDialog(self)
        dialog.setWindowTitle("Friend Requests")
        dialog.setMinimumWidth(360)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("Incoming requests")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)

        if not requests:
            empty_label = QLabel("No pending requests.")
            empty_label.setStyleSheet("color: #666;")
            layout.addWidget(empty_label)
        else:
            list_widget = QListWidget()
            list_widget.setStyleSheet("""
                QListWidget { border: none; background: transparent; }
                QListWidget::item {
                    background: white;
                    border: 1px solid #dcebe7;
                    border-radius: 12px;
                    padding: 10px 12px;
                    margin-bottom: 6px;
                }
                QListWidget::item:selected {
                    background: #e6f3ef;
                    border: 1px solid #b9d6cf;
                }
            """)
            selected_request = {"uid": None}

            for requester_uid, request_data in requests.items():
                profile = firebase.get_user_profile(requester_uid)
                username = request_data.get("from_username") or profile.get("username", "User")
                tag = request_data.get("from_tag") or profile.get("tag", "")

                item = QListWidgetItem(f"{username} {tag}".strip())
                item.setData(Qt.UserRole, requester_uid)
                item.setToolTip(f"{username} {tag}".strip())
                list_widget.addItem(item)

            def on_request_clicked(item):
                selected_request["uid"] = item.data(Qt.UserRole)

            list_widget.itemClicked.connect(on_request_clicked)
            layout.addWidget(list_widget)

            btn_row = QHBoxLayout()
            accept_btn = QPushButton("Accept")
            accept_btn.setStyleSheet(
                "QPushButton { background-color: #25D366; color: white; border: none; border-radius: 10px; padding: 6px 12px; }"
                "QPushButton:hover { background-color: #20bf5a; }"
            )
            decline_btn = QPushButton("Decline")
            decline_btn.setStyleSheet(
                "QPushButton { background-color: #ff5a5f; color: white; border: none; border-radius: 10px; padding: 6px 12px; }"
                "QPushButton:hover { background-color: #e64b50; }"
            )
            btn_row.addWidget(accept_btn)
            btn_row.addWidget(decline_btn)
            layout.addLayout(btn_row)

            def accept_current_request():
                if not selected_request["uid"]:
                    QMessageBox.warning(dialog, "Error", "Please select a request")
                    return
                result = firebase.accept_friend_request(self.current_user_uid, selected_request["uid"])
                if result.get("success"):
                    QMessageBox.information(dialog, "Success", result.get("message", "Accepted"))
                    self.refresh_contacts()
                    dialog.accept()
                else:
                    QMessageBox.warning(dialog, "Error", result.get("message", "Could not accept"))

            def decline_current_request():
                if not selected_request["uid"]:
                    QMessageBox.warning(dialog, "Error", "Please select a request")
                    return
                result = firebase.decline_friend_request(self.current_user_uid, selected_request["uid"])
                if result.get("success"):
                    QMessageBox.information(dialog, "Success", result.get("message", "Declined"))
                    dialog.accept()
                else:
                    QMessageBox.warning(dialog, "Error", result.get("message", "Could not decline"))

            accept_btn.clicked.connect(accept_current_request)
            decline_btn.clicked.connect(decline_current_request)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.reject)
        layout.addWidget(close_btn)

        dialog.exec()

    def load_chat_messages(self):
        """Load chat messages"""
        if not self.current_chat_uid:
            return
        # load messages in background to avoid UI freeze
        if self._load_chat_thread and getattr(self._load_chat_thread, "is_alive", lambda: False)():
            return

        def _fetch_chat():
            try:
                firebase.mark_messages_as_read(self.current_chat_uid, self.current_user_uid)
                messages = firebase.get_chat_messages(self.current_user_uid, self.current_chat_uid)
                other_user = firebase.get_user_profile(self.current_chat_uid)
                other_username = other_user.get("username", "Unknown")
                self.signals.chat_loaded.emit({"messages": messages, "other_username": other_username})
            except Exception as e:
                print(f"Message load error: {e}")

        self._load_chat_thread = threading.Thread(target=_fetch_chat, daemon=True)
        self._load_chat_thread.start()

    def _apply_chat_messages(self, data: dict):
        try:
            messages = data.get("messages", []) or []
            other_username = data.get("other_username", "Unknown")
            self.chat_display.clear()

            # Remove exact duplicates (same Firebase id or identical sender+timestamp+text)
            unique_messages = []
            seen_keys = set()
            for m in messages:
                mid = m.get("id") or ""
                key = mid if mid else f"{m.get('sender','')}|{m.get('timestamp','')}|{m.get('text','') }"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                unique_messages.append(m)

            for msg in unique_messages:
                sender_uid = (msg.get("sender") or "").strip()
                text = msg.get("text", "")
                timestamp = msg.get("timestamp", "")
                current_uid = (str(self.current_user_uid) or "").strip()

                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M")
                except:
                    time_str = ""

                # Attempt to decrypt if message is encrypted
                try:
                    display_text = _maybe_decrypt_text(text)
                except Exception:
                    display_text = text
                safe_text = html.escape(display_text).replace("\n", "<br>")
                safe_other_username = html.escape(other_username)

                is_own_message = sender_uid == current_uid

                if is_own_message:
                    read_mark = "✓✓" if msg.get("read") else "✓"
                    bubble_html = (
                        f"<span style='background:#dcf8c6; color:#111; border-radius:18px 18px 6px 18px; padding:8px 10px; display:inline-block; max-width:72%;'>"
                        f"<span style='white-space:pre-wrap; line-height:1.35; font-size:14px;'>{safe_text}</span><br>"
                        f"<span style='font-size:8px; opacity:0.7;'>{time_str}&nbsp;{read_mark}</span>"
                        f"</span>"
                    )
                else:
                    bubble_html = (
                        f"<span style='background:#ffffff; color:#111; border-radius:18px 18px 18px 6px; padding:8px 10px; display:inline-block; max-width:72%; border:1px solid #ddd;'>"
                        f"<span style='font-size:8px; opacity:0.7;'>{safe_other_username}</span><br>"
                        f"<span style='white-space:pre-wrap; line-height:1.35; font-size:14px;'>{safe_text}</span><br>"
                        f"<span style='font-size:8px; opacity:0.7;'>{time_str}</span>"
                        f"</span>"
                    )

                cursor = self.chat_display.textCursor()
                cursor.movePosition(QTextCursor.End)
                block_format = QTextBlockFormat()
                block_format.setAlignment(Qt.AlignRight if is_own_message else Qt.AlignLeft)
                block_format.setTopMargin(3)
                block_format.setBottomMargin(3)
                cursor.insertBlock(block_format)
                cursor.insertHtml(bubble_html)
                self.chat_display.setTextCursor(cursor)

            self.chat_display.moveCursor(QTextCursor.End)
        except Exception as e:
            print(f"Message UI update error: {e}")

    def send_message(self):
        """Send message"""
        if not self.current_chat_uid:
            QMessageBox.warning(self, "Error", "Please select a contact!")
            return

        self._sync_message_block_state()
        now_ts = time.time()
        if now_ts < self.chat_blocked_until:
            remain = int(self.chat_blocked_until - now_ts)
            if self.chat_block_reason == "spam":
                QMessageBox.warning(self, "Blocked", f"Spam nedeniyle mesaj gönderemezsiniz. Kalan süre: {remain}s")
            else:
                QMessageBox.warning(self, "Blocked", f"Mesaj gönderemezsiniz. Kalan süre: {remain}s")
            return

        message = self.message_input.text().strip()
        if not message:
            return

        try:
            # compute fingerprint from plaintext so server can detect repeats
            fingerprint = hashlib.sha256(message.encode("utf-8")).hexdigest()
            to_send = _encrypt_text_if_needed(message)
            success = firebase.send_message(self.current_user_uid, self.current_chat_uid, to_send)

            if success:
                # include fingerprint in real-time socket packet for spam detection
                self.socket_client.send_message(
                    self.current_user_uid,
                    self.current_user_name or self.current_user_tag or self.current_user_uid,
                    self.current_chat_uid,
                    to_send,
                    fingerprint=fingerprint,
                )
                self._register_local_spam_signal(fingerprint)
                self.message_input.clear()
                self.load_chat_messages()
            else:
                QMessageBox.warning(self, "Error", "Message could not be sent!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Send error: {str(e)}")

    def handle_logout(self):
        """Logout"""
        uid = self.current_user_uid

        self.update_timer.stop()
        self.socket_timer.stop()

        # Switch UI immediately; run network cleanup in background
        self.parent_window.logout()

        def _background_cleanup(user_uid):
            try:
                self.socket_client.disconnect()
            except Exception as e:
                print(f"Logout socket cleanup error: {e}")

            try:
                if user_uid:
                    firebase.update_user_status(user_uid, "offline")
            except Exception as e:
                print(f"Logout status update error: {e}")

        try:
            threading.Thread(target=_background_cleanup, args=(uid,), daemon=True).start()
        except Exception as e:
            print(f"Logout cleanup thread error: {e}")


class ChatApp(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat")
        self.setGeometry(100, 100, 380, 760)

        self.stacked_widget = QStackedWidget()

        self.login_window = LoginWindow(self)
        self.chat_window = ChatWindow(self)

        self.stacked_widget.addWidget(self.login_window)
        self.stacked_widget.addWidget(self.chat_window)

        self.setCentralWidget(self.stacked_widget)
        self.show_login()

    def show_login(self):
        """Show login screen"""
        self.stacked_widget.setCurrentWidget(self.login_window)

    def show_chat(self):
        """Show chat screen"""
        self.stacked_widget.setCurrentWidget(self.chat_window)

    def login(self, uid, email, token=""):
        """Log in"""
        self.chat_window.load_user_data(uid, email, token)
        self.show_chat()

        def _set_online(user_uid):
            try:
                if user_uid:
                    firebase.update_user_status(user_uid, "online")
            except Exception as e:
                print(f"Login status update error: {e}")

        threading.Thread(target=_set_online, args=(uid,), daemon=True).start()

    def logout(self):
        """Log out"""
        self.show_login()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec())
