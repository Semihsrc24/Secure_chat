"""
Secure Chat - PySide6 GUI
Mobile-style login, signup, contacts list and chat screens.
All visible text is in English and UI is restyled for a mobile look.
"""

import sys
import os
import json
import socket
import queue
import threading
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

# Direct ngrok defaults (hardcoded to avoid env pollution)
SOCKET_HOST = os.getenv("CHAT_SOCKET_HOST", "8.tcp.ngrok.io")
SOCKET_PORT = int(os.getenv("CHAT_SOCKET_PORT", "11188"))

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

    def connect(self, uid: str, username: str, token: str = "") -> bool:
        self.disconnect(close_only=True)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
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
        if not self.sock:
            return
        message = json.dumps(payload, ensure_ascii=False) + "\n"
        self.sock.sendall(message.encode("utf-8"))

    def send_message(self, sender_uid: str, sender_name: str, receiver_uid: str, text: str) -> None:
        self._send_packet({
            "type": "message",
            "sender_uid": sender_uid,
            "sender_name": sender_name,
            "receiver_uid": receiver_uid,
            "text": text,
            "timestamp": datetime.now().isoformat(),
        })

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
            if self.running:
                self.event_queue.put({"type": "connection", "connected": False, "error": str(exc)})
        finally:
            self.running = False
            self.event_queue.put({"type": "connection", "connected": False})
            self.disconnect(close_only=True)

    def disconnect(self, close_only: bool = False) -> None:
        self.running = False

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
    chat_updated = Signal()
    connection_changed = Signal(bool)


class LoginWindow(QWidget):
    """Login / Signup screen (mobile style)"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
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
        email = self.login_email.text().strip()
        password = self.login_password.text()

        if not email or not password:
            QMessageBox.warning(self, "Error", "Email and password required!")
            return

        try:
            result = firebase.login_user(email, password)
            if result["success"]:
                QMessageBox.information(self, "Success", "Login successful!")
                self.parent_window.login(result["uid"], email, result.get("token", ""))
            else:
                QMessageBox.warning(self, "Error", result["message"])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Login error: {str(e)}")

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
        self.socket_timer.start(150)

    def load_user_data(self, uid, email, token=""):
        """Load user data"""
        self.current_user_uid = uid
        self.current_user_token = token or ""
        try:
            profile = firebase.get_user_profile(uid)
            self.current_user_name = profile.get("username", email.split("@")[0])
            self.current_user_tag = profile.get("tag") or profile.get("username", email.split("@")[0])
        except:
            self.current_user_name = email.split("@")[0]
            self.current_user_tag = self.current_user_name

        self.user_tag_label.setText(f"Your tag: {self.current_user_tag}")
        self.invite_code_label.setText(f"Invite code: {uid}")
        self.chat_display.clear()
        if not self.update_timer.isActive():
            self.update_timer.start(3000)
        if not self.socket_timer.isActive():
            self.socket_timer.start(150)
        self.connect_socket()
        self.refresh_contacts()

    def connect_socket(self):
        if not self.current_user_uid:
            return

        connected = self.socket_client.connect(
            self.current_user_uid,
            self.current_user_name or self.current_user_tag or self.current_user_uid,
            self.current_user_token,
        )
        if not connected:
            print(f"Socket connection failed: {SOCKET_HOST}:{SOCKET_PORT}")

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

    def refresh_contacts(self):
        """Refresh contact list"""
        if not self.current_user_uid:
            return

        try:
            users = firebase.get_all_users(self.current_user_uid)
            friends = firebase.get_friends(self.current_user_uid)
            recent_chats = firebase.get_recent_chats(self.current_user_uid)

            self.contact_list.clear()

            for uid, user_info in users.items():
                username = user_info.get("username", "Unknown")
                tag = user_info.get("tag", "")
                status = user_info.get("status", "offline")
                unread = recent_chats.get(uid, {}).get("unread", 0)

                item_text = tag or username
                if friends and uid in friends:
                    item_text = f"★ {item_text}"
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
            print(f"Contact load error: {e}")

    def on_contact_selected(self, item):
        """When a contact is selected"""
        self.current_chat_uid = item.data(Qt.UserRole)
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

        try:
            firebase.mark_messages_as_read(self.current_chat_uid, self.current_user_uid)
            messages = firebase.get_chat_messages(self.current_user_uid, self.current_chat_uid)
            self.chat_display.clear()

            other_user = firebase.get_user_profile(self.current_chat_uid)
            other_username = other_user.get("username", "Unknown")

            for msg in messages:
                sender_uid = (msg.get("sender") or "").strip()
                text = msg.get("text", "")
                timestamp = msg.get("timestamp", "")
                current_uid = (str(self.current_user_uid) or "").strip()

                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M")
                except:
                    time_str = ""

                safe_text = html.escape(text).replace("\n", "<br>")
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
            print(f"Message load error: {e}")

    def send_message(self):
        """Send message"""
        if not self.current_chat_uid:
            QMessageBox.warning(self, "Error", "Please select a contact!")
            return

        message = self.message_input.text().strip()
        if not message:
            return

        try:
            success = firebase.send_message(self.current_user_uid, self.current_chat_uid, message)

            if success:
                self.socket_client.send_message(
                    self.current_user_uid,
                    self.current_user_name or self.current_user_tag or self.current_user_uid,
                    self.current_chat_uid,
                    message,
                )
                self.message_input.clear()
                self.load_chat_messages()
            else:
                QMessageBox.warning(self, "Error", "Message could not be sent!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Send error: {str(e)}")

    def handle_logout(self):
        """Logout"""
        self.update_timer.stop()
        self.socket_timer.stop()
        self.socket_client.disconnect()
        firebase.update_user_status(self.current_user_uid, "offline")
        self.parent_window.logout()


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
        firebase.update_user_status(uid, "online")
        self.chat_window.load_user_data(uid, email, token)
        self.show_chat()

    def logout(self):
        """Log out"""
        self.show_login()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec())
