import queue
import socket
import sys
import threading

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class ChatGuiQt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat GUI Client (PySide6)")
        self.resize(980, 620)

        self.sock = None
        self.running = False
        self.inbox = queue.Queue()
        self.recv_thread = None

        self._build_ui()

        self.timer = QTimer(self)
        self.timer.setInterval(80)
        self.timer.timeout.connect(self.process_inbox)
        self.timer.start()

    def _build_ui(self):
        root = QWidget(self)
        self.setCentralWidget(root)

        main_layout = QVBoxLayout(root)

        conn_panel = QWidget()
        conn_layout = QGridLayout(conn_panel)

        conn_layout.addWidget(QLabel("Host"), 0, 0)
        self.host_edit = QLineEdit("127.0.0.1")
        conn_layout.addWidget(self.host_edit, 0, 1)

        conn_layout.addWidget(QLabel("Port"), 0, 2)
        self.port_edit = QLineEdit("5555")
        self.port_edit.setMaximumWidth(100)
        conn_layout.addWidget(self.port_edit, 0, 3)

        conn_layout.addWidget(QLabel("Nickname"), 0, 4)
        self.nick_edit = QLineEdit("Misafir")
        conn_layout.addWidget(self.nick_edit, 0, 5)

        self.connect_btn = QPushButton("Baglan")
        self.connect_btn.clicked.connect(self.connect_to_server)
        conn_layout.addWidget(self.connect_btn, 0, 6)

        self.disconnect_btn = QPushButton("Ayril")
        self.disconnect_btn.setEnabled(False)
        self.disconnect_btn.clicked.connect(self.disconnect_from_server)
        conn_layout.addWidget(self.disconnect_btn, 0, 7)

        conn_layout.setColumnStretch(1, 2)
        conn_layout.setColumnStretch(5, 2)

        main_layout.addWidget(conn_panel)

        center = QHBoxLayout()

        self.chat_box = QTextEdit()
        self.chat_box.setReadOnly(True)
        center.addWidget(self.chat_box, 5)

        side = QVBoxLayout()
        side.addWidget(QLabel("Kullanicilar"))
        self.user_list = QListWidget()
        side.addWidget(self.user_list, 1)

        self.refresh_btn = QPushButton("Listeyi Yenile (/list)")
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.clicked.connect(self.request_user_list)
        side.addWidget(self.refresh_btn)

        center.addLayout(side, 2)
        main_layout.addLayout(center, 1)

        bottom = QHBoxLayout()
        self.msg_edit = QLineEdit()
        self.msg_edit.setPlaceholderText("Mesaj veya komut yaz... (/list, /nick yeniad, /stats, /quit)")
        self.msg_edit.returnPressed.connect(self.send_message)
        bottom.addWidget(self.msg_edit, 1)

        self.send_btn = QPushButton("Gonder")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.send_message)
        bottom.addWidget(self.send_btn)

        main_layout.addLayout(bottom)

        self.status_label = QLabel("Hazir")
        self.status_label.setAlignment(Qt.AlignLeft)
        main_layout.addWidget(self.status_label)

    def append_text(self, text, color=None):
        if color:
            self.chat_box.setTextColor(QColor(color))
        else:
            self.chat_box.setTextColor(QColor("#111111"))
        self.chat_box.append(text)
        self.chat_box.moveCursor(QTextCursor.End)

    def set_connected_ui(self, connected):
        self.connect_btn.setEnabled(not connected)
        self.disconnect_btn.setEnabled(connected)
        self.send_btn.setEnabled(connected)
        self.refresh_btn.setEnabled(connected)

    def send_raw(self, text):
        if self.sock:
            self.sock.send(text.encode("utf-8"))

    def connect_to_server(self):
        if self.running:
            return

        host = self.host_edit.text().strip()
        port_text = self.port_edit.text().strip()
        nick = self.nick_edit.text().strip() or "Misafir"

        if not host:
            QMessageBox.critical(self, "Hata", "Host bos olamaz")
            return

        try:
            port = int(port_text)
        except ValueError:
            QMessageBox.critical(self, "Hata", "Port sayi olmali")
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.sock.send(nick.encode("utf-8"))
        except Exception as exc:
            self.sock = None
            QMessageBox.critical(self, "Baglanti Hatasi", f"Server baglantisi kurulamadi: {exc}")
            return

        self.running = True
        self.set_connected_ui(True)
        self.status_label.setText(f"Bagli: {host}:{port} ({nick})")
        self.append_text(f"[CLIENT] Baglandi -> {host}:{port}", "#0b5ed7")

        self.recv_thread = threading.Thread(target=self.recv_loop, daemon=True)
        self.recv_thread.start()

    def disconnect_from_server(self):
        if not self.running:
            return

        try:
            self.send_raw("/quit")
        except Exception:
            pass

        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None

        self.set_connected_ui(False)
        self.status_label.setText("Bagli degil")
        self.append_text("[CLIENT] Baglanti kapatildi", "#0b5ed7")

    def send_message(self):
        if not self.running:
            return

        text = self.msg_edit.text().strip()
        if not text:
            return

        try:
            self.send_raw(text)
        except Exception as exc:
            self.append_text(f"[CLIENT] Mesaj gonderilemedi: {exc}", "#b30000")
            self.disconnect_from_server()
            return

        self.msg_edit.clear()

    def request_user_list(self):
        if not self.running:
            return
        try:
            self.send_raw("/list")
        except Exception as exc:
            self.append_text(f"[CLIENT] /list gonderilemedi: {exc}", "#b30000")

    def recv_loop(self):
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    self.inbox.put(("disconnect", "[CLIENT] Server baglantisi kapandi"))
                    break

                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        self.inbox.put(("message", line))
            except Exception:
                if self.running:
                    self.inbox.put(("disconnect", "[CLIENT] Baglanti hatasi"))
                break

    def process_inbox(self):
        while True:
            try:
                event_type, payload = self.inbox.get_nowait()
            except queue.Empty:
                break

            if event_type == "message":
                self.handle_message(payload)
            elif event_type == "disconnect":
                self.append_text(payload, "#0b5ed7")
                self.disconnect_from_server()

    def handle_message(self, line):
        if "[ALERT]" in line:
            self.append_text(line, "#b30000")
            QMessageBox.warning(self, "Guvenlik Uyarisi", line)
            return

        if line.startswith("[SERVER]"):
            self.append_text(line, "#0b5ed7")
        else:
            self.append_text(line)

        marker = "[SERVER] Cevrimici:"
        if line.startswith(marker):
            names_raw = line[len(marker):].strip()
            names = [n.strip() for n in names_raw.split(",") if n.strip()]
            self.user_list.clear()
            for name in names:
                self.user_list.addItem(name)

    def closeEvent(self, event):
        self.disconnect_from_server()
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = ChatGuiQt()
    window.append_text("[CLIENT] Komutlar: /list, /nick <yeniad>, /stats, /quit", "#0b5ed7")
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
