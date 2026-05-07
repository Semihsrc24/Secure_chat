import queue
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk


class ChatGuiClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat GUI Client")
        self.root.geometry("900x560")

        self.sock = None
        self.running = False
        self.recv_thread = None
        self.ui_queue = queue.Queue()

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self.process_ui_queue)

    def _build_ui(self):
        top = ttk.LabelFrame(self.root, text=" Baglanti Ayarlari ")
        top.pack(fill="x", padx=8, pady=(8, 4))

        row = ttk.Frame(top)
        row.pack(fill="x", padx=8, pady=8)

        ttk.Label(row, text="Host").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.host_entry = ttk.Entry(row, textvariable=self.host_var, width=18)
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=(0, 12))

        ttk.Label(row, text="Port").grid(row=0, column=2, sticky="w", padx=(0, 6))
        self.port_var = tk.StringVar(value="5555")
        self.port_entry = ttk.Entry(row, textvariable=self.port_var, width=8)
        self.port_entry.grid(row=0, column=3, sticky="ew", padx=(0, 12))

        ttk.Label(row, text="Nickname").grid(row=0, column=4, sticky="w", padx=(0, 6))
        self.nick_var = tk.StringVar(value="Misafir")
        self.nick_entry = ttk.Entry(row, textvariable=self.nick_var, width=16)
        self.nick_entry.grid(row=0, column=5, sticky="ew", padx=(0, 12))

        self.connect_btn = ttk.Button(row, text="Baglan", width=10, command=self.connect)
        self.connect_btn.grid(row=0, column=6, padx=(0, 6))

        self.disconnect_btn = ttk.Button(row, text="Ayril", width=10, command=self.disconnect, state="disabled")
        self.disconnect_btn.grid(row=0, column=7)

        row.columnconfigure(1, weight=1)
        row.columnconfigure(5, weight=1)

        center = tk.Frame(self.root, padx=8, pady=4)
        center.pack(fill="both", expand=True)

        left = tk.Frame(center)
        left.pack(side="left", fill="both", expand=True)

        right = tk.Frame(center, width=220)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self.chat_text = tk.Text(
            left,
            wrap="word",
            state="disabled",
            height=24,
            bg="#ffffff",
            fg="#111111",
        )
        self.chat_text.pack(side="left", fill="both", expand=True)

        chat_scroll = tk.Scrollbar(left, command=self.chat_text.yview)
        chat_scroll.pack(side="right", fill="y")
        self.chat_text.config(yscrollcommand=chat_scroll.set)

        self.chat_text.tag_configure("alert", foreground="#b30000")
        self.chat_text.tag_configure("server", foreground="#003d99")

        tk.Label(right, text="Kullanicilar", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(0, 6))
        self.user_list = tk.Listbox(right, height=20, bg="#ffffff", fg="#111111")
        self.user_list.pack(fill="both", expand=True)

        self.refresh_btn = tk.Button(right, text="Listeyi Yenile (/list)", command=self.request_user_list, state="disabled")
        self.refresh_btn.pack(fill="x", pady=(6, 0))

        bottom = tk.Frame(self.root, padx=8, pady=8)
        bottom.pack(fill="x")

        self.msg_entry = tk.Entry(bottom, bg="#ffffff", fg="#111111")
        self.msg_entry.pack(side="left", fill="x", expand=True)
        self.msg_entry.bind("<Return>", self.on_send)

        self.send_btn = tk.Button(bottom, text="Gonder", width=10, command=self.send_message, state="disabled")
        self.send_btn.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="Hazir")
        status = tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken")
        status.pack(fill="x", side="bottom")

    def append_chat(self, text, tag=None):
        self.chat_text.config(state="normal")
        if tag:
            self.chat_text.insert("end", text + "\n", tag)
        else:
            self.chat_text.insert("end", text + "\n")
        self.chat_text.see("end")
        self.chat_text.config(state="disabled")

    def set_connected_ui(self, connected):
        if connected:
            self.connect_btn.config(state="disabled")
            self.disconnect_btn.config(state="normal")
            self.send_btn.config(state="normal")
            self.refresh_btn.config(state="normal")
        else:
            self.connect_btn.config(state="normal")
            self.disconnect_btn.config(state="disabled")
            self.send_btn.config(state="disabled")
            self.refresh_btn.config(state="disabled")

    def connect(self):
        if self.running:
            return

        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        nick = self.nick_var.get().strip() or "Misafir"

        if not host:
            messagebox.showerror("Hata", "Host bos olamaz")
            return

        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Hata", "Port sayi olmali")
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.sock.send(nick.encode("utf-8"))
        except Exception as exc:
            self.sock = None
            messagebox.showerror("Baglanti Hatasi", f"Server baglantisi kurulamadi: {exc}")
            return

        self.running = True
        self.set_connected_ui(True)
        self.status_var.set(f"Bagli: {host}:{port} ({nick})")
        self.append_chat(f"[CLIENT] Baglandi -> {host}:{port}")

        self.recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        self.recv_thread.start()

    def disconnect(self):
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
        self.status_var.set("Bagli degil")
        self.append_chat("[CLIENT] Baglanti kapatildi")

    def send_raw(self, text):
        if self.sock:
            self.sock.send(text.encode("utf-8"))

    def send_message(self):
        if not self.running:
            return

        msg = self.msg_entry.get().strip()
        if not msg:
            return

        try:
            self.send_raw(msg)
        except Exception as exc:
            self.ui_queue.put(("system", f"[CLIENT] Mesaj gonderilemedi: {exc}"))
            self.disconnect()
            return

        self.msg_entry.delete(0, "end")

    def on_send(self, _event):
        self.send_message()

    def request_user_list(self):
        if not self.running:
            return
        try:
            self.send_raw("/list")
        except Exception as exc:
            self.ui_queue.put(("system", f"[CLIENT] /list gonderilemedi: {exc}"))

    def receive_loop(self):
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    self.ui_queue.put(("disconnect", "[CLIENT] Server baglantisi kapandi"))
                    break

                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    clean = line.strip()
                    if clean:
                        self.ui_queue.put(("message", clean))
            except Exception:
                if self.running:
                    self.ui_queue.put(("disconnect", "[CLIENT] Baglanti hatasi"))
                break

    def process_ui_queue(self):
        while True:
            try:
                event_type, payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            if event_type == "message":
                self.handle_incoming_line(payload)
            elif event_type == "disconnect":
                self.append_chat(payload, tag="server")
                self.disconnect()
            elif event_type == "system":
                self.append_chat(payload, tag="server")

        self.root.after(100, self.process_ui_queue)

    def handle_incoming_line(self, line):
        if "[ALERT]" in line:
            self.append_chat(line, tag="alert")
            messagebox.showwarning("Guvenlik Uyarisi", line)
            return

        if line.startswith("[SERVER]"):
            self.append_chat(line, tag="server")
        else:
            self.append_chat(line)

        marker = "[SERVER] Cevrimici:"
        if line.startswith(marker):
            names_raw = line[len(marker):].strip()
            names = [n.strip() for n in names_raw.split(",") if n.strip()]
            self.user_list.delete(0, "end")
            for name in names:
                self.user_list.insert("end", name)

    def on_close(self):
        self.disconnect()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ChatGuiClient(root)
    app.append_chat("[CLIENT] Komutlar: /list, /nick <yeniad>, /stats, /quit", tag="server")
    root.mainloop()


if __name__ == "__main__":
    main()
