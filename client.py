import socket
import threading
import sys
import argparse
import json
from datetime import datetime

HOST = '127.0.0.1'
PORT = 5555
BUFFER_SIZE = 2048

running = True

def receive_messages(sock):
    global running
    reader = sock.makefile('r', encoding='utf-8', newline='\n')
    while running:
        try:
            line = reader.readline()
            if not line:
                print("\n⚠️  Server bağlantısı kesildi.")
                running = False
                break
            text = line.strip()
            if not text:
                continue

            try:
                packet = json.loads(text)
            except Exception:
                print(text)
                continue

            packet_type = packet.get('type')
            message_text = packet.get('text', '')

            if packet_type == 'message':
                sender_name = packet.get('sender_name', 'User')
                print(f"[{sender_name}] {message_text}")
            elif packet_type in {'system', 'alert'}:
                print(message_text)
            else:
                print(message_text or text)
        except:
            if running:
                print("\n⚠️  Bağlantı hatası.")
            running = False
            break

def parse_args():
    parser = argparse.ArgumentParser(description="Python chat client")
    parser.add_argument("--host", default=HOST, help="Server host (local or ngrok host)")
    parser.add_argument("--port", type=int, default=PORT, help="Server port (local or ngrok port)")
    parser.add_argument("--peer", default="", help="Optional receiver uid/name for direct messages")
    return parser.parse_args()


def main():
    global running
    args = parse_args()

    print("=" * 45)
    print("  💻 PYTHON CHAT CLIENT")
    print(f"  📡 Bağlanılıyor: {args.host}:{args.port}")
    print("  📋 Komutlar: /quit  /list  /nick <yeniad>")
    print("=" * 45)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except Exception as exc:
        print(f"❌ Server'a bağlanılamadı! ({exc})")
        sys.exit(1)

    print("✅ Bağlantı kuruldu!")

    # Önce nickname gönder
    try:
        nickname = input("🔑 Takma adınızı girin: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n👋 Giriş iptal edildi.")
        sock.close()
        return

    if not nickname:
        nickname = "Misafir"
    sock.sendall((json.dumps({
        'type': 'auth',
        'uid': nickname,
        'name': nickname,
        'token': '',
    }, ensure_ascii=False) + '\n').encode('utf-8'))
    # Alıcı thread başlat
    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()

    # Mesaj gönderme döngüsü
    try:
        while running:
            try:
                msg = input()
            except EOFError:
                break
            if not msg.strip():
                continue
            try:
                payload = {
                    'type': 'command',
                    'text': msg,
                } if msg.strip().startswith('/') else {
                    'type': 'message',
                    'sender_uid': nickname,
                    'sender_name': nickname,
                    'receiver_uid': args.peer,
                    'text': msg,
                    'timestamp': datetime.now().isoformat(),
                }
                sock.sendall((json.dumps(payload, ensure_ascii=False) + '\n').encode('utf-8'))
            except:
                print("❌ Mesaj gönderilemedi.")
                break
            if msg.strip().lower() == '/quit':
                print("👋 Çıkılıyor...")
                running = False
                break
    except KeyboardInterrupt:
        print("\n👋 Çıkılıyor...")
    finally:
        running = False
        sock.close()
        print("Bağlantı kapatıldı.")

if __name__ == '__main__':
    main()