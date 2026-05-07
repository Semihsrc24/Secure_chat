import os
import socket
import threading
import time
import logging
import json
from datetime import datetime
from collections import deque

HOST = "0.0.0.0"
PORT = 5555
BUFFER_SIZE = 2048

RATE_LIMIT_MESSAGES = 10
RATE_LIMIT_WINDOW_SEC = 5
REPEAT_THRESHOLD = 10
EMPTY_THRESHOLD = 8
BLOCK_SECONDS = 30
MONITOR_INTERVAL_SEC = 10

clients = {}
clients_lock = threading.Lock()
server_stats = {
    "total_connections": 0,
    "total_messages": 0,
    "total_alerts": 0,
}
running = True


def send_packet(sock, payload):
    try:
        data = json.dumps(payload, ensure_ascii=False) + "\n"
        sock.sendall(data.encode("utf-8"))
    except Exception:
        remove_client(sock)


def broadcast(payload, exclude_sock=None):
    with clients_lock:
        sockets = list(clients.keys())

    for sock in sockets:
        if exclude_sock is not None and sock is exclude_sock:
            continue
        send_packet(sock, payload)


def online_users_text():
    with clients_lock:
        names = [info["name"] for info in clients.values()]
    if not names:
        return "(kimse yok)"
    return ", ".join(sorted(names))


def remove_client(sock):
    with clients_lock:
        info = clients.pop(sock, None)

    username = info["name"] if info else None

    try:
        sock.close()
    except Exception:
        pass

    if username:
        msg = {"type": "system", "text": f"{username} ayrildi."}
        print(f"[SERVER] {username} ayrildi.")
        logging.info("DISCONNECT user=%s", username)
        broadcast(msg)


def unique_name(requested_name):
    name = requested_name.strip() if requested_name.strip() else "Misafir"
    with clients_lock:
        used = {info["name"] for info in clients.values()}

    if name not in used:
        return name

    idx = 2
    while f"{name}{idx}" in used:
        idx += 1
    return f"{name}{idx}"


def trim_window(ts_deque, now_ts, window_sec):
    while ts_deque and (now_ts - ts_deque[0]) > window_sec:
        ts_deque.popleft()


def detect_intrusion(client_info, text, now_ts):
    msg_times = client_info["msg_times"]
    msg_times.append(now_ts)
    trim_window(msg_times, now_ts, RATE_LIMIT_WINDOW_SEC)

    if len(msg_times) > RATE_LIMIT_MESSAGES:
        return "Spam/Flood detected: message rate too high"

    if text == client_info["last_message"] and text:
        client_info["repeat_count"] += 1
    else:
        client_info["last_message"] = text
        client_info["repeat_count"] = 1

    if client_info["repeat_count"] >= REPEAT_THRESHOLD:
        return "Repeated-message flooding detected"

    if not text.strip():
        empty_times = client_info["empty_times"]
        empty_times.append(now_ts)
        trim_window(empty_times, now_ts, RATE_LIMIT_WINDOW_SEC)
        if len(empty_times) >= EMPTY_THRESHOLD:
            return "Empty/malformed packet flooding detected"

    return None


def user_stats_text(client_info):
    now_ts = time.time()
    blocked = int(client_info["blocked_until"] - now_ts)
    blocked = blocked if blocked > 0 else 0
    return (
        f"name={client_info['name']} "
        f"messages={client_info['total_messages']} "
        f"alerts={client_info['alerts']} "
        f"blocks={client_info['blocked_count']} "
        f"blocked_for={blocked}s"
    )


def monitor_loop():
    while running:
        time.sleep(MONITOR_INTERVAL_SEC)
        with clients_lock:
            connected = len(clients)
            total_msgs = server_stats["total_messages"]
            total_alerts = server_stats["total_alerts"]

            top_user = None
            top_count = -1
            for info in clients.values():
                if info["total_messages"] > top_count:
                    top_count = info["total_messages"]
                    top_user = info["name"]

        summary = (
            f"MONITOR connected={connected} total_messages={total_msgs} "
            f"total_alerts={total_alerts} top_user={top_user or '-'}"
        )
        print(f"[MONITOR] {summary}")
        logging.info(summary)


def handle_client(client_sock, addr):
    # Bu istemci protokolunde ilk paket nickname olarak bekleniyor.
    reader = client_sock.makefile("r", encoding="utf-8", newline="\n")
    try:
        raw_name = reader.readline()
        if not raw_name:
            client_sock.close()
            return

        requested_name = raw_name.strip()
        try:
            first_packet = json.loads(requested_name)
        except Exception:
            first_packet = {"type": "nickname", "name": requested_name}

        requested_name = str(first_packet.get("name") or first_packet.get("uid") or "Misafir").strip()
        username = unique_name(requested_name)
        uid = str(first_packet.get("uid") or username).strip()

        client_info = {
            "uid": uid,
            "name": username,
            "joined_at": time.time(),
            "msg_times": deque(),
            "empty_times": deque(),
            "last_message": "",
            "repeat_count": 0,
            "blocked_until": 0.0,
            "alerts": 0,
            "blocked_count": 0,
            "total_messages": 0,
        }

        with clients_lock:
            clients[client_sock] = client_info
            server_stats["total_connections"] += 1

        welcome = (
            f"Hos geldin {username}!"
        )
        send_packet(client_sock, {"type": "system", "text": welcome, "uid": uid, "name": username})

        join_msg = {"type": "system", "text": f"{username} sohbete katildi.", "uid": uid, "name": username}
        print(f"{addr[0]}:{addr[1]} -> {username} baglandi")
        logging.info("CONNECT user=%s ip=%s port=%s", username, addr[0], addr[1])
        broadcast(join_msg, exclude_sock=client_sock)

        while True:
            raw_line = reader.readline()
            if not raw_line:
                break

            text = raw_line.strip()
            if not text:
                continue

            try:
                packet = json.loads(text)
            except Exception:
                packet = {"type": "text", "text": text}

            packet_type = packet.get("type")
            is_command_packet = packet_type in {"command", "text", "nickname"}

            if packet_type in {"message", "command", "text"}:
                text = str(packet.get("text", text)).strip()

            now_ts = time.time()

            if is_command_packet:
                if text.lower() == "/quit":
                    send_packet(client_sock, {"type": "system", "text": "Baglanti kapatiliyor..."})
                    break

                if text.lower() == "/list":
                    send_packet(client_sock, {"type": "system", "text": f"Cevrimici: {online_users_text()}"})
                    continue

                if text.lower() == "/stats":
                    with clients_lock:
                        total_msgs = server_stats["total_messages"]
                        total_alerts = server_stats["total_alerts"]
                        current_info = clients.get(client_sock, client_info)
                    send_packet(
                        client_sock,
                        {
                            "type": "system",
                            "text": (
                                f"User stats: {user_stats_text(current_info)} | "
                                f"Server stats: total_messages={total_msgs} total_alerts={total_alerts}"
                            ),
                        },
                    )
                    continue

                if text.lower().startswith("/nick"):
                    parts = text.split(maxsplit=1)
                    if len(parts) < 2 or not parts[1].strip():
                        send_packet(client_sock, {"type": "system", "text": "Kullanim: /nick <yeniad>"})
                        continue

                    new_name = unique_name(parts[1])
                    with clients_lock:
                        old_name = clients.get(client_sock, client_info)["name"]
                        clients[client_sock]["name"] = new_name
                    username = new_name
                    client_info["name"] = new_name

                    broadcast({"type": "system", "text": f"{old_name} artik {new_name} olarak biliniyor."})
                    logging.info("NICK old=%s new=%s", old_name, new_name)
                    continue

            if now_ts < client_info["blocked_until"]:
                remain = int(client_info["blocked_until"] - now_ts)
                send_packet(client_sock, {"type": "system", "text": f"Gecici engellendiniz. Kalan sure: {remain}s"})
                continue

            reason = detect_intrusion(client_info, text, now_ts)
            if reason:
                client_info["alerts"] += 1
                client_info["blocked_count"] += 1
                client_info["blocked_until"] = now_ts + BLOCK_SECONDS
                with clients_lock:
                    server_stats["total_alerts"] += 1

                alert_text = {
                    "type": "alert",
                    "text": (
                        f"Supheli aktivite: user={client_info['name']} "
                        f"reason={reason} block={BLOCK_SECONDS}s"
                    ),
                }
                broadcast(alert_text)
                logging.warning(
                    "ALERT user=%s ip=%s port=%s reason=%s",
                    client_info["name"],
                    addr[0],
                    addr[1],
                    reason,
                )
                continue

            client_info["total_messages"] += 1
            with clients_lock:
                server_stats["total_messages"] += 1

            # Debug: print received packet and current counters
            try:
                print(f"[RECV] user={client_info['name']} uid={client_info.get('uid')} type={packet.get('type')} text={text}")
            except Exception:
                print(f"[RECV] user={client_info.get('name')} packet={packet}")
            print(f"[STATS] total_messages={server_stats['total_messages']} total_alerts={server_stats['total_alerts']}")

            broadcast(
                {
                    "type": "message",
                    "sender_uid": client_info.get("uid", client_info["name"]),
                    "sender_name": client_info["name"],
                    "receiver_uid": str(packet.get("receiver_uid", "")).strip(),
                    "text": text,
                    "timestamp": packet.get("timestamp") or datetime.now().isoformat(),
                }
            )
            logging.info("MSG user=%s text=%s", client_info["name"], text)

    except Exception as exc:
        print(f"Hata ({addr[0]}:{addr[1]}): {exc}")
        logging.exception("CLIENT_ERROR ip=%s port=%s err=%s", addr[0], addr[1], exc)
    finally:
        remove_client(client_sock)
        try:
            reader.close()
        except Exception:
            pass


def maybe_start_ngrok(local_port):
    use_ngrok = os.getenv("USE_PYNGROK", "0").strip() == "1"
    if not use_ngrok:
        print("[NGROK] Pyngrok otomatik acilis kapali (USE_PYNGROK=1 yaparsan acilir).")
        return

    try:
        from pyngrok import ngrok
    except ImportError:
        print("[NGROK] pyngrok kurulu degil. Kurulum: pip install pyngrok")
        return

    token = os.getenv("NGROK_AUTHTOKEN", "").strip()
    if token:
        ngrok.set_auth_token(token)

    try:
        tunnel = ngrok.connect(addr=local_port, proto="tcp")
        print(f"[NGROK] Public TCP URL: {tunnel.public_url}")
    except Exception as exc:
        print(f"[NGROK] Tunnel acilamadi: {exc}")


def main():
    global running

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler("server.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    print("=" * 45)
    print("  PYTHON CHAT SERVER")
    print(f"  Dinleniyor: {HOST}:{PORT}")
    print("  Komutlar client tarafindan gonderilir: /quit /list /nick")
    print("=" * 45)

    maybe_start_ngrok(PORT)
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()

    try:
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Kapatiliyor...")
    finally:
        running = False
        with clients_lock:
            socks = list(clients.keys())
        for s in socks:
            try:
                s.close()
            except Exception:
                pass
        server.close()


if __name__ == "__main__":
    main()
