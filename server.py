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
ENDPOINT_FILE = "socket_endpoint.json"

# Security: Brute-force and spam detection
failed_logins = {}  # {username: count}
failed_logins_lock = threading.Lock()
last_failed_login_time = {}  # {username: timestamp} for 24h reset
repeat_count = {}  # {username: count}
last_message = {}  # {username: last_msg_text}
repeat_count_lock = threading.Lock()  # Thread-safe access to repeat_count/last_message
block_list = {}  # {username: {"blocked_until": timestamp, "block_level": 1}}
block_list_lock = threading.Lock()

FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_BLOCK_SECONDS = 60
REPEAT_MESSAGE_THRESHOLD = 5  # Changed from 10 to 5 for faster spam detection
INITIAL_BLOCK_SECONDS = 30
BLOCK_RESET_HOURS = 24


def write_socket_endpoint(host, port, source="unknown"):
    payload = {
        "host": str(host).strip(),
        "port": int(port),
        "source": source,
        "updated_at": datetime.now().isoformat(),
    }
    try:
        with open(ENDPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[CONFIG] Socket endpoint yazildi: {payload['host']}:{payload['port']} ({source})")
    except Exception as exc:
        print(f"[CONFIG] Socket endpoint dosyasi yazilamadi: {exc}")


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


def check_and_update_block_list(username):
    """Check if user is currently blocked. If 24h passed, reset block level."""
    now_ts = time.time()
    with block_list_lock:
        if username in block_list:
            entry = block_list[username]
            if now_ts < entry["blocked_until"]:
                return True, entry["blocked_until"] - now_ts  # Still blocked
            else:
                # 24h passed, reset block level for next violation
                del block_list[username]
    return False, 0


def add_to_block_list(username, block_level=1):
    """Add user to block list with exponential backoff. block_level: 1, 2, 3... corresponds to 30s, 60s, 120s..."""
    block_duration = INITIAL_BLOCK_SECONDS * (2 ** (block_level - 1))
    now_ts = time.time()
    with block_list_lock:
        block_list[username] = {
            "blocked_until": now_ts + block_duration,
            "block_level": block_level,
            "reason": "spam/brute-force",
        }
    return block_duration


def check_brute_force_login(username):
    """Check and track failed login attempts. Return True if user should be blocked."""
    now_ts = time.time()
    with failed_logins_lock:
        # Reset failed login counter if 24h has passed
        if username in last_failed_login_time:
            if now_ts - last_failed_login_time[username] > BLOCK_RESET_HOURS * 3600:
                failed_logins[username] = 0
                last_failed_login_time[username] = now_ts
        
        failed_logins[username] = failed_logins.get(username, 0) + 1
        last_failed_login_time[username] = now_ts
        
        if failed_logins[username] >= FAILED_LOGIN_THRESHOLD:
            add_to_block_list(username, block_level=1)
            return True
    return False


def check_repeated_message(username, current_msg):
    """Check for repeated message spam. Return True if spam detected. Thread-safe."""
    if not current_msg or not current_msg.strip():
        return False
    
    with repeat_count_lock:
        if last_message.get(username) == current_msg:
            repeat_count[username] = repeat_count.get(username, 0) + 1
        else:
            repeat_count[username] = 1
            last_message[username] = current_msg
        
        current_repeat = repeat_count[username]
    
    if current_repeat >= REPEAT_MESSAGE_THRESHOLD:
        # Determine block level based on current block entry (exponential)
        current_block_level = 1
        with block_list_lock:
            if username in block_list:
                current_block_level = block_list[username].get("block_level", 1) + 1
        add_to_block_list(username, block_level=current_block_level)
        with repeat_count_lock:
            repeat_count[username] = 0  # Reset after block
        return True
    return False


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

            # Check if user is blocked by security system
            is_blocked, remaining = check_and_update_block_list(username)
            if is_blocked:
                remain = int(remaining)
                alert_msg = {
                    "type": "alert",
                    "text": f"[SPAM/FLOOD] Engellendiz. Kalan sure: {remain}s",
                }
                send_packet(client_sock, alert_msg)
                broadcast(alert_msg)
                logging.warning("BLOCKED user=%s ip=%s port=%s", username, addr[0], addr[1])
                print(f"[BLOCKED] {username}: {remain}s remaining")
                continue

            # Check for repeated message spam
            # Prefer fingerprint if client provided it (SHA256 of plaintext), otherwise use raw text
            fingerprint = packet.get("fingerprint") if isinstance(packet, dict) else None
            check_val = fingerprint or text
            print(f"[SPAM_CHECK] user={username} key='{(check_val[:30] if isinstance(check_val, str) else str(check_val))}'")
            if check_repeated_message(username, check_val):
                client_info["alerts"] += 1
                with clients_lock:
                    server_stats["total_alerts"] += 1
                
                # Also update client_info blocked_until for consistency
                current_block_level = 1
                with block_list_lock:
                    if username in block_list:
                        current_block_level = block_list[username].get("block_level", 1)
                block_duration = INITIAL_BLOCK_SECONDS * (2 ** (current_block_level - 1))
                now_ts = time.time()
                client_info["blocked_until"] = now_ts + block_duration
                
                alert_msg = {
                    "type": "alert",
                    "text": f"[SPAM] {username} çok hızlı tekrar mesaj gönderiyor. {int(block_duration)}s engellendi.",
                }
                send_packet(client_sock, alert_msg)
                broadcast(alert_msg)
                logging.warning("SPAM_DETECTED user=%s ip=%s port=%s duration=%ds", username, addr[0], addr[1], int(block_duration))
                print(f"[SPAM_DETECTED] {username}: blocked for {int(block_duration)}s")
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
    
    use_ngrok = os.getenv("USE_PYNGROK", "1").strip() != "0"
    if not use_ngrok:
        print("[NGROK] Pyngrok otomatik acilis kapali (USE_PYNGROK=0 yaparsan kapatilir).")
        return None

    try:
        from pyngrok import ngrok
    except ImportError:
        print("[NGROK] pyngrok kurulu degil. Kurulum: pip install pyngrok")
        return None

    token = os.getenv("NGROK_AUTHTOKEN", "").strip()
    if token:
        ngrok.set_auth_token(token)

    try:
        tunnel = ngrok.connect(addr=local_port, proto="tcp")
        print(f"[NGROK] Public TCP URL: {tunnel.public_url}")
        public_url = str(tunnel.public_url).strip()
        # format expected: tcp://host:port
        endpoint = public_url.split("://", 1)[1] if "://" in public_url else public_url
        host, port_text = endpoint.rsplit(":", 1)
        return host.strip(), int(port_text.strip())
    except Exception as exc:
        print(f"[NGROK] Tunnel acilamadi: {exc}")
        return None


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

    ngrok_endpoint = maybe_start_ngrok(PORT)
    if ngrok_endpoint:
        write_socket_endpoint(ngrok_endpoint[0], ngrok_endpoint[1], source="ngrok")
    else:
        # Local fallback for same-machine development
        local_host = os.getenv("LOCAL_SOCKET_HOST", "127.0.0.1").strip() or "127.0.0.1"
        write_socket_endpoint(local_host, PORT, source="local")
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
