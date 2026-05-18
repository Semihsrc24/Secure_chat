import os
import socket
import threading
import time
import logging
import json
from datetime import datetime
from collections import deque
import csv

HOST = "0.0.0.0"
PORT = 5555
ADMIN_PORT = 5001
BUFFER_SIZE = 2048

RATE_LIMIT_MESSAGES = 10
RATE_LIMIT_WINDOW_SEC = 5
REPEAT_THRESHOLD = 5
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

# RTT Measurement and Metrics
admin_clients = {}  # {socket: {"connected_at": timestamp}}
admin_clients_lock = threading.Lock()
rtt_measurements = []  # List of RTT values for averaging
rtt_lock = threading.Lock()
METRICS_FILE = "rtt_metrics.csv"
DETECTION_CSV = "detection_events.csv"

FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_BLOCK_SECONDS = 60
REPEAT_MESSAGE_THRESHOLD = 5
INITIAL_BLOCK_SECONDS = 30
BLOCK_RESET_HOURS = 24


def init_metrics_file():
    """Initialize RTT metrics CSV file with headers if not exists."""
    try:
        if not os.path.exists(METRICS_FILE):
            with open(METRICS_FILE, "w", encoding="utf-8") as f:
                f.write("timestamp,rtt_ms,client_count,total_messages\n")
    except Exception:
        pass


def write_metrics(rtt_ms: float):
    """Append RTT measurement to CSV."""
    try:
        with clients_lock:
            client_count = len(clients)
            total_msgs = server_stats["total_messages"]
        with open(METRICS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.utcnow().isoformat()},{rtt_ms:.2f},{client_count},{total_msgs}\n")
    except Exception:
        pass


def append_detection_csv(row: dict):
    """Append a detection/event row to DETECTION_CSV. Creates header if missing."""
    fieldnames = [
        "timestamp",
        "username",
        "event",
        "detail",
        "repeat_count",
        "failed_count",
        "blocked_until",
        "response_ms",
    ]
    try:
        file_exists = os.path.exists(DETECTION_CSV)
        with open(DETECTION_CSV, "a", encoding="utf-8", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow({k: row.get(k, "") for k in fieldnames})
    except Exception:
        pass


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
        print(f"[CONFIG] Socket endpoint written: {payload['host']}:{payload['port']} ({source})")
    except Exception as exc:
        print(f"[CONFIG] Failed to write socket endpoint file: {exc}")


def send_packet(sock, payload):
    try:
        data = json.dumps(payload, ensure_ascii=False) + "\n"
        sock.sendall(data.encode("utf-8"))
    except Exception:
        remove_client(sock)


def store_public_key(uid: str, public_key_pem: str):
    """Store user's public key in a simple JSON file for E2E key exchange."""
    try:
        keys_file = "public_keys.json"
        keys_data = {}
        
        if os.path.exists(keys_file):
            try:
                with open(keys_file, "r", encoding="utf-8") as f:
                    keys_data = json.load(f)
            except Exception:
                keys_data = {}
        
        keys_data[uid] = public_key_pem
        
        with open(keys_file, "w", encoding="utf-8") as f:
            json.dump(keys_data, f, ensure_ascii=False, indent=2)
        
        print(f"[E2E] Public key stored for user {uid}")
        return True
    except Exception as e:
        print(f"[E2E] Failed to store public key for {uid}: {e}")
        return False


def get_public_key(uid: str) -> str:
    """Retrieve user's public key for E2E encryption."""
    try:
        keys_file = "public_keys.json"
        if not os.path.exists(keys_file):
            return ""
        
        with open(keys_file, "r", encoding="utf-8") as f:
            keys_data = json.load(f)
        
        return keys_data.get(uid, "")
    except Exception as e:
        print(f"[E2E] Failed to retrieve public key for {uid}: {e}")
        return ""


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
        return "(no one online)"
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
                # Log to detection.log
                try:
                    with open("detection.log", "a", encoding="utf-8") as df:
                        df.write(f"{datetime.utcnow().isoformat()} - BRUTE_FORCE detected - user={username} failed={failed_logins[username]}\n")
                except Exception:
                    pass
                # Append structured CSV entry
                try:
                    append_detection_csv({
                        "timestamp": datetime.utcnow().isoformat(),
                        "username": username,
                        "event": "brute_force",
                        "detail": "failed_login_threshold_reached",
                        "repeat_count": "",
                        "failed_count": failed_logins[username],
                        "blocked_until": block_list.get(username, {}).get("blocked_until", ""),
                        "response_ms": "",
                    })
                except Exception:
                    pass
                return True
    return False


def check_repeated_message(username, current_msg):
    """Check for repeated message repetition. Return a reason string if detected. Thread-safe."""
    if not current_msg or not current_msg.strip():
        return None
    
    with repeat_count_lock:
        prev = last_message.get(username)
        if prev == current_msg:
            repeat_count[username] = repeat_count.get(username, 0) + 1
        else:
            repeat_count[username] = 1
            last_message[username] = current_msg
        
        current_repeat = repeat_count[username]
        print(f"[DEBUG_SPAM] user={username} prev_key={(prev[:20] if isinstance(prev, str) else prev)} new_key={(str(current_msg)[:20])} repeat={current_repeat}")
    
    if current_repeat >= REPEAT_MESSAGE_THRESHOLD:
        # Determine block level based on current block entry (exponential)
        current_block_level = 1
        with block_list_lock:
            if username in block_list:
                current_block_level = block_list[username].get("block_level", 1) + 1
        add_to_block_list(username, block_level=current_block_level)
        with repeat_count_lock:
            repeat_count[username] = 0  # Reset after block
        # Log repetition detection
        try:
            with open("detection.log", "a", encoding="utf-8") as df:
                df.write(f"{datetime.utcnow().isoformat()} - REPETITION detected - user={username} repeat_count={current_repeat} key={str(current_msg)[:64]}\n")
        except Exception:
            pass
        return f"Repetition detected: same message sent {current_repeat} times in a row"
    return None


def remove_client(sock):
    with clients_lock:
        info = clients.pop(sock, None)

    username = info["name"] if info else None

    try:
        sock.close()
    except Exception:
        pass

    if username:
        msg = {"type": "system", "text": f"{username} left."}
        print(f"[SERVER] {username} left.")
        logging.info("DISCONNECT user=%s", username)
        broadcast(msg)


def unique_name(requested_name):
    name = requested_name.strip() if requested_name.strip() else "Guest"
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


def print_monitor_status():
    """Print current monitor status."""
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


def monitor_loop():
    while running:
        time.sleep(MONITOR_INTERVAL_SEC)
        print_monitor_status()


def handle_client(client_sock, addr):
    # In this client protocol, the first packet is expected as nickname/auth payload.
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

        requested_name = str(first_packet.get("name") or first_packet.get("uid") or "Guest").strip()
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
            f"Welcome {username}!"
        )
        send_packet(client_sock, {"type": "system", "text": welcome, "uid": uid, "name": username})

        join_msg = {"type": "system", "text": f"{username} joined the chat.", "uid": uid, "name": username}
        print(f"{addr[0]}:{addr[1]} -> {username} connected")
        logging.info("CONNECT user=%s ip=%s port=%s", username, addr[0], addr[1])
        print_monitor_status()
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

            # Handle E2E public key exchange
            if packet_type == "key_exchange":
                user_id = str(packet.get("user_id", "")).strip()
                public_key = str(packet.get("public_key", "")).strip()
                
                if user_id and public_key:
                    store_public_key(user_id, public_key)
                    send_packet(client_sock, {
                        "type": "system",
                        "text": "[E2E] Public key registered successfully"
                    })
                    logging.info("E2E_KEY_EXCHANGE user_id=%s", user_id)
                continue

            if packet_type in {"message", "command", "text"}:
                text = str(packet.get("text", text)).strip()

            now_ts = time.time()

            if is_command_packet:
                if text.lower() == "/quit":
                    send_packet(client_sock, {"type": "system", "text": "Connection is closing..."})
                    break

                if text.lower() == "/list":
                    send_packet(client_sock, {"type": "system", "text": f"Online: {online_users_text()}"})
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
                        send_packet(client_sock, {"type": "system", "text": "Usage: /nick <new_name>"})
                        continue

                    new_name = unique_name(parts[1])
                    with clients_lock:
                        old_name = clients.get(client_sock, client_info)["name"]
                        clients[client_sock]["name"] = new_name
                    username = new_name
                    client_info["name"] = new_name

                    broadcast({"type": "system", "text": f"{old_name} is now known as {new_name}."})
                    logging.info("NICK old=%s new=%s", old_name, new_name)
                    continue

            if now_ts < client_info["blocked_until"]:
                remain = int(client_info["blocked_until"] - now_ts)
                send_packet(client_sock, {"type": "system", "text": f"You are temporarily blocked. Remaining time: {remain}s"})
                continue

            # Check if user is blocked by security system
            is_blocked, remaining = check_and_update_block_list(username)
            if is_blocked:
                remain = int(remaining)
                alert_msg = {
                    "type": "alert",
                    "text": f"[SPAM/FLOOD] You are blocked. Remaining time: {remain}s",
                    "target_uid": uid,
                    "target_username": username,
                    "block_reason": "blocked",
                    "blocked_until": time.time() + remaining,
                    "block_seconds": remain,
                }
                send_packet(client_sock, alert_msg)
                logging.warning("BLOCKED user=%s ip=%s port=%s", username, addr[0], addr[1])
                print(f"[BLOCKED] {username}: {remain}s remaining")
                continue

            # Check for repeated message spam
            # Prefer fingerprint if client provided it (SHA256 of plaintext), otherwise use raw text
            fingerprint = packet.get("fingerprint") if isinstance(packet, dict) else None
            check_val = fingerprint or text
            print(f"[SPAM_CHECK] user={username} key='{(check_val[:30] if isinstance(check_val, str) else str(check_val))}'")
            # measure detection -> alert send timing
            detect_call_ts = time.time()
            repetition_reason = check_repeated_message(username, check_val)
            if repetition_reason:
                alert_sent_ts = time.time()
                response_ms = (alert_sent_ts - detect_call_ts) * 1000.0
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
                    "text": f"[REPETITION] {username} is sending the same message repeatedly. Blocked for {int(block_duration)}s.",
                    "target_uid": uid,
                    "target_username": username,
                    "block_reason": "repetition",
                    "blocked_until": client_info["blocked_until"],
                    "block_seconds": int(block_duration),
                }
                # append structured CSV entry for this repetition detection including server-side response_ms
                try:
                    append_detection_csv({
                        "timestamp": datetime.utcnow().isoformat(),
                        "username": username,
                        "event": "repetition",
                        "detail": str(check_val)[:128],
                        "repeat_count": repeat_count.get(username, ""),
                        "failed_count": "",
                        "blocked_until": client_info["blocked_until"],
                        "response_ms": f"{response_ms:.2f}",
                    })
                except Exception:
                    pass

                send_packet(client_sock, alert_msg)
                logging.warning("REPETITION_DETECTED user=%s ip=%s port=%s duration=%ds", username, addr[0], addr[1], int(block_duration))
                print(f"[REPETITION_DETECTED] {username}: blocked for {int(block_duration)}s")
                continue

            reason = detect_intrusion(client_info, text, now_ts)
            if reason:
                # record detection timestamp and measure server-side response time
                detect_ts = time.time()
                client_info["alerts"] += 1
                client_info["blocked_count"] += 1
                client_info["blocked_until"] = now_ts + BLOCK_SECONDS
                with clients_lock:
                    server_stats["total_alerts"] += 1

                is_rate_limit_spam = reason.startswith("Spam/Flood")
                alert_reason = "spam" if is_rate_limit_spam else "suspicious"
                alert_text_value = (
                    f"[SPAM] {client_info['name']} is sending messages too quickly. Blocked for {BLOCK_SECONDS}s."
                    if is_rate_limit_spam
                    else (
                        f"Suspicious activity: user={client_info['name']} "
                        f"reason={reason} block={BLOCK_SECONDS}s"
                    )
                )

                alert_text = {
                    "type": "alert",
                    "text": alert_text_value,
                    "target_uid": uid,
                    "target_username": username,
                    "block_reason": alert_reason,
                    "blocked_until": client_info["blocked_until"],
                    "block_seconds": BLOCK_SECONDS,
                }
                # Log suspicious activity to detection.log and CSV
                try:
                    with open("detection.log", "a", encoding="utf-8") as df:
                        df.write(
                            f"{datetime.utcnow().isoformat()} - {alert_reason.upper()} activity - user={username} reason={reason}\n"
                        )
                except Exception:
                    pass

                # append CSV entry (response_ms measured as approx time until sending alert)
                try:
                    alert_send_ts = time.time()
                    response_ms = (alert_send_ts - detect_ts) * 1000.0
                    append_detection_csv({
                        "timestamp": datetime.utcnow().isoformat(),
                        "username": username,
                        "event": alert_reason,
                        "detail": reason,
                        "repeat_count": client_info.get("repeat_count", ""),
                        "failed_count": "",
                        "blocked_until": client_info["blocked_until"],
                        "response_ms": f"{response_ms:.2f}",
                    })
                except Exception:
                    pass

                send_packet(client_sock, alert_text)
                if is_rate_limit_spam:
                    logging.warning(
                        "SPAM user=%s ip=%s port=%s reason=%s",
                        client_info["name"],
                        addr[0],
                        addr[1],
                        reason,
                    )
                else:
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
                    "fingerprint": packet.get("fingerprint", ""),
                    "client_message_id": packet.get("client_message_id", ""),
                }
            )
            logging.info("MSG user=%s text=%s", client_info["name"], text)

    except Exception as exc:
        print(f"Error ({addr[0]}:{addr[1]}): {exc}")
        logging.exception("CLIENT_ERROR ip=%s port=%s err=%s", addr[0], addr[1], exc)
    finally:
        remove_client(client_sock)
        try:
            reader.close()
        except Exception:
            pass


def handle_admin_client(admin_sock, addr):
    """Handle admin dashboard connection for RTT monitoring and metrics."""
    with admin_clients_lock:
        admin_clients[admin_sock] = {"connected_at": time.time()}
    
    print(f"[ADMIN] Connection accepted from {addr[0]}:{addr[1]}")
    logging.info("ADMIN_CONNECT ip=%s port=%s", addr[0], addr[1])
    print_monitor_status()
    
    try:
        admin_sock.settimeout(60)
        while running:
            try:
                data = admin_sock.recv(BUFFER_SIZE).decode("utf-8").strip()
                if not data:
                    break
                
                command = json.loads(data)
                action = command.get("action", "").strip()
                
                if action == "measure_rtt":
                    # Send ping to all main chat clients
                    start_time = time.time()
                    
                    # Broadcast ping to all connected clients
                    with clients_lock:
                        client_socks = list(clients.keys())
                    
                    if client_socks:
                        ping_packet = {"type": "ping"}
                        for client_sock in client_socks:
                            try:
                                send_packet(client_sock, ping_packet)
                            except Exception:
                                pass
                        
                        # Simple RTT: measure time spent sending pings
                        end_time = time.time()
                        rtt_ms = (end_time - start_time) * 1000
                    else:
                        rtt_ms = 0
                    
                    # Record measurement
                    with rtt_lock:
                        rtt_measurements.append(rtt_ms)
                        if len(rtt_measurements) > 100:  # Keep last 100 measurements
                            rtt_measurements.pop(0)
                        avg_rtt = sum(rtt_measurements) / len(rtt_measurements)
                    
                    write_metrics(rtt_ms)
                    
                    # Send result back to admin
                    result = {
                        "type": "RTT_UPDATE",
                        "value": rtt_ms,
                        "average": avg_rtt,
                        "client_count": len(client_socks),
                    }
                    admin_sock.sendall((json.dumps(result) + "\n").encode("utf-8"))
                    
                    print(f"[ADMIN] RTT measured: {rtt_ms:.2f}ms (avg: {avg_rtt:.2f}ms)")
                    logging.info("RTT_MEASUREMENT rtt_ms=%.2f avg_ms=%.2f", rtt_ms, avg_rtt)
                
                elif action == "get_stats":
                    # Return current server statistics
                    with clients_lock:
                        client_count = len(clients)
                        client_names = [info.get("name", "-") for info in clients.values()]
                        total_msgs = server_stats["total_messages"]
                        total_alerts = server_stats["total_alerts"]
                    
                    with rtt_lock:
                        avg_rtt = sum(rtt_measurements) / len(rtt_measurements) if rtt_measurements else 0
                    
                    stats = {
                        "type": "STATS_UPDATE",
                        "client_count": client_count,
                        "client_names": client_names,
                        "total_messages": total_msgs,
                        "total_alerts": total_alerts,
                        "avg_rtt": avg_rtt,
                    }
                    admin_sock.sendall((json.dumps(stats) + "\n").encode("utf-8"))
                
            except socket.timeout:
                continue
            except json.JSONDecodeError:
                continue
            except Exception as exc:
                print(f"[ADMIN] Error: {exc}")
                break
    
    except Exception as exc:
        print(f"[ADMIN] Connection error from {addr}: {exc}")
        logging.exception("ADMIN_ERROR ip=%s port=%s", addr[0], addr[1])
    
    finally:
        with admin_clients_lock:
            admin_clients.pop(admin_sock, None)
        try:
            admin_sock.close()
        except Exception:
            pass
        print(f"[ADMIN] Disconnected {addr[0]}:{addr[1]}")
        logging.info("ADMIN_DISCONNECT ip=%s port=%s", addr[0], addr[1])


def maybe_start_ngrok(local_port):
    
    use_ngrok = os.getenv("USE_PYNGROK", "1").strip() != "0"
    if not use_ngrok:
        print("[NGROK] Automatic pyngrok startup is disabled (set USE_PYNGROK=0).")
        return None

    try:
        from pyngrok import ngrok
    except ImportError:
        print("[NGROK] pyngrok is not installed. Install with: pip install pyngrok")
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
        print(f"[NGROK] Failed to open tunnel: {exc}")
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

    init_metrics_file()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    admin_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    admin_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    admin_server.bind((HOST, ADMIN_PORT))
    admin_server.listen(10)

    print("=" * 45)
    print("  PYTHON CHAT SERVER")
    print(f"  Listening on: {HOST}:{PORT}")
    print(f"  Admin Dashboard: {HOST}:{ADMIN_PORT}")
    print("  Client commands: /quit /list /nick")
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

    def admin_accept_loop():
        while running:
            try:
                admin_sock, addr = admin_server.accept()
                t = threading.Thread(target=handle_admin_client, args=(admin_sock, addr), daemon=True)
                t.start()
            except OSError:
                # Server socket closed
                break
            except Exception as exc:
                print(f"[ADMIN] Accept error: {exc}")

    admin_thread = threading.Thread(target=admin_accept_loop, daemon=True)
    admin_thread.start()

    try:
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
    finally:
        running = False
        with clients_lock:
            socks = list(clients.keys())
        for s in socks:
            try:
                s.close()
            except Exception:
                pass
        with admin_clients_lock:
            admin_socks = list(admin_clients.keys())
        for s in admin_socks:
            try:
                s.close()
            except Exception:
                pass
        server.close()
        admin_server.close()


if __name__ == "__main__":
    main()
