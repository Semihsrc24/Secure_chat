#!/usr/bin/env python3
"""Quick test to verify admin port is working."""
import socket
import json
import time

sock = socket.create_connection(("127.0.0.1", 5001), timeout=5)
print("[CONNECTED]")

# Send get_stats command
command = json.dumps({"action": "get_stats"}) + "\n"
sock.sendall(command.encode("utf-8"))
print(f"[SENT] {command.strip()}")

# Receive response
response = sock.recv(1024).decode("utf-8").strip()
print(f"[RECV] {response}")

data = json.loads(response)
print(f"Stats: {data}")

sock.close()
