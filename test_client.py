#!/usr/bin/env python3
"""
Test client that connects to server and responds to ping messages.
Used for RTT measurement testing.
"""

import socket
import json
import threading
import time
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5555

def main():
    print("=" * 50)
    print("  TEST CLIENT")
    print(f"  Connecting to {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 50)
    
    try:
        sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=10)
        print(f"[CONNECTED] Test client connected\n")
    except Exception as e:
        print(f"[ERROR] Could not connect: {e}")
        sys.exit(1)
    
    # Send initial nickname packet
    nickname_packet = json.dumps({
        "type": "nickname",
        "name": "TestClient",
        "uid": "test_client_uid_001"
    })
    sock.sendall((nickname_packet + "\n").encode("utf-8"))
    
    # Receive welcome message
    try:
        welcome = sock.recv(1024).decode("utf-8")
        print(f"[WELCOME] {welcome.strip()}\n")
    except Exception:
        pass
    
    def receive_loop():
        """Listen for incoming packets and respond to pings."""
        try:
            sock.settimeout(None)
            reader = sock.makefile("r", encoding="utf-8", newline="\n")
            
            while True:
                line = reader.readline()
                if not line:
                    break
                
                try:
                    packet = json.loads(line.strip())
                except Exception:
                    continue
                
                packet_type = packet.get("type")
                
                if packet_type == "ping":
                    # Respond to ping immediately
                    pong = json.dumps({"type": "pong", "timestamp": time.time()})
                    sock.sendall((pong + "\n").encode("utf-8"))
                    print(f"[PING] Received ping, sent pong")
                
                elif packet_type == "system":
                    print(f"[SYSTEM] {packet.get('text', '')}")
                
                elif packet_type == "message":
                    sender = packet.get("sender_name", "Unknown")
                    text = packet.get("text", "")
                    print(f"[MESSAGE] {sender}: {text}")
        
        except Exception as e:
            print(f"[RECV_ERROR] {e}")
        finally:
            sock.close()
            print("[DISCONNECTED]")
    
    # Start receive loop in background thread
    recv_thread = threading.Thread(target=receive_loop, daemon=True)
    recv_thread.start()
    
    # Keep client running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Closing...")
        sock.close()

if __name__ == "__main__":
    main()
