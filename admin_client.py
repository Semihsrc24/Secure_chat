#!/usr/bin/env python3
"""
Simple admin client for monitoring server RTT and metrics.
Connect to port 5001 (ADMIN_PORT).
"""

import socket
import json
import time
import sys

ADMIN_HOST = "127.0.0.1"
ADMIN_PORT = 5001

def main():
    print("=" * 50)
    print("  ADMIN DASHBOARD CLIENT")
    print(f"  Connecting to {ADMIN_HOST}:{ADMIN_PORT}")
    print("=" * 50)
    print("Commands:")
    print("  measure_rtt      - Measure round-trip time")
    print("  get_stats        - Get server statistics")
    print("  quit             - Exit")
    print()

    try:
        sock = socket.create_connection((ADMIN_HOST, ADMIN_PORT), timeout=10)
        print(f"[CONNECTED] Admin client connected\n")
    except Exception as e:
        print(f"[ERROR] Could not connect: {e}")
        sys.exit(1)

    try:
        while True:
            cmd = input("admin> ").strip().lower()
            
            if cmd == "quit" or cmd == "exit":
                break
            
            elif cmd == "measure_rtt":
                command = json.dumps({"action": "measure_rtt"})
                sock.sendall((command + "\n").encode("utf-8"))
                
                response = sock.recv(4096).decode("utf-8").strip()
                if response:
                    data = json.loads(response)
                    print(f"  RTT: {data.get('value', 0):.2f} ms")
                    print(f"  Average RTT: {data.get('average', 0):.2f} ms")
                    print(f"  Clients: {data.get('client_count', 0)}")
                    print()
            
            elif cmd == "get_stats":
                command = json.dumps({"action": "get_stats"})
                sock.sendall((command + "\n").encode("utf-8"))
                
                response = sock.recv(4096).decode("utf-8").strip()
                if response:
                    data = json.loads(response)
                    print(f"  Clients: {data.get('client_count', 0)}")
                    print(f"  Total messages: {data.get('total_messages', 0)}")
                    print(f"  Total alerts: {data.get('total_alerts', 0)}")
                    print(f"  Average RTT: {data.get('avg_rtt', 0):.2f} ms")
                    print()
            
            elif cmd:
                print(f"  Unknown command: {cmd}")
    
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Exiting...")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("[DISCONNECTED]")

if __name__ == "__main__":
    main()
