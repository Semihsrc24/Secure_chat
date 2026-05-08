# Secure Chat — Socket-based Real-time Chat with IDS

This repository contains a socket-based chat application built for networking projects. It includes a central chat server with simple intrusion detection rules, a PySide6 GUI client, and utilities for testing.

## Features

- Central TCP chat server
- Multi-client support (threaded)
- Basic commands: `/list`, `/nick <name>`, `/stats`, `/quit`
- Monitoring: connected clients, message/alert counters
- Simple Intrusion Detection rules for flooding/spam and repeated messages
- Temporary blocking of suspicious clients
- Firebase integration for optional authentication and message persistence

## Included Files

- `server.py` — chat server, IDS, monitoring, and optional ngrok integration
- `secure_chat.py` — main PySide6 GUI client (recommended)
- `firebase_config.py` — Firebase helper (demo mode if credentials are absent)
- `requirements.txt` — Python dependencies
- `run_secure_chat.bat` — Windows launcher for the GUI

Files excluded from the repository (should be present locally if needed):

- `serviceAccountKey.json` — Firebase service account file (DO NOT commit)

## Setup

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

3. (Optional) Place Firebase credentials at the project root as `serviceAccountKey.json` to enable full Firebase functionality.

## Run

Start the server (on the host machine):

```powershell
.venv\Scripts\python.exe server.py
```

Start the GUI client (on any machine; set `CHAT_SOCKET_HOST`/`CHAT_SOCKET_PORT` if using ngrok):

```powershell
.venv\Scripts\python.exe secure_chat.py
```

If you type `python secure_chat.py` and see a NumPy/PySide error, that means PowerShell is using the system Python instead of the project virtual environment. Run this first:

```powershell
.\.venv\Scripts\Activate.ps1
```

Alternatively use the included Windows launcher:

```powershell
run_secure_chat.bat
```

## Notes

- Keep your Firebase keys out of the repository. The project automatically uses demo mode when no service account is present.
- If using ngrok, run the server with ngrok enabled to obtain a public TCP endpoint and share the `tcp://...` address with remote clients.

## License

MIT

---

If you want additional cleanup (remove virtualenvs, build a single executable, or publish a release), tell me which step to perform next.
