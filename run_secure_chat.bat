@echo off
REM Double-click to launch the Secure Chat GUI using the project's virtualenv.
REM Edit CHAT_SOCKET_HOST and CHAT_SOCKET_PORT below if you need a different ngrok address.
cd /d "%~dp0"
if exist .venv\Scripts\activate.bat (
  call .venv\Scripts\activate.bat
)

REM --- Edit these if needed ---
set CHAT_SOCKET_HOST=8.tcp.ngrok.io
set CHAT_SOCKET_PORT=11188
REM ----------------------------

echo Using CHAT_SOCKET_HOST=%CHAT_SOCKET_HOST% CHAT_SOCKET_PORT=%CHAT_SOCKET_PORT%
python secure_chat.py
pause
