# Secure Chat and Intrusion Detection System

Bu proje, Computer Networks dersi için gelistirilmis socket tabanli bir sohbet sistemidir.

## Ozellikler

- TCP tabanli merkezi chat server
- Coklu istemci destegi (thread tabanli)
- Komutlar: `/list`, `/nick <yeniad>`, `/stats`, `/quit`
- Monitoring (bagli istemci, mesaj/alert sayaçlari)
- Intrusion Detection kurallari:
  - Spam/Flood (zaman penceresinde mesaj hizi)
  - Repeated message flooding
  - Bos/malformed davranis kontrolu
- Supheli davranista gecici blok
- `server.log` dosyasina loglama
- GUI istemci:
  - PySide6 tabanli: `gui_client_qt.py`
  - Tkinter tabanli: `gui_client.py` (yedek)

## Proje Dosyalari

- `server.py`: Chat server + IDS + monitoring + logging
- `client.py`: Komut satiri istemci
- `gui_client_qt.py`: PySide6 GUI istemci
- `gui_client.py`: Tkinter GUI istemci
- `server.log`: Sunucu olay kayitlari

## Kurulum

Python 3.9+ onerilir.

Firebase login icin proje kokune bir `.env` dosyasi ekleyebilirsin:

```env
FIREBASE_WEB_API_KEY=your_firebase_web_api_key
```

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install PySide6
```

## Calistirma

### 1) Server

```bash
python server.py
```

### 2) CLI Client

```bash
python client.py --host 127.0.0.1 --port 5555
```

### 3) GUI Client (onerilen)

```bash
python gui_client_qt.py
```

## Test Senaryolari (Ozet)

1. Normal chat: Iki istemci baglanir, mesajlasma dogrulanir.
2. Komut testi: `/list`, `/nick`, `/stats`, `/quit`.
3. IDS testi: Hizli mesaj/flood ve tekrar mesaj davranisi ile alert tetiklenmesi.
4. Block testi: Alert sonrasi gecici engel ve sure dolunca normale donus.
5. Log testi: `grep ALERT server.log` ile kanit satirlari.

## Notlar

- Test sirasinda IDS spam esigi gecici olarak degistirildiyse, teslim oncesi dokuman esigine geri alinmalidir.
- Farkli bilgisayardan baglanmak icin karsi tarafin sadece istemciyi calistirmasi yeterlidir; server tek noktada calisir.
