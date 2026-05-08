import sys
import os
from cryptography.fernet import Fernet


def load_key():
    k = os.getenv('FERNET_KEY', '').strip()
    if k:
        return k
    if os.path.exists('fernet.key'):
        try:
            return open('fernet.key', 'r', encoding='utf-8').read().strip()
        except Exception:
            return None
    return None


def main():
    if len(sys.argv) < 2:
        print('Usage: py tools\\decrypt_token.py "enc:v1:..." [key]')
        sys.exit(2)

    token_text = sys.argv[1]
    key = sys.argv[2] if len(sys.argv) >= 3 else None

    if not key:
        key = load_key()

    print('Using key:', '<present>' if key else '<none>')

    if not isinstance(token_text, str) or not token_text.startswith('enc:v1:'):
        print('Provided text does not look like an enc:v1 token. Raw:')
        print(token_text)
        return

    token = token_text.split(':', 2)[2]

    if not key:
        print('No key available to attempt decrypt. Provide key as second arg or set FERNET_KEY / fernet.key')
        sys.exit(1)

    try:
        f = Fernet(key.encode() if isinstance(key, str) else key)
        plain = f.decrypt(token.encode('utf-8'))
        print('Decrypted plaintext:')
        print(plain.decode('utf-8'))
    except Exception as e:
        print('Decryption failed:', e)


if __name__ == '__main__':
    main()
