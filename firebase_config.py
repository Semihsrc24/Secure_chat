"""
Firebase Configuration
Uses Firebase Realtime Database and Authentication
"""

from datetime import datetime
import json
import os
from pathlib import Path
import secrets

# Gracefully handle missing firebase_admin package
try:
    import firebase_admin
    from firebase_admin import credentials, db, auth
    _HAS_FIREBASE = True
except ImportError:
    _HAS_FIREBASE = False
    firebase_admin = None
    credentials = None
    db = None
    auth = None


def _load_dotenv_file() -> None:
    """Load simple KEY=VALUE pairs from a local .env file if present."""
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return

    try:
        for raw_line in env_path.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip().lstrip("\ufeff")
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value
    except Exception as exc:
        print(f"[WARNING] .env load error: {exc}")


_load_dotenv_file()

# Firebase credentials dosyası (Firebase Console'dan indirin)
# serviceAccountKey.json dosyasını bu dizine koyun
CREDENTIALS_PATH = "serviceAccountKey.json"
DATABASE_URL = "https://chatapp-bd95e-default-rtdb.firebaseio.com"
WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY", "AIzaSyACsaMjrXG6CjHbWDCtMxdivKlylAq4IZk")


class FirebaseManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        try:
            # Check if firebase_admin is available
            if not _HAS_FIREBASE:
                print("[WARNING] firebase_admin not installed - Demo mode enabled")
                self._demo_mode = True
                self._initialized = True
                return

            # Firebase Admin SDK başlat
            if not os.path.exists(CREDENTIALS_PATH):
                print(f"[WARNING] {CREDENTIALS_PATH} not found!")
                print("Demo mode enabled - real Firebase connection will not be used")
                self._demo_mode = True
                self._initialized = True
                return
                
            cred = credentials.Certificate(CREDENTIALS_PATH)
            firebase_admin.initialize_app(
                cred,
                {
                    "databaseURL": DATABASE_URL
                }
            )
            self._demo_mode = False
            self._initialized = True
            print("[OK] Firebase connected")
        except Exception as e:
            print(f"[WARNING] Firebase error, demo mode enabled: {e}")
            self._demo_mode = True
            self._initialized = True

    # ==================== Authentication ====================

    @staticmethod
    def _make_tag(username: str, discriminator: str) -> str:
        return f"{username}#{discriminator}"

    @staticmethod
    def _generate_discriminator(users: dict) -> str:
        """Generate a unique 4-digit discriminator."""
        existing = {
            str(info.get("discriminator", "")).zfill(4)
            for info in users.values()
            if isinstance(info, dict)
        }

        for _ in range(1000):
            candidate = f"{secrets.randbelow(10000):04d}"
            if candidate not in existing:
                return candidate

        return f"{secrets.randbelow(10000):04d}"

    @staticmethod
    def _find_user_by_identifier(users: dict, identifier: str, current_uid: str | None = None):
        """Find user by UID, tag or email."""
        normalized = identifier.strip().lower()

        if identifier in users:
            if current_uid and identifier == current_uid:
                return None, None
            return identifier, users.get(identifier)

        for uid, info in users.items():
            if current_uid and uid == current_uid:
                continue

            if not isinstance(info, dict):
                continue

            email = str(info.get("email", "")).strip().lower()
            tag = str(info.get("tag", "")).strip().lower()
            if normalized == email or normalized == tag:
                return uid, info

        return None, None

    @staticmethod
    def _ensure_user_tag(uid: str, user: dict) -> dict:
        """Backfill missing tag/discriminator for existing users."""
        if not isinstance(user, dict):
            return user

        if user.get("tag") and user.get("discriminator"):
            return user

        try:
            if FirebaseManager()._demo_mode:
                if hasattr(FirebaseManager, '_demo_users') and uid in FirebaseManager._demo_users:
                    demo_users = FirebaseManager._demo_users
                    discriminator = user.get("discriminator") or FirebaseManager._generate_discriminator(demo_users)
                    username = user.get("username", "User")
                    demo_users[uid]["discriminator"] = discriminator
                    demo_users[uid]["tag"] = FirebaseManager._make_tag(username, discriminator)
                    return demo_users[uid]

            ref = db.reference("users")
            all_users = ref.get() or {}
            discriminator = user.get("discriminator") or FirebaseManager._generate_discriminator(all_users)
            username = user.get("username", "User")
            tag = FirebaseManager._make_tag(username, discriminator)
            updates = {"discriminator": discriminator, "tag": tag}
            db.reference(f"users/{uid}").update(updates)
            user.update(updates)
        except Exception as exc:
            print(f"Tag backfill error: {exc}")

        return user

    @staticmethod
    def _auth_error_message(error_code: str) -> str:
        """Map Firebase Auth REST error codes to readable messages."""
        mapping = {
            "INVALID_LOGIN_CREDENTIALS": "Email or password is incorrect.",
            "INVALID_PASSWORD": "Email or password is incorrect.",
            "EMAIL_NOT_FOUND": "Email or password is incorrect.",
            "USER_DISABLED": "This user account is disabled.",
            "OPERATION_NOT_ALLOWED": "Email/Password sign-in is not enabled in Firebase Authentication.",
            "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many login attempts. Please try again later.",
            "INVALID_API_KEY": "Invalid Firebase Web API Key.",
            "API_KEY_INVALID": "Invalid Firebase Web API Key.",
        }
        return mapping.get(error_code, f"Login failed: {error_code}")

    @staticmethod
    def register_user(email: str, password: str, username: str) -> dict:
        """Register a new user"""
        try:
            if FirebaseManager()._demo_mode:
                # Demo mode - local veri depolama
                import uuid
                uid = str(uuid.uuid4())
                if not hasattr(FirebaseManager, '_demo_users'):
                    FirebaseManager._demo_users = {}
                discriminator = FirebaseManager._generate_discriminator(FirebaseManager._demo_users)
                FirebaseManager._demo_users[uid] = {
                    "email": email,
                    "username": username,
                    "discriminator": discriminator,
                    "tag": FirebaseManager._make_tag(username, discriminator),
                    "password": password
                }
                return {"success": True, "uid": uid, "message": "Demo: Registration successful"}
            
            # Firebase Auth'ta kullanıcı oluştur
            user = auth.create_user(email=email, password=password)

            ref = db.reference("users")
            existing_users = ref.get() or {}
            discriminator = FirebaseManager._generate_discriminator(existing_users)

            # Kullanıcı bilgilerini Realtime Database'e kaydet
            user_ref = db.reference(f"users/{user.uid}")
            user_ref.set({
                "email": email,
                "username": username,
                "discriminator": discriminator,
                "tag": FirebaseManager._make_tag(username, discriminator),
                "created_at": datetime.now().isoformat(),
                "status": "online",
                "avatar": ""
            })

            return {"success": True, "uid": user.uid, "message": "Registration successful"}
        except auth.EmailAlreadyExistsError:
            return {"success": False, "message": "This email is already registered"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    @staticmethod
    def login_user(email: str, password: str) -> dict:
        """User login"""
        try:
            if FirebaseManager()._demo_mode:
                # Demo mode - local kontrol
                if not hasattr(FirebaseManager, '_demo_users'):
                    return {"success": False, "message": "User not found. Please sign up."}
                    
                for uid, user in FirebaseManager._demo_users.items():
                    if user["email"] == email and user["password"] == password:
                        return {
                            "success": True,
                            "uid": uid,
                            "token": "demo_token",
                            "message": "Login successful (Demo)"
                        }
                return {"success": False, "message": "Email or password incorrect"}
            
            # Firebase REST API login with Web API Key
            import requests

            api_key = WEB_API_KEY.strip()
            if not api_key:
                return {
                    "success": False,
                    "message": "FIREBASE_WEB_API_KEY is missing. Set it in your environment.",
                }

            response = requests.post(
                f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}",
                json={"email": email, "password": password, "returnSecureToken": True}
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "uid": data["localId"],
                    "token": data["idToken"],
                    "message": "Login successful"
                }
            else:
                try:
                    err = response.json().get("error", {})
                    err_code = err.get("message", "UNKNOWN_ERROR")
                except Exception:
                    err_code = f"HTTP_{response.status_code}"
                return {"success": False, "message": FirebaseManager._auth_error_message(err_code)}
        except Exception as e:
            return {"success": False, "message": str(e)}

    # ==================== User Management ====================

    @staticmethod
    def get_user_profile(uid: str) -> dict:
        """Get user profile"""
        try:
            if FirebaseManager()._demo_mode:
                if hasattr(FirebaseManager, '_demo_users') and uid in FirebaseManager._demo_users:
                    user = FirebaseManager._ensure_user_tag(uid, FirebaseManager._demo_users[uid])
                    return {
                        "username": user.get("username", "User"),
                        "email": user.get("email", ""),
                        "tag": user.get("tag", ""),
                        "discriminator": user.get("discriminator", ""),
                        "status": "online",
                        "created_at": datetime.now().isoformat()
                    }
                return {}
            
            ref = db.reference(f"users/{uid}")
            user = ref.get()
            if not user:
                return {}
            return FirebaseManager._ensure_user_tag(uid, user)
        except Exception as e:
            print(f"Profile fetch error: {e}")
            return {}

    @staticmethod
    def update_user_status(uid: str, status: str):
        """Update user status (online/offline)"""
        try:
            if FirebaseManager()._demo_mode:
                if hasattr(FirebaseManager, '_demo_users') and uid in FirebaseManager._demo_users:
                    FirebaseManager._demo_users[uid]["status"] = status
                return
            
            ref = db.reference(f"users/{uid}")
            ref.update({"status": status, "last_seen": datetime.now().isoformat()})
        except Exception as e:
            print(f"Status update error: {e}")

    @staticmethod
    def update_user_profile(uid: str, updates: dict):
        """Update user profile with given fields (e.g., public_key)"""
        try:
            if FirebaseManager()._demo_mode:
                if hasattr(FirebaseManager, '_demo_users') and uid in FirebaseManager._demo_users:
                    FirebaseManager._demo_users[uid].update(updates)
                return True
            
            ref = db.reference(f"users/{uid}")
            ref.update(updates)
            return True
        except Exception as e:
            print(f"Profile update error: {e}")
            return False

    @staticmethod
    def get_all_users(current_uid: str) -> dict:
        """Get all users (excluding current)"""
        try:
            if FirebaseManager()._demo_mode:
                if not hasattr(FirebaseManager, '_demo_users'):
                    return {}
                result = {}
                for uid, user in FirebaseManager._demo_users.items():
                    if uid != current_uid:
                        result[uid] = {
                            "username": user.get("username", "User"),
                            "tag": user.get("tag", ""),
                            "status": "online"
                        }
                return result
            
            ref = db.reference("users")
            users = ref.get()

            if not users:
                return {}

            # Kendisi hariç tüm kullanıcıları döndür
            return {uid: info for uid, info in users.items() if uid != current_uid}
        except Exception as e:
            print(f"User list error: {e}")
            return {}

    # ==================== Friends ====================

    @staticmethod
    def add_friend(current_uid: str, friend_identifier: str) -> dict:
        """Send a friend request by UID, tag or email for current_uid"""
        try:
            if FirebaseManager()._demo_mode:
                if not hasattr(FirebaseManager, '_demo_users'):
                    return {"success": False, "message": "No users exist"}

                friend_uid, friend_user = FirebaseManager._find_user_by_identifier(
                    FirebaseManager._demo_users, friend_identifier, current_uid
                )

                if not friend_uid:
                    return {"success": False, "message": "User not found"}

                if 'friends' not in FirebaseManager._demo_users[current_uid]:
                    FirebaseManager._demo_users[current_uid]['friends'] = {}
                if friend_uid in FirebaseManager._demo_users[current_uid]['friends']:
                    return {"success": False, "message": "Already friends"}

                if 'friend_requests' not in FirebaseManager._demo_users[friend_uid]:
                    FirebaseManager._demo_users[friend_uid]['friend_requests'] = {}

                FirebaseManager._demo_users[friend_uid]['friend_requests'][current_uid] = {
                    "from_uid": current_uid,
                    "from_username": FirebaseManager._demo_users[current_uid].get("username", "User"),
                    "from_tag": FirebaseManager._demo_users[current_uid].get("tag", ""),
                    "timestamp": datetime.now().isoformat(),
                    "status": "pending"
                }
                return {"success": True, "friend_uid": friend_uid, "message": "Friend request sent (Demo)"}

            # Gerçek Firebase
            ref = db.reference("users")
            users = ref.get() or {}

            friend_uid, friend_user = FirebaseManager._find_user_by_identifier(users, friend_identifier, current_uid)

            if not friend_uid:
                return {"success": False, "message": "User not found"}

            if db.reference(f"users/{current_uid}/friends/{friend_uid}").get():
                return {"success": False, "message": "Already friends"}

            current_user = db.reference(f"users/{current_uid}").get() or {}
            db.reference(f"users/{friend_uid}/friend_requests/{current_uid}").set({
                "from_uid": current_uid,
                "from_username": current_user.get("username", "User"),
                "from_tag": current_user.get("tag", ""),
                "timestamp": datetime.now().isoformat(),
                "status": "pending"
            })
            return {"success": True, "friend_uid": friend_uid, "message": "Friend request sent"}
        except Exception as e:
            print(f"Add friend error: {e}")
            return {"success": False, "message": str(e)}

    @staticmethod
    def get_friend_requests(uid: str) -> dict:
        """Return incoming friend requests."""
        try:
            if FirebaseManager()._demo_mode:
                if not hasattr(FirebaseManager, '_demo_users') or uid not in FirebaseManager._demo_users:
                    return {}

                requests = FirebaseManager._demo_users[uid].get('friend_requests', {})
                result = {}
                for from_uid, request in requests.items():
                    if not isinstance(request, dict):
                        continue
                    result[from_uid] = request
                return result

            requests = db.reference(f"users/{uid}/friend_requests").get() or {}
            return requests
        except Exception as e:
            print(f"Request fetch error: {e}")
            return {}

    @staticmethod
    def accept_friend_request(current_uid: str, requester_uid: str) -> dict:
        """Accept an incoming friend request."""
        try:
            if FirebaseManager()._demo_mode:
                if not hasattr(FirebaseManager, '_demo_users'):
                    return {"success": False, "message": "No users exist"}

                if requester_uid not in FirebaseManager._demo_users.get(current_uid, {}).get('friend_requests', {}):
                    return {"success": False, "message": "Request not found"}

                FirebaseManager._demo_users.setdefault(current_uid, {}).setdefault('friends', {})[requester_uid] = True
                FirebaseManager._demo_users.setdefault(requester_uid, {}).setdefault('friends', {})[current_uid] = True
                FirebaseManager._demo_users[current_uid].get('friend_requests', {}).pop(requester_uid, None)
                return {"success": True, "message": "Friend request accepted (Demo)"}

            request_ref = db.reference(f"users/{current_uid}/friend_requests/{requester_uid}")
            request_data = request_ref.get()
            if not request_data:
                return {"success": False, "message": "Request not found"}

            db.reference(f"users/{current_uid}/friends/{requester_uid}").set(True)
            db.reference(f"users/{requester_uid}/friends/{current_uid}").set(True)
            request_ref.delete()
            return {"success": True, "message": "Friend request accepted"}
        except Exception as e:
            print(f"Accept request error: {e}")
            return {"success": False, "message": str(e)}

    @staticmethod
    def decline_friend_request(current_uid: str, requester_uid: str) -> dict:
        """Decline an incoming friend request."""
        try:
            if FirebaseManager()._demo_mode:
                if hasattr(FirebaseManager, '_demo_users') and current_uid in FirebaseManager._demo_users:
                    FirebaseManager._demo_users[current_uid].get('friend_requests', {}).pop(requester_uid, None)
                return {"success": True, "message": "Friend request declined (Demo)"}

            db.reference(f"users/{current_uid}/friend_requests/{requester_uid}").delete()
            return {"success": True, "message": "Friend request declined"}
        except Exception as e:
            print(f"Decline request error: {e}")
            return {"success": False, "message": str(e)}

    @staticmethod
    def mark_messages_as_read(sender_uid: str, receiver_uid: str) -> None:
        """Mark messages from sender_uid to receiver_uid as read."""
        try:
            chat_id = "-".join(sorted([sender_uid, receiver_uid]))

            if FirebaseManager()._demo_mode:
                if not hasattr(FirebaseManager, '_demo_messages') or chat_id not in FirebaseManager._demo_messages:
                    return

                for message in FirebaseManager._demo_messages[chat_id]:
                    if message.get("sender") == sender_uid and message.get("receiver") == receiver_uid:
                        message["read"] = True
                return

            ref = db.reference(f"messages/{chat_id}")
            messages = ref.get() or {}
            updates = {}

            for msg_id, msg_data in messages.items():
                if msg_data.get("sender") == sender_uid and msg_data.get("receiver") == receiver_uid and not msg_data.get("read"):
                    updates[f"{msg_id}/read"] = True

            if updates:
                ref.update(updates)
        except Exception as e:
            print(f"Mark read error: {e}")

    @staticmethod
    def get_friends(uid: str) -> dict:
        """Return the user's friend list (uid -> profile)"""
        try:
            if FirebaseManager()._demo_mode:
                if not hasattr(FirebaseManager, '_demo_users') or uid not in FirebaseManager._demo_users:
                    return {}

                friends = FirebaseManager._demo_users[uid].get('friends', {})
                result = {}
                for fuid in friends.keys():
                    user = FirebaseManager._demo_users.get(fuid)
                    if user:
                        result[fuid] = {"username": user.get('username', 'User'), "email": user.get('email', '')}
                return result

            ref = db.reference(f"users/{uid}/friends")
            friends = ref.get()
            if not friends:
                return {}

            result = {}
            for fuid in friends.keys():
                info = db.reference(f"users/{fuid}").get()
                if info:
                    result[fuid] = {"username": info.get('username', 'User'), "email": info.get('email', '')}
            return result
        except Exception as e:
            print(f"Error fetching friends: {e}")
            return {}

    # ==================== Messaging ====================

    @staticmethod
    def send_message(sender_uid: str, receiver_uid: str, message: str) -> bool:
        """Send a message"""
        try:
            if FirebaseManager()._demo_mode:
                if not hasattr(FirebaseManager, '_demo_messages'):
                    FirebaseManager._demo_messages = {}
                chat_id = "-".join(sorted([sender_uid, receiver_uid]))
                if chat_id not in FirebaseManager._demo_messages:
                    FirebaseManager._demo_messages[chat_id] = []
                FirebaseManager._demo_messages[chat_id].append({
                    "sender": sender_uid,
                    "receiver": receiver_uid,
                    "text": message,
                    "timestamp": datetime.now().isoformat(),
                    "read": False
                })
                return True
            
            chat_id = "-".join(sorted([sender_uid, receiver_uid]))
            timestamp = datetime.now().isoformat()

            ref = db.reference(f"messages/{chat_id}")
            ref.push({
                "sender": sender_uid,
                "receiver": receiver_uid,
                "text": message,
                "timestamp": timestamp,
                "read": False
            })
            return True
        except Exception as e:
            print(f"Message send error: {e}")
            return False

    @staticmethod
    def get_chat_messages(uid1: str, uid2: str) -> list:
        """Get messages between two users"""
        try:
            if FirebaseManager()._demo_mode:
                chat_id = "-".join(sorted([uid1, uid2]))
                if hasattr(FirebaseManager, '_demo_messages') and chat_id in FirebaseManager._demo_messages:
                    return FirebaseManager._demo_messages[chat_id]
                return []
            
            chat_id = "-".join(sorted([uid1, uid2]))
            ref = db.reference(f"messages/{chat_id}")
            messages = ref.get()

            if not messages:
                return []

            # Mesajları listele ve sırala
            msg_list = []
            for msg_id, msg_data in messages.items():
                msg_data["id"] = msg_id
                msg_list.append(msg_data)

            # Timestamp'e göre sırala
            msg_list.sort(key=lambda x: x.get("timestamp", ""))
            return msg_list
        except Exception as e:
            print(f"Message fetch error: {e}")
            return []

    @staticmethod
    def get_recent_chats(uid: str) -> dict:
        """Get recent chats for a user"""
        try:
            def _preview_text(raw_text):
                text = raw_text if isinstance(raw_text, str) else str(raw_text or "")
                if text.startswith("dbenc:v1:") or text.startswith("e2e:v1:"):
                    return "[Encrypted message]"
                return text

            if FirebaseManager()._demo_mode:
                chats = {}
                if hasattr(FirebaseManager, '_demo_messages'):
                    for chat_id, messages in FirebaseManager._demo_messages.items():
                        if uid in chat_id:
                            msg_list = sorted(messages, key=lambda x: x.get("timestamp", ""), reverse=True)
                            last_msg = msg_list[0] if msg_list else {}
                            other_uid = chat_id.replace(uid, "").replace("-", "")
                            chats[other_uid] = {
                                "last_message": _preview_text(last_msg.get("text", "")),
                                "timestamp": last_msg.get("timestamp", ""),
                                "unread": sum(1 for m in msg_list if not m.get("read") and m.get("receiver") == uid)
                            }
                return chats
            
            ref = db.reference("messages")
            all_messages = ref.get()

            if not all_messages:
                return {}

            # Bu kullanıcının konuştuğu kişileri bul
            chats = {}
            for chat_id, messages in all_messages.items():
                if uid in chat_id:
                    # Son mesajı al
                    msg_list = list(messages.values())
                    msg_list.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                    last_msg = msg_list[0] if msg_list else {}

                    # Diğer kişinin UID'sini bulun
                    other_uid = chat_id.replace(uid, "").replace("-", "")

                    chats[other_uid] = {
                        "last_message": _preview_text(last_msg.get("text", "")),
                        "timestamp": last_msg.get("timestamp", ""),
                        "unread": sum(1 for m in msg_list if not m.get("read") and m.get("receiver") == uid)
                    }

            return chats
        except Exception as e:
            print(f"Recent chats error: {e}")
            return {}


# Singleton instance
firebase = FirebaseManager()
