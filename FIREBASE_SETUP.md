"""
Firebase Kurulum ve Yapılandırma Rehberi
"""

# requirements.txt'e eklenecek paketler:
# firebase-admin==6.0.0
# requests==2.31.0
# PySide6==6.6.0 (zaten yüklü)

# ============================================
# FIREBASE KURULUM ADIMLARI
# ============================================

"""
1. FIREBASE PROJESİ OLUŞTURMA
   - https://console.firebase.google.com adresine gidin
   - Google hesabınızla giriş yapın
   - "Proje Oluştur"a tıklayın
   - Proje adı girin (örneğin: "WhatsApp-Chat")
   - İleri'ye tıklayın
   - Google Analytics'i etkinleştirin veya kapatın
   - Proje oluşturmayı tamamlayın

2. REALTIME DATABASE KURULUMU
   - Firebase Console'da sol tarafta "Realtime Database"'yi seçin
   - "Veritabanı Oluştur"a tıklayın
   - Konumu seçin (örn: Europe / europe-west1)
   - Güvenlik kurallarını seçin: "Test mode" (Geliştirme için)
   
   ! ÖNEMLİ: Test mode değiştirme (Production'a)
   Kurallar sekmesinde şunu yapıştırın:
   {
     "rules": {
       "users": {
         ".read": "auth != null",
         ".write": "auth != null"
       },
       "messages": {
         ".read": "auth != null",
         ".write": "auth != null"
       }
     }
   }

3. SERVICE ACCOUNT KEY İNDİRME
   - Firebase Console'da sağ üst köşeye tıklayın ⚙️
   - "Proje Ayarları"nı seçin
   - "Hizmet Hesapları" sekmesine gidin
   - "Yeni Özel Anahtar Oluştur"a tıklayın
   - JSON dosyası indirilecek
   - Dosyayı "serviceAccountKey.json" olarak proje klasörüne koyun

4. DATABASE URL BULMA
   - Firebase Console'da "Realtime Database"'ye gidin
   - URL'i kopyalayın (örn: https://myproject-abc123.firebaseio.com)
   - firebase_config.py'de DATABASE_URL'i güncelleyin

5. WEB API KEY BULMA (LOGIN için)
   - Proje Ayarları → Genel
   - "Web API Key"'i kopyalayın
   - firebase_config.py'de YOUR_WEB_API_KEY'i güncelleyin

6. PİPLE PAKET KURMA
   python -m pip install firebase-admin requests PySide6

7. UYGULAMAY ÇALIŞTIRMA
   python whatsapp_chat.py
"""

# ============================================
# firebase_config.py GÜNCELLEMESİ
# ============================================

"""
Aşağıdaki satırları firebase_config.py'de güncelleyin:

1. CREDENTIALS_PATH = "serviceAccountKey.json"
   (Dosya aynı klasörde olmalı)

2. DATABASE_URL = "https://YOUR_PROJECT.firebaseio.com"
   (https://console.firebase.google.com → Realtime Database → URL)

3. requests.post(...key=YOUR_WEB_API_KEY...) satırında:
   YOUR_WEB_API_KEY yerine gerçek API key'i koyun
   (Proje Ayarları → Genel → Web API Key)
"""

# ============================================
# VERITABANI YAPISI
# ============================================

"""
Veritabanında şu yapı oluşacak:

{
  "users": {
    "uid_1": {
      "email": "user1@example.com",
      "username": "User One",
      "created_at": "2024-01-01T10:00:00",
      "status": "online",
      "avatar": ""
    },
    "uid_2": {
      "email": "user2@example.com",
      "username": "User Two",
      "created_at": "2024-01-01T11:00:00",
      "status": "offline",
      "avatar": ""
    }
  },
  "messages": {
    "uid_1-uid_2": {
      "msg_1": {
        "sender": "uid_1",
        "receiver": "uid_2",
        "text": "Merhaba!",
        "timestamp": "2024-01-01T12:00:00",
        "read": false
      }
    }
  }
}
"""

# ============================================
# SORUN GİDERME
# ============================================

"""
❌ "serviceAccountKey.json bulunamadı"
   → Dosyayı Firebase Console'dan indirin ve proje klasörüne koyun

❌ "Database URL yanlış"
   → Firebase Console → Realtime Database → Ayarlar → URL'i kopyalayın

❌ "Web API Key invalid"
   → Proje Ayarları → Genel → Web API Key'i düzenleyin

❌ "Firestore database bulunamadı"
   → Realtime Database (Firestore değil) oluşturmalısınız

❌ Mesajlar kaydedilmiyor
   → Güvenlik Kurallarını kontrol edin (Test mode ise tamam)
   → Veritabanı URL'sinin doğru olduğundan emin olun
"""

print("""
✓ Firebase Kurulum Rehberi
Detaylı talimatlar için bu dosyayı okuyun!
""")
