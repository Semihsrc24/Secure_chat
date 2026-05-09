## End-to-End Encryption (E2E) - Implementasyon Kılavuzu

### Genel Bakış

Sistem Fernet şifrelemesinden **RSA tabanlı End-to-End Encryption**'a migre edilmiştir. Bu kılavuz yeni E2E sisteminin nasıl çalıştığını açıklar.

---

## Mimarı

### 1. **Key Pair Oluşturma**
Her kullanıcı giriş yaptığında:
- **RSA-2048 anahtar çifti** otomatik olarak oluşturulur
- Anahtarlar `keys/` dizinine kaydedilir:
  - `keys/{user_id}_private.pem` - Özel anahtar (güvenli tutulur)
  - `keys/{user_id}_public.pem` - Genel anahtar (paylaşılır)

### 2. **Public Key Exchange**
- Kullanıcının public key'i otomatik olarak Firebase'e yüklenir
- Diğer kullanıcılar mesaj göndermek için alıcının public key'ini indirir
- Public key'ler cache'lenir (performans için)

### 3. **Mesaj Şifreleme**
```
Alice → Bob:
1. Alice, Bob'un public key'ini alır
2. Mesajı Bob'un public key'i ile şifreler: OAEP+SHA256
3. Şifrelenmiş mesaj: "e2e:v1:{base64_ciphertext}"
4. Mesaj Firebase'e gönderilir (sunucu okunamaz)
```

### 4. **Mesaj Deşifreleme**
```
Bob mesajı alır:
1. Şifrelenmiş mesajı "e2e:v1:" ön ekinden tanır
2. Kendi private key'i ile deşifreler (yalnızca Bob deşifre edebilir)
3. Orijinal mesaj görüntülenir
```

---

## Dosya Yapısı

```
project/
├── e2e_encryption.py          # E2E şifreleme modülü
├── secure_chat.py              # Güncellenmiş istemci (E2E entegrasyonlu)
├── firebase_config.py           # Firebase config (public_key alanı eklendi)
├── keys/                       # Kullanıcı anahtarları (otomatik oluşturulur)
│   ├── {user_id}_private.pem
│   └── {user_id}_public.pem
└── E2E_ENCRYPTION.md           # Bu dosya
```

---

## API Referansı

### `E2EEncryption` Sınıfı

#### Başlatma
```python
from e2e_encryption import E2EEncryption

# Kullanıcı için E2E encrybir oluştur
e2e = E2EEncryption(user_id="user123", keys_dir="keys")
```

#### Public Key'i Alma
```python
public_key_pem = e2e.get_public_key_pem()
# Firebase'e yükleme için PEM formatında string
```

#### Mesaj Şifreleme
```python
# Alıcının public key'i
recipient_public_key = e2e.get_cached_public_key("recipient_uid")
if not recipient_public_key:
    # Public key'i Firebase'den yükle
    public_key_pem = fetch_public_key_from_firebase("recipient_uid")
    e2e.cache_public_key("recipient_uid", public_key_pem)
    recipient_public_key = e2e.get_cached_public_key("recipient_uid")

# Mesajı şifrele
encrypted = e2e.encrypt_message("Merhaba!", recipient_public_key)
# Sonuç: "e2e:v1:{base64_encrypted_text}"
```

#### Mesaj Deşifreleme
```python
# Şifrelenmiş mesaj
encrypted_msg = "e2e:v1:{base64_encrypted_text}"

# Deşifrele (private key ile)
plaintext = e2e.decrypt_message(encrypted_msg)
```

---

## ChatWindow İntegrasyonu

### Otomatik İşlemler

1. **Giriş Sırasında**
   ```python
   self.e2e = E2EEncryption(uid)  # Anahtar çifti oluşturulur/yüklenir
   ```

2. **Profil Yüklemesi**
   - Public key otomatik olarak Firebase'e yüklenir
   - Geri kalan public key'ler cache'lenir

3. **Mesaj Gönderme**
   ```python
   to_send = self._encrypt_message_e2e(message, recipient_uid)
   # Otomatik olarak:
   # - Alıcının public key'ini alır
   # - Mesajı şifreler
   # - Firebase'e gönderir
   ```

4. **Mesaj Alma**
   ```python
   display_text = self._decrypt_message_e2e(encrypted_message)
   # Otomatik olarak:
   # - Şifrelenmiş mesajı deşifreler (private key ile)
   # - Metni görüntüler
   ```

---

## Güvenlik Özellikleri

### ✅ Sağlanan Koruma

1. **End-to-End Encryption**: 
   - Sunucu mesaj içeriğini göremez
   - Yalnızca gönderici ve alıcı okuabilir

2. **RSA-2048 Anahtarlar**:
   - Endüstri standardı şifreleme güvenliği
   - 2048-bit anahtar boyutu

3. **OAEP Padding**:
   - SHA256 ile secure padding
   - Ek güvenlik katmanı

4. **Private Key Güvenliği**:
   - Anahtarlar local dosyada saklanır
   - Şifreli olmayarak kaydedilir (geliştirme için)
   - Üretimde: key koruması ekleyin

### ⚠️ Sınırlamalar

1. **Public Key Yönetimi**:
   - Sunucu public key'leri depolayabilir
   - Public key'ler güvenlidir (şifreleme değil)
   
2. **Key Bozulması**:
   - Private key kaybolursa, eski mesajlar deşifre edilemez
   - Backup stratejisi önerilir

3. **Üretim Ortamı İçin**:
   - Private key'leri şifrele (PasswordBased Encryption)
   - HSM veya key vault kullan
   - Secure key derivation kullan

---

## Üretim Önerileri

### 1. Private Key Koruması
```python
# Private key'i password ile şifrele
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

encryption_algorithm = BestAvailableEncryption(password)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=encryption_algorithm
)
```

### 2. Public Key Verification
```python
# Sunucudan public key indirilirken doğrulama:
# - Certificate pinning
# - Signature verification
# - Trusted public key registry
```

### 3. Key Rotation
```python
# Periyodik key rotasyonu implemente et:
def rotate_keys(user_id):
    e2e = E2EEncryption(user_id)
    new_e2e = E2EEncryption(user_id + "_new")
    # Eski mesajları deşifrele
    # Yeni key pair ile yapılandır
```

### 4. Auditing
```python
# Şifreleme işlemlerini logla:
# - Key oluşturma
# - Public key exchange
# - Mesaj şifreleme/deşifreleme başarı/başarısızlık
```

---

## Troubleshooting

### "E2E message could not be decrypted"
**Nedeni**: Private key eksik veya uyumsuz
**Çözüm**: 
- Private key dosyasının varlığını kontrol et: `keys/{user_id}_private.pem`
- Başka bir cihazdan giriş yaptıysa, key senkronizasyonu yapın

### "No public key for {user_id}"
**Nedeni**: Alıcının public key'i Firebase'de yok
**Çözüm**:
- Alıcı kullanıcı en az bir kez giriş yaptı mı?
- Firebase'de public_key alanı var mı? (migration kontrol et)

### "Failed to initialize encryption"
**Nedeni**: keys/ dizini oluşturulamadı veya dosya yazma hatası
**Çözüm**:
- keys/ dizini var mı?
- Uygulama yazma izinleri var mı?

---

## Fernet Geriye Uyumluluk

Sistem **hybrid mode**'ta çalışır:

1. **E2E Mesajlar**: `e2e:v1:{...}` formatı
2. **Fernet Mesajlar**: `enc:v1:{...}` formatı (eski mesajlar)
3. **Otomatik Fallback**: E2E başarısız olursa Fernet kullanılır

```python
# secure_chat.py - Automatic fallback
to_send = self._encrypt_message_e2e(message, recipient_uid)
# Eğer E2E başarısız → Fernet fallback

display_text = self._decrypt_message_e2e(encrypted_message)
# E2E mesaj ise deşifre et
# Fernet mesaj ise Fernet ile deşifre et
```

---

## Yapılandırma

### Ortam Değişkenleri

Şu anda E2E şifreleme için değişken yok. İleride eklenebilir:

```bash
# .env dosyası
E2E_ENABLED=true
E2E_KEYS_DIR=keys
E2E_KEY_SIZE=2048
```

### Firebase Şeması

Public key Firebase'de user profile altında saklanır:

```json
{
  "users": {
    "user123": {
      "username": "alice",
      "email": "alice@example.com",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "tag": "alice#1234",
      "...": "other fields"
    }
  }
}
```

---

## Gelecek İyileştirmeler

- [ ] Perfect Forward Secrecy (PFS) - Sesyon anahtarları
- [ ] Message Authentication Code (MAC) - Temper detection
- [ ] Key Derivation Functions - Daha güçlü key generation
- [ ] Signal Protocol benzeri - Forward & backward secrecy
- [ ] Multi-device support - Key senkronizasyonu
- [ ] E2E Group Encryption - Grup mesajları

---

## Referanslar

- [cryptography.io - RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
- [OAEP - Wikipedia](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
- [End-to-End Encryption - Signal Protocol](https://signal.org/docs/)

---

**Son güncelleme**: 2026-05-09  
**Versiyon**: E2E 1.0
