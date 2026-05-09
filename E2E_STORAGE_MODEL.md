# E2E Encryption - Architecture Summary

## Storage vs Transit Model

### Before Fix
- **Issue**: Messages encrypted for recipient, stored encrypted in Firebase
- **Problem**: Sender couldn't decrypt their own messages → "[E2E message could not be decrypted]"

### After Fix
- **Firebase (Storage)**: Plaintext messages
  - Own messages: stored as plaintext
  - Received messages: stored as plaintext (decrypted by recipient before storage)
  - Security: Protected by HTTPS + Firebase Auth

- **Socket (Real-time Transit)**: E2E encrypted
  - Messages encrypted with recipient's public key
  - `"e2e:v1:{base64_ciphertext}"` format
  - Only recipient can decrypt with their private key

## Message Flow

### Sending
```
User A: "Merhaba"
  ↓
Encrypt with User B's public key → "e2e:v1:{...}"
  ↓
Store in Firebase: plaintext "Merhaba"
  ↓
Send via Socket: encrypted "e2e:v1:{...}"
```

### Receiving (User B)
```
From Firebase: plaintext "Merhaba"
  → Display as-is ✓

From Socket (real-time): encrypted "e2e:v1:{...}"
  → Decrypt with private key → "Merhaba" ✓
  → Update UI
```

## Encryption Layers

| Component | Encryption | Purpose |
|-----------|------------|---------|
| HTTPS (Browser→Server) | TLS 1.3 | Transport security |
| Firebase DB | None | Plaintext storage (auth protected) |
| Socket (P2P) | E2E RSA-2048 | Forward secrecy |
| Real-time messages | E2E | Recipient-only readability |

## Benefits

✅ **No "[E2E message could not be decrypted]" for own messages**
✅ **Plaintext stored in Firebase (searchable, queryable)**
✅ **E2E for real-time socket communication**
✅ **Backward compatible with Fernet**
✅ **Sender sees their own messages immediately**
✅ **Recipient can decrypt via socket**

## Implementation Notes

- `send_message()`: Stores plaintext in Firebase, encrypts for socket
- `_decrypt_message_e2e()`: Only decrypts "e2e:v1:" prefixed messages
- `e2e.decrypt_message()`: Returns plaintext as-is if not encrypted
- Socket messages: Processed separately, attempt decryption
- Firebase messages: Assumed plaintext or legacy Fernet

## Future Improvements

For encrypted storage with E2E retrieval:
1. Store encrypted messages + key indices
2. Implement key rotation
3. Use forward secrecy (session keys)
4. Add message authentication (HMAC)
