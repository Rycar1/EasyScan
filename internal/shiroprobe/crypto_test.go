package shiroprobe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// javaLikePlaintext builds a plaintext that begins with the Java serialization
// magic so the CBC heuristic accepts it.
func javaLikePlaintext() []byte {
	data := append([]byte{}, javaSerializationMagic...)
	data = append(data, []byte("some-serialized-principal-data......")...)
	// Pad to a multiple of the AES block size with PKCS#7.
	pad := aes.BlockSize - len(data)%aes.BlockSize
	for i := 0; i < pad; i++ {
		data = append(data, byte(pad))
	}
	return data
}

func encryptCBC(t *testing.T, key, plaintext []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...))
}

func encryptGCM(t *testing.T, key, plaintext []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
}

func TestTryDecryptCookieCBC(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes
	keyB64 := base64.StdEncoding.EncodeToString(key)
	cookie := encryptCBC(t, key, javaLikePlaintext())

	result, ok := tryDecryptCookie(cookie, keyB64)
	if !ok {
		t.Fatalf("expected CBC decryption to succeed")
	}
	if result.mode != "AES-CBC" {
		t.Fatalf("expected mode AES-CBC, got %q", result.mode)
	}
	if result.key != keyB64 {
		t.Fatalf("expected key %q, got %q", keyB64, result.key)
	}
}

func TestTryDecryptCookieGCM(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes
	keyB64 := base64.StdEncoding.EncodeToString(key)
	cookie := encryptGCM(t, key, javaLikePlaintext())

	result, ok := tryDecryptCookie(cookie, keyB64)
	if !ok {
		t.Fatalf("expected GCM decryption to succeed")
	}
	if result.mode != "AES-GCM" {
		t.Fatalf("expected mode AES-GCM, got %q", result.mode)
	}
}

func TestTryDecryptCookieWrongKey(t *testing.T) {
	key := []byte("0123456789abcdef")
	cookie := encryptCBC(t, key, javaLikePlaintext())
	wrongKeyB64 := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))

	if _, ok := tryDecryptCookie(cookie, wrongKeyB64); ok {
		t.Fatalf("expected decryption with wrong key to fail")
	}
}

// TestBuiltinKeysAllDecodeToValidAES verifies every key in the expanded
// dictionary decodes to a valid AES key length (16, 24, or 32 bytes). Keys
// that fail to decode or have wrong lengths are silently ignored at runtime,
// but we catch them here to keep the dictionary clean.
func TestBuiltinKeysAllDecodeToValidAES(t *testing.T) {
	for _, keyB64 := range builtinKeys {
		keyBytes, err := decodeKey(keyB64)
		if err != nil {
			t.Errorf("key %q failed to decode: %v", keyB64, err)
			continue
		}
		if !validAESKeyLen(len(keyBytes)) {
			t.Errorf("key %q decoded to %d bytes, not a valid AES key length (16/24/32)", keyB64, len(keyBytes))
		}
	}
}

// TestBuiltinKeysNoDuplicates ensures the expanded dictionary has no duplicate
// entries that would waste decryption cycles.
func TestBuiltinKeysNoDuplicates(t *testing.T) {
	seen := make(map[string]struct{}, len(builtinKeys))
	for _, k := range builtinKeys {
		if _, exists := seen[k]; exists {
			t.Errorf("duplicate key in builtin dictionary: %q", k)
		}
		seen[k] = struct{}{}
	}
}

// TestBuiltinKeysExpandedCount verifies the dictionary has been expanded beyond
// the original 57 keys to improve coverage.
func TestBuiltinKeysExpandedCount(t *testing.T) {
	if len(builtinKeys) < 90 {
		t.Fatalf("expected expanded dictionary with 90+ keys, got %d", len(builtinKeys))
	}
}

func TestTryDecryptCookieInvalidInputs(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	tests := []struct {
		name   string
		cookie string
		key    string
	}{
		{"empty cookie", "", validKey},
		{"not base64 cookie", "!!!not-base64!!!", validKey},
		{"too short cookie", base64.StdEncoding.EncodeToString([]byte("short")), validKey},
		{"invalid key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123")), "not-a-key"},
		{"bad key length", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), base64.StdEncoding.EncodeToString([]byte("12345"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tryDecryptCookie(tt.cookie, tt.key); ok {
				t.Fatalf("expected decryption to fail for %s", tt.name)
			}
		})
	}
}
