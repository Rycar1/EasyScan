package shiroprobe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
)

// javaSerializationMagic is the leading bytes of any Java object stream. A
// decrypted rememberMe cookie that begins with this magic was almost certainly
// decrypted with the correct key.
var javaSerializationMagic = []byte{0xAC, 0xED, 0x00, 0x05}

// decryptResult describes a successful rememberMe decryption.
type decryptResult struct {
	mode string
	key  string
}

// tryDecryptCookie attempts to decrypt a base64 rememberMe cookie value with a
// base64 AES key. Shiro prepends a 16-byte IV to the ciphertext. Both AES-GCM
// (authenticated, a definitive oracle) and AES-CBC (padding + Java magic check)
// are attempted. It returns the mode when the key is correct.
func tryDecryptCookie(cookieB64, keyB64 string) (decryptResult, bool) {
	keyBytes, err := decodeKey(keyB64)
	if err != nil || !validAESKeyLen(len(keyBytes)) {
		return decryptResult{}, false
	}
	data, err := base64.StdEncoding.DecodeString(cookieB64)
	if err != nil || len(data) <= 16 {
		return decryptResult{}, false
	}
	iv := data[:16]
	ciphertext := data[16:]
	if len(ciphertext) == 0 {
		return decryptResult{}, false
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return decryptResult{}, false
	}

	// AES-GCM: a successful Open verifies the authentication tag and is a
	// definitive signal that the key is correct. Shiro uses a 16-byte nonce;
	// some deployments use 12, so both are attempted.
	for _, nonceSize := range []int{16, 12} {
		if len(iv) < nonceSize {
			continue
		}
		gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
		if err != nil {
			continue
		}
		if _, err := gcm.Open(nil, iv[:nonceSize], append(ciphertext, nil...), nil); err == nil {
			return decryptResult{mode: "AES-GCM", key: keyB64}, true
		}
	}

	// AES-CBC: no authentication tag, so require valid PKCS#7 padding and a
	// Java serialization header to reduce false positives.
	if len(ciphertext)%aes.BlockSize == 0 {
		plaintext := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
		if pkcs7Valid(plaintext) && hasJavaMagic(plaintext) {
			return decryptResult{mode: "AES-CBC", key: keyB64}, true
		}
	}
	return decryptResult{}, false
}

func decodeKey(keyB64 string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(keyB64); err == nil {
		return b, nil
	}
	trimmed := strings.TrimRight(keyB64, "=")
	return base64.RawStdEncoding.DecodeString(trimmed)
}

func validAESKeyLen(n int) bool { return n == 16 || n == 24 || n == 32 }

func pkcs7Valid(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(data) {
		return false
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return false
		}
	}
	return true
}

func hasJavaMagic(data []byte) bool {
	if len(data) < len(javaSerializationMagic) {
		return false
	}
	for i, b := range javaSerializationMagic {
		if data[i] != b {
			return false
		}
	}
	return true
}
