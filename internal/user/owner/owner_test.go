package owner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/prappser/prappser-spaces/internal/keys"
	"github.com/stretchr/testify/assert"
)

const testMasterPassword = "admin-password"

// buildJWE encrypts payload the same way the Flutter client does: a JWE with
// alg=dir, A256GCM, whose key is Argon2id(masterPassword, salt), and the salt
// carried (base64 std encoded) in a custom "salt" protected header.
func buildJWE(t *testing.T, payload []byte, masterPassword string, salt []byte) string {
	t.Helper()

	headers := jwe.NewHeaders()
	err := headers.Set(jweSaltHeaderParam, base64.StdEncoding.EncodeToString(salt))
	assert.NoError(t, err)

	key := keys.DeriveKey(masterPassword, salt)
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), key), jwe.WithProtectedHeaders(headers))
	assert.NoError(t, err)

	return string(encrypted)
}

func randomSalt(t *testing.T) []byte {
	t.Helper()
	salt := make([]byte, keys.SaltSize)
	_, err := rand.Read(salt)
	assert.NoError(t, err)
	return salt
}

func TestDecryptJWE_ShouldDecryptValidly(t *testing.T) {
	// given
	salt := randomSalt(t)
	payload := []byte(`{"jws":"some-jws-token"}`)
	encryptedJWE := buildJWE(t, payload, testMasterPassword, salt)

	// when
	actualClaims, err := DecryptJWE(encryptedJWE, testMasterPassword)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, actualClaims)
	assert.Equal(t, "some-jws-token", actualClaims.JWS)
}

func TestDecryptJWE_ShouldNotDecryptValidlyIfWrongPasswordUsed(t *testing.T) {
	// given
	salt := randomSalt(t)
	payload := []byte(`{"jws":"some-jws-token"}`)
	encryptedJWE := buildJWE(t, payload, testMasterPassword, salt)

	// when
	actualClaims, err := DecryptJWE(encryptedJWE, "wrong-password")

	// then
	assert.Error(t, err)
	assert.Nil(t, actualClaims)
}

func TestDecryptJWE_ShouldFailWhenSaltHeaderMissing(t *testing.T) {
	// given - encrypt without setting the "salt" protected header
	salt := randomSalt(t)
	key := keys.DeriveKey(testMasterPassword, salt)
	payload := []byte(`{"jws":"some-jws-token"}`)
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), key))
	assert.NoError(t, err)

	// when
	actualClaims, err := DecryptJWE(string(encrypted), testMasterPassword)

	// then
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "salt")
	assert.Nil(t, actualClaims)
}

func TestDecryptJWE_ShouldFailWhenSaltHasBadLength(t *testing.T) {
	// given - salt header decodes to the wrong number of bytes
	badSalt := []byte("too-short")
	headers := jwe.NewHeaders()
	err := headers.Set(jweSaltHeaderParam, base64.StdEncoding.EncodeToString(badSalt))
	assert.NoError(t, err)

	// Key derivation must still use a 32-byte salt for the AES key itself,
	// so pad with a real salt only for producing a decryptable ciphertext -
	// the assertion here is about DecryptJWE rejecting the header, not the
	// key derivation, so any key works as long as decryption never succeeds.
	key := keys.DeriveKey(testMasterPassword, randomSalt(t))
	payload := []byte(`{"jws":"some-jws-token"}`)
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), key), jwe.WithProtectedHeaders(headers))
	assert.NoError(t, err)

	// when
	actualClaims, err := DecryptJWE(string(encrypted), testMasterPassword)

	// then
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "salt length")
	assert.Nil(t, actualClaims)
}

// Helper to generate Ed25519 signed JWT for testing
func generateEd25519JWT(privateKey ed25519.PrivateKey, publicKeyBase64 string, username string, iat int64) string {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"publicKey": publicKeyBase64,
		"username":  username,
		"iat":       iat,
	})
	tokenString, _ := token.SignedString(privateKey)
	return tokenString
}

func TestVerifyJWS_ShouldVerifyValidly(t *testing.T) {
	// given - generate Ed25519 keypair
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	issuedAt := time.Now().Unix()

	// Create JWT signed with EdDSA
	signedJWT := generateEd25519JWT(privateKey, publicKeyBase64, "testuser", issuedAt)

	SetTimeNowFunc(func() time.Time {
		return time.Unix(issuedAt+5, 0) // 5 seconds after issuedAt
	})

	// when
	actualClaims, err := VerifyJWS(signedJWT, 10)

	// then
	assert.NoError(t, err)
	assert.Equal(t, publicKeyBase64, actualClaims.PublicKey)
	assert.Equal(t, "testuser", actualClaims.Username)
	assert.Equal(t, issuedAt, actualClaims.IssuedAt)
}

func TestVerifyJWS_ShouldNotVerifyWhenExpired(t *testing.T) {
	// given - generate Ed25519 keypair
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	issuedAt := time.Now().Unix()

	// Create JWT signed with EdDSA
	signedJWT := generateEd25519JWT(privateKey, publicKeyBase64, "testuser", issuedAt)

	SetTimeNowFunc(func() time.Time {
		return time.Unix(issuedAt+20, 0) // 20 seconds after issuedAt (expired with 10s TTL)
	})

	// when
	actualClaims, err := VerifyJWS(signedJWT, 10)

	// then
	assert.Error(t, err)
	assert.Nil(t, actualClaims)
}

func TestVerifyJWS_ShouldNotVerifyWithWrongPublicKey(t *testing.T) {
	// given - generate two different Ed25519 keypairs
	_, privateKey1, _ := ed25519.GenerateKey(nil)
	publicKey2, _, _ := ed25519.GenerateKey(nil)
	publicKeyBase64Wrong := base64.StdEncoding.EncodeToString(publicKey2) // Wrong public key
	issuedAt := time.Now().Unix()

	// Sign with privateKey1 but claim to be publicKey2
	signedJWT := generateEd25519JWT(privateKey1, publicKeyBase64Wrong, "testuser", issuedAt)

	SetTimeNowFunc(func() time.Time {
		return time.Unix(issuedAt+5, 0)
	})

	// when
	actualClaims, err := VerifyJWS(signedJWT, 10)

	// then
	assert.Error(t, err)
	assert.Nil(t, actualClaims)
}

func TestExtractJWEFromAuthorizationHeader_ShouldExtractValidly(t *testing.T) {
	// given
	authHeader := "Bearer eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..914U_1q7qRgmah7-.4MqUDKtqo1CH2Y2JcFdsrelwHBBFOK0FJKXGqjwKCXo1XVgm0CuHDh6sBaDKDuDjtYtNW8Mrx_n7NPhWpchbL-ejwI8LWcS4VTBM0sVqMxgzNTckW2vbEXKTnTQlpF_-MIfLFANr5EskLFuUIpeZTBN_KZ5bqeMn5Uwjth0CXrQ6ec_2nSRnK7yMIShCRTjSiOBUhrT-d0tHQjbKXMpqyQ4GQYVwQ5g-wRT7vsOpBBZmw5YpuSeL32ZD7Ltl_bnKAWkis55Uj2nu6oCZN-chqMDDetHjuHYGRSf4GbrGB2mJ_T7EzUjyHVrtAUS6ZYaLTglcrwH1TZ3dIv0oeexDECfrJjvAP_VcNXmgP5OB6_kS937wquuoNgnjTNnMvL9QGNfIbUW4tL7QcGyjJ4ynQcheWAIUPu9Y73Se-9ecDnAr_Tq83EKWUFFyhQb_lTxULtRQ5GqrC-vYeIXy63BsJqSUwr1hPNXP6Pm3_IJzwK4HtjyZWwQzxH3gBogDhP39MB5eRCkUPHaMyLyGZ1PYEUlrXabZp0BsxIDqK6sWlNj0JP63diHb8INLR7ysGD2SMOzsuxfhJtzCnK2SHK5hNOSXpcDYd1mWcKz1lh_iCPk--AYqGX27r2Doa06jFDqeMt31zrulDbwwQgW-_wKtY6VRk-Yb-M8_Dpy-qZFt1GzTObYCa9ovIFqDbt5hUPa_e2EYBesGoDHG4GXz_e4d4ACObJSSxCBt0s9ywgviw-7Oc6aRy6z8u_bqrY315kbQcRI4mFLgWPHgHDZOtEbJDxk-uXdg0DlrecMh2VP1Gfn3JUVCy3TUlc_f-grnQfUWgMrcI0c1jx49rzoVBx7sg0o1jzwQyozYRwKWekS2r-Xi3z1218yfwFNYImaaJgvjbooyvb_gMD3H2Gd6nktLS9hEpaUvJ4rhNiFNgsYuBSg4Pv6u9DPsZyeUDUcUBhX_oh931IVaZj81ZPkfSLuiHWwpNAkhA6KAqn0xl8MSBOMakcY6hZfDSGQwdBBIaCGq_ryRRTDP26Y8LeOt0Kny5qP-b7RcHsiR0gfvrrfqWBE9u9jiMvR5mOnGUKHegSjQpyrSbQO-y-GrX5a_r4_fPWNzyWHXhq88-KfqEegdSxEU4TR4ji2hD1ofhvCQFXstjT6B96YyLxN9855yUzZCjCSFbJ2MVpAnIoVlTiLtLBRTSqkfOI58S5XLw_Bgx98C6cD13XuTs30VnKf28_bDxkyuGqezrTVBjRSSjmKma8KzOpD_97ZO9EZkr2AT5MerN4-_gCbhxthL19HB-RnPHhMHf04KTLmfqojfLeljOobSRMpPkA.X-BZvdm7Nw48ckMrX2cWnA"

	// when
	jwe, err := ExtractJWEFromAuthorizationHeader(authHeader)

	// then
	assert.NoError(t, err)
	assert.NotEmpty(t, jwe)
	assert.Contains(t, jwe, "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0")
}

func TestExtractJWEFromAuthorizationHeader_ShouldFailWithInvalidFormat(t *testing.T) {
	// given
	authHeader := "InvalidFormat"

	// when
	jwe, err := ExtractJWEFromAuthorizationHeader(authHeader)

	// then
	assert.Error(t, err)
	assert.Empty(t, jwe)
}
