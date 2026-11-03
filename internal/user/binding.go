package user

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	bindingTyp     = "prappser-binding"
	bindingSkewSec = 300
)

var ErrInvalidBinding = errors.New("invalid binding")

var ErrDeviceRowConflict = errors.New("device key already registered to another account or revoked")

type BindingRequiredError struct {
	Binding string
}

func (e *BindingRequiredError) Error() string { return "binding required" }

type bindingClaims struct {
	Issuer   string
	Subject  string
	URL      string
	IssuedAt int64
}

func verifyBinding(signed, accountKey string, now time.Time) (*bindingClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		return nil, ErrInvalidBinding
	}
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidBinding
	}

	var c bindingClaims
	if typ, _ := mapClaims["typ"].(string); typ != bindingTyp {
		return nil, ErrInvalidBinding
	}
	c.Issuer, _ = mapClaims["iss"].(string)
	c.Subject, _ = mapClaims["sub"].(string)
	c.URL, _ = mapClaims["url"].(string)
	if iat, ok := mapClaims["iat"].(float64); ok {
		c.IssuedAt = int64(iat)
	}

	if c.Issuer != accountKey || !isPublicKey(c.Issuer) || !isCanonicalPublicKey(c.Subject) {
		return nil, ErrInvalidBinding
	}
	issuerKey, _ := base64.StdEncoding.DecodeString(c.Issuer)

	verified, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrInvalidBinding
		}
		return ed25519.PublicKey(issuerKey), nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !verified.Valid {
		return nil, ErrInvalidBinding
	}

	if c.IssuedAt <= 0 || c.IssuedAt > now.Unix()+bindingSkewSec {
		return nil, ErrInvalidBinding
	}
	return &c, nil
}

type Bindings struct {
	repo           UserRepository
	spacePublicKey string
	Disconnect     func(account, device string)
}

func NewBindings(repo UserRepository, spacePublicKey string) *Bindings {
	return &Bindings{repo: repo, spacePublicKey: spacePublicKey}
}

func (b *Bindings) Accept(account, jws string, c *bindingClaims) (storedJWS, storedSub string, err error) {
	storedJWS, storedSub, updated, err := b.repo.AcceptBinding(account, jws, c.IssuedAt, c.Subject, b.spacePublicKey)
	if err != nil {
		return "", "", err
	}
	// A stored change disconnects the account's sockets (device "" = all).
	if updated && b.Disconnect != nil {
		b.Disconnect(account, "")
	}
	return storedJWS, storedSub, nil
}

func (b *Bindings) IsIdentitySpace(acct *User) (bool, error) {
	blob, _, err := b.repo.GetEscrow(acct.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to look up escrow: %w", err)
	}
	return blob != "" && (acct.BindingSub == "" || acct.BindingSub == b.spacePublicKey), nil
}

func (b *Bindings) RosterAllowed(acct *User, d *Device) (bool, error) {
	if d == nil || d.UserPublicKey != acct.PublicKey || d.RevokedAt != nil {
		return false, nil
	}
	if d.DevicePublicKey == acct.PublicKey || acct.BindingIat == 0 {
		return true, nil
	}
	return b.IsIdentitySpace(acct)
}

func (b *Bindings) VerifyAdmission(accountKey, devicePublicKey, binding, assertion string, now time.Time) (*bindingClaims, error) {
	c, err := verifyBinding(binding, accountKey, now)
	if err != nil {
		return nil, err
	}
	a, err := VerifyAssertion(assertion, b.spacePublicKey, devicePublicKey, c.Subject, now)
	if err != nil {
		return nil, err
	}
	if a.UserID != accountKey {
		return nil, ErrInvalidAssertion
	}
	return c, nil
}

func (b *Bindings) Admit(account, devicePublicKey, binding string, c *bindingClaims, deviceName *string, now time.Time) error {
	storedJWS, storedSub, err := b.Accept(account, binding, c)
	if err != nil {
		return err
	}
	if storedSub != c.Subject {
		return &BindingRequiredError{Binding: storedJWS}
	}

	d, err := b.repo.GetDevice(devicePublicKey)
	if err != nil {
		return fmt.Errorf("failed to look up device: %w", err)
	}
	if d != nil {
		if d.UserPublicKey != account || d.RevokedAt != nil {
			return ErrDeviceRowConflict
		}
		return nil
	}
	if err := b.repo.EnsureDevice(devicePublicKey, account, deviceName, now.Unix()); err != nil {
		return fmt.Errorf("failed to ensure device: %w", err)
	}
	return nil
}

func isCanonicalPublicKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == ed25519.PublicKeySize && base64.StdEncoding.EncodeToString(b) == s
}
