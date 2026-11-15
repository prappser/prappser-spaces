package user

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

type failingPaymentStore struct {
	bindingTestRepo
}

func (failingPaymentStore) GetPaymentMethods(string) ([]byte, error) {
	return nil, errors.New("connection reset")
}

func (failingPaymentStore) UpdatePaymentMethods(string, []byte) error { return nil }

func TestGetProfile_ShouldReturn500WhenPaymentMethodsLookupFails(t *testing.T) {
	// given
	ue := UserEndpoints{userRepository: &failingPaymentStore{}}
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", &User{PublicKey: "acct", Username: "alice"})

	// when
	ue.GetProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
}
