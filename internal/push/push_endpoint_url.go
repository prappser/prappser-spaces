package push

import (
	"errors"
	"net/url"
)

var ErrInvalidEndpoint = errors.New("endpoint must be an https URL without credentials")

func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return ErrInvalidEndpoint
	}
	return nil
}
