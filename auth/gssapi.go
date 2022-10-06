package auth

import "io"

type gssapiAuth struct {
}

func (a *gssapiAuth) Authenticate(writer io.Writer, reader io.Reader) error {
	return nil
}
