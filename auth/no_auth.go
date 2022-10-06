package auth

import "io"

type noAuth struct{}

func (a *noAuth) Authenticate(writer io.Writer, reader io.Reader) error {
	return nil
}
