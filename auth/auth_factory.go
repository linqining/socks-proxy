package auth

import (
	"errors"
	"io"
)

// An AuthMethod represents a SOCKS authentication method.
type AuthMethod int

const (
	AuthMethodNotRequired      AuthMethod = 0x00 // no authentication required
	AuthMethodGSSAPI           AuthMethod = 0x01
	AuthMethodUsernamePassword AuthMethod = 0x02 // use username/password

	//0x03-0x7f IANA分配
	//0x80-0xfe 私有方法
	AuthMethodNoAcceptableMethods AuthMethod = 0xff // no acceptable authentication methods
)

var NoAcceptableMethod = errors.New("No Acceptable Methods")

type Authenticator interface {
	Authenticate(io.Writer, io.Reader) error
}

func NewAuthenticator(authType AuthMethod) (Authenticator, error) {
	switch authType {
	case AuthMethodNotRequired:
		return &noAuth{}, nil
	case AuthMethodGSSAPI:
		return &gssapiAuth{}, nil
	case AuthMethodUsernamePassword:
		return passAuthInstance, nil
	case AuthMethodNoAcceptableMethods:
		return nil, NoAcceptableMethod
	}
	return nil, NoAcceptableMethod
}
