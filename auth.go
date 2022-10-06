package main

import (
	"io"
)

type AuthError struct {
	msg string
}

func (ae *AuthError) Error() string {
	return "Authentication ERR: " + ae.msg
}

func NewAuthError(msg string) error {
	return &AuthError{msg: msg}
}

type ProtocolErr struct {
	msg string
}

func (pe *ProtocolErr) Error() string {
	return "Protocol Err: " + pe.msg
}

func NewProtocolErr(msg string) error {
	return &ProtocolErr{msg: msg}
}

func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) error {
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 2); err != nil {
		return err
	}
	if header[0] != Version5 {
		return NewProtocolErr("unexpected protocol version")
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(bufConn, methods, numMethods)
	if err != nil {
		return NewProtocolErr("methods not match")
	}

	authMethod, authenticator := s.ac.selectMethod(methods)

	_, err = conn.Write([]byte{Version5, uint8(authMethod)})
	if err != nil {
		return err
	}
	return authenticator.Authenticate(conn, bufConn)
}
