package auth

import (
	"errors"
	"fmt"
	"io"
)

const (
	passAuthVersion = 0x01
)
const (
	authSuccess = iota
	authFailure
)

var passAuthInstance *passAuth

func init() {
	passAuthInstance = &passAuth{
		repo: newMemoryRepo(),
	}
}

type credentialRepo interface {
	Get(string) (string, error)
	Set(string, string)
	Delete(string)
}

type memoryRepo struct {
	storage map[string]string
}

func newMemoryRepo() *memoryRepo {
	return &memoryRepo{
		storage: make(map[string]string),
	}
}

func (m memoryRepo) Get(s string) (string, error) {
	passwd, ok := m.storage[s]
	if !ok {
		return "", errors.New("user not exists")
	}
	return passwd, nil
}

func (m memoryRepo) Set(s string, s2 string) {
	m.storage[s] = s2
}

func (m memoryRepo) Delete(s string) {
	delete(m.storage, s)
}

type passAuth struct {
	repo credentialRepo
}

// password sub-negotiation documentation
// https://www.rfc-editor.org/rfc/rfc1929
func (a *passAuth) Authenticate(writer io.Writer, reader io.Reader) error {
	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return err
	}

	// Ensure we are compatible
	if header[0] != passAuthVersion {
		return fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return err
	}

	// Verify the password
	if a.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{passAuthVersion, authSuccess}); err != nil {
			return err
		}
	} else {
		if _, err := writer.Write([]byte{passAuthVersion, authFailure}); err != nil {
			return err
		}
		return errors.New("user auth failed")
	}
	return nil
}

func (a *passAuth) Valid(userName, password string) bool {
	passwd, err := a.repo.Get(userName)
	if err != nil {
		return false
	}
	return passwd == password
}
