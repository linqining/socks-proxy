package main

import (
	"bytes"
	"log"
	"tcpproxy/auth"
	"testing"
)

type testWriter struct {
}

func (tw *testWriter) Write(p []byte) (n int, err error) {
	log.Println(string(p))
	return 0, nil
}

func Test_authenticate(t *testing.T) {
	r := bytes.NewReader([]byte{Version5, 2, uint8(auth.AuthMethodNotRequired), uint8(auth.AuthMethodUsernamePassword)})
	s, _ := NewServer(ServerConfig{})

	err := s.authenticate(&testWriter{}, r)
	if err != nil {
		t.Fatal(err)
	}
}
