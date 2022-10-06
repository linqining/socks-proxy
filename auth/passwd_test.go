package auth

import (
	"bytes"
	"log"
	"testing"
)

type testWriter struct {
}

func (tw *testWriter) Write(p []byte) (n int, err error) {
	log.Println(p)
	return 0, nil
}

func Test_passAuth_Authenticate(t *testing.T) {
	userName, testPass := "testUser", "testPasswd"
	passAuthInstance.repo.Set(userName, testPass)
	data := []byte{passAuthVersion, uint8(len(userName))}
	data = append(data, []byte(userName)...)
	data = append(data, uint8(len(testPass)))
	//failedPass := "TestPasswd"
	data = append(data, []byte(testPass)...)
	r := bytes.NewReader(data)
	passAuthInstance.Authenticate(&testWriter{}, r)
}
