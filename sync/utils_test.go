package sync

import (
	"bytes"
	"testing"
)

func Test_randomRecordId(t *testing.T) {
	recordId := randomRecordId()
	if len(recordId) != 12 {
		t.Error("randomRecordId did not return 12 character string")
	}
}

func Test_paddedPlaintext(t *testing.T) {
	plaintext := []byte{42}
	expected := []byte{42, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}
	padded := paddedPlaintext(plaintext, 16)
	if !bytes.Equal(expected, padded) {
		t.Error("Bad padding: ", padded)
	}
}

func Test_paddedPlaintextFullBlock(t *testing.T) {
	plaintext := []byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}
	expected := []byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}
	padded := paddedPlaintext(plaintext, 16)
	if !bytes.Equal(expected, padded) {
		t.Error("Bad padding: ", padded)
	}
}

func Test_paddedPlaintextEmptyBlock(t *testing.T) {
	plaintext := []byte{}
	expected := []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}
	padded := paddedPlaintext(plaintext, 16)
	if !bytes.Equal(expected, padded) {
		t.Error("Bad padding: ", padded)
	}
}
