package sync

import (
	"crypto/rand"
	"time"
)

func randomRecordId() string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, 12)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func timestampNow() float64 {
	return float64(time.Now().UnixNano()/10000000) / 100
}

func paddedPlaintext(plaintext []byte, blockSize int) []byte {
	paddingLength := blockSize - (len(plaintext) % blockSize)
	padding := make([]byte, paddingLength)
	for i := 0; i < paddingLength; i++ {
		padding[i] = byte(paddingLength)
	}

	padded := make([]byte, len(plaintext)+paddingLength)

	n := copy(padded, plaintext)
	copy(padded[n:], padding)

	return padded
}
