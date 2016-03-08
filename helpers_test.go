package main

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

func TestEncrypting(t *testing.T) {
	var ciphertext, plaintext []byte
	var err error

	// The key length can be 32, 24, 16  bytes (OR in bits: 128, 192 or 256)
	key := []byte("opensesame123456")
	plaintext = []byte("This is the unecrypted data. Referring to it as plain text.")

	if ciphertext, err = encrypt(key, plaintext); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Cyphertext is:")
	fmt.Printf("%0x\n", ciphertext)
	fmt.Println("_____________________")

	var unencryptedCyphertext []byte
	if unencryptedCyphertext, err = decrypt(key, ciphertext); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Plaintext is:")
	fmt.Printf("%s\n", unencryptedCyphertext)
	fmt.Println("_____________________")

	if !bytes.Equal(plaintext, unencryptedCyphertext) {
		t.Fail()
	}
}
