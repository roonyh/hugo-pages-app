package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log"

	"github.com/google/go-github/github"
	mgo "gopkg.in/mgo.v2"
)

type repoMap map[int]bool

func getReposWithOrgs(ghrepos []github.Repository) (map[string]repoMap, repoMap) {
	accountsMap := make(map[string]repoMap)
	allRepoMap := make(repoMap)

	for _, ghr := range ghrepos {
		owner := *ghr.Owner.Login
		reposOfAccount, ok := accountsMap[owner]
		if !ok {
			acc := &Account{}
			err := accounts.FindId(owner).One(acc)
			if err != nil && err != mgo.ErrNotFound {
				log.Println(err.Error())
			}

			reposOfAccount = make(repoMap)
			for _, r := range acc.Repos {
				reposOfAccount[r] = true
			}

			accountsMap[owner] = reposOfAccount
		}

		if reposOfAccount[*ghr.ID] {
			allRepoMap[*ghr.ID] = true
		}
	}

	return accountsMap, allRepoMap
}

func encrypt(text []byte) (ciphertext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(secretKey); err != nil {
		return nil, err
	}

	ivSource := []byte("abcdef1234567890")
	iv := ivSource[:aes.BlockSize] // const BlockSize = 16

	cfb := cipher.NewCFBEncrypter(block, iv)

	ciphertext = make([]byte, len(text))
	cfb.XORKeyStream(ciphertext, text)

	return
}

func decrypt(ciphertext []byte) (plaintext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(secretKey); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := []byte("abcdef1234567890")

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}
