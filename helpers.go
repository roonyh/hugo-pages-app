package main

import (
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
