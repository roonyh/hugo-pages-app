package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"gopkg.in/mgo.v2/bson"

	"golang.org/x/oauth2"

	"github.com/gin-gonic/gin"
)

// /
func index(c *gin.Context) {
	user := getSession(c)

	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"user":    user,
		"content": "ROOT",
	})
}

// /login
func login(c *gin.Context) {
	url := oauthConf.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// /callback
func githubCallback(c *gin.Context) {
	state := c.Query("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}

	code := c.Query("code")

	token, err := oauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("oauthConf.Exchange() failed with '%s'\n", err)
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}

	ghuser := getGHUser(token)

	log.Printf("Logged in as GitHub user: %s\n", *ghuser.Login)

	sessionID := newSessionID()
	tokenString, _ := tokenToJSON(token)

	newSession := &Session{
		ID:          sessionID,
		Username:    *ghuser.Login,
		AccessToken: tokenString,
	}

	addSession(newSession)

	user := &User{
		Username: *ghuser.Login,
		Repos:    []int{},
	}

	addUser(user)

	c.SetCookie("use_ghpages", sessionID, 2*365*24*60*60, "/", "", false, true)

	c.Redirect(http.StatusTemporaryRedirect, "/")
}

// /repos
func listRepos(c *gin.Context) {
	session := getSession(c)
	token, _ := tokenFromJSON(session.AccessToken)

	repos, resp := getGHUserRepos(token, 1)

	var areMore bool
	if resp != nil {
		areMore = resp.NextPage != 0
	}

	_, addedRepos := getReposWithOrgs(repos)

	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"user":       session,
		"repos":      repos,
		"addedRepos": addedRepos,
		"areMore":    areMore,
		"content":    "REPOS",
	})
}

// /only-repos
func onlyRepos(c *gin.Context) {
	session := getSession(c)
	token, _ := tokenFromJSON(session.AccessToken)

	page := c.Query("page")
	pageInt, err := strconv.Atoi(page)
	if err != nil {
		log.Println("could not convert page")
	}
	if pageInt == 0 {
		pageInt = 1
	}

	repos, resp := getGHUserRepos(token, pageInt)

	c.Header("HG-PG-Next-Page", strconv.Itoa(resp.NextPage))

	_, addedRepos := getReposWithOrgs(repos)

	c.HTML(http.StatusOK, "repolist.tmpl", gin.H{
		"repos":      repos,
		"addedRepos": addedRepos,
	})
}

// /add
func addNewRepo(c *gin.Context) {
	session := getSession(c)
	token, _ := tokenFromJSON(session.AccessToken)

	fullname := c.Query("fullname")
	id, _ := strconv.Atoi(c.Query("id"))

	repo := &Repo{
		ID:          id,
		Fullname:    fullname,
		Username:    session.Username,
		AccessToken: token.AccessToken,
	}

	err := addRepo(repo, session, token)
	if err != nil {
		log.Println(err.Error(), fullname)
		c.JSON(http.StatusNotAcceptable, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, nil)
}

// /view
func viewRepo(c *gin.Context) {
	session := getSession(c)

	user := User{}
	err := users.Find(bson.M{"_id": session.Username}).One(&user)
	if err != nil {
		fmt.Println("Error: Cant find user")
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))

	repo := Repo{}
	repos.FindId(id).One(&repo)

	buildOutPut := strings.Split(repo.LastBuildOutput, "\n")

	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"user":        session,
		"reposToShow": []Repo{},
		"mainRepo":    repo,
		"buildOutPut": buildOutPut,
		"content":     "BUILDS",
	})
}

// /builds/*fullname
func viewBuilds(c *gin.Context) {
	session := getSession(c)
	token, _ := tokenFromJSON(session.AccessToken)

	fullname := c.Param("fullname")

	fmt.Println(fullname)

	ghrepos, resp := getGHUserRepos(token, 1)

	var areMore bool
	if resp != nil {
		areMore = resp.NextPage != 0
	}

	_, addedRepos := getReposWithOrgs(ghrepos)

	reposToShow := []Repo{}
	var mainRepo Repo

	for idx := range addedRepos {
		repo := Repo{}
		repos.FindId(idx).One(&repo)
		if "/"+repo.Fullname == fullname {
			mainRepo = repo
		}

		reposToShow = append(reposToShow, repo)
	}

	fmt.Println(reposToShow)
	fmt.Println(len(fullname))
	fmt.Println(len(reposToShow))
	if len(fullname) == 1 && len(reposToShow) > 0 {
		fmt.Println("k k k")
		// this request came as /builds/
		mainRepo = reposToShow[0]
	}

	var buildOutPut []string
	buildOutPut = strings.Split(mainRepo.LastBuildOutput, "\n")

	fmt.Println(buildOutPut)

	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"user":        session,
		"areMore":     areMore,
		"reposToShow": reposToShow,
		"mainRepo":    mainRepo,
		"buildOutPut": buildOutPut,
		"fullname":    fullname,
		"content":     "BUILDS",
	})
}

// /only-builds
func onlyBuilds(c *gin.Context) {
	session := getSession(c)
	token, _ := tokenFromJSON(session.AccessToken)

	page := c.Query("page")
	fullname := c.Query("main")
	fmt.Println(fullname)
	pageInt, err := strconv.Atoi(page)
	if err != nil {
		log.Println("could not convert page")
	}
	if pageInt == 0 {
		pageInt = 1
	}

	ghrepos, resp := getGHUserRepos(token, pageInt)

	c.Header("HG-PG-Next-Page", strconv.Itoa(resp.NextPage))

	_, addedRepos := getReposWithOrgs(ghrepos)

	reposToShow := []Repo{}
	var mainRepo Repo
	var mainRepoFound bool

	for idx := range addedRepos {
		repo := Repo{}
		repos.FindId(idx).One(&repo)
		fmt.Println(fullname, repo.Fullname)
		if "/"+repo.Fullname == fullname {
			mainRepo = repo
			mainRepoFound = true
		}

		reposToShow = append(reposToShow, repo)
	}

	if mainRepoFound {
		fmt.Println("bbbbbb")
		var buildOutPut []string
		buildOutPut = strings.Split(mainRepo.LastBuildOutput, "\n")

		c.HTML(http.StatusOK, "build-details.tmpl", gin.H{
			"reposToShow": reposToShow,
			"mainRepo":    mainRepo,
			"buildOutPut": buildOutPut,
		})

		return
	}

	c.HTML(http.StatusOK, "build-list.tmpl", gin.H{
		"reposToShow": reposToShow,
		"mainRepo":    mainRepo,
	})
}

// /remove
func removeAddedRepo(c *gin.Context) {
	session := getSession(c)
	token, _ := tokenFromJSON(session.AccessToken)

	fullname := c.Query("fullname")
	id, _ := strconv.Atoi(c.Query("id"))

	repo := &Repo{
		ID:       id,
		Fullname: fullname,
	}

	err := removeRepo(repo, session, token)
	if err != nil {
		log.Println(err.Error(), fullname)
		c.JSON(http.StatusNotAcceptable, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, nil)
}
