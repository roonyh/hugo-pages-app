package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	oauthConf *oauth2.Config
)

// Session is a session
type Session struct {
	ID                 string `bson:"_id,omitempty"`
	Username           string
	EncAccessToken     []byte
	EncAccessTokenOnly []byte
}

// User is a user
type User struct {
	Username string `bson:"_id,omitempty"`
	Repos    []int
}

// Account is a account
type Account struct {
	Username string `bson:"_id,omitempty"`
	Repos    []int
}

// Repo is a github repo
type Repo struct {
	ID              int `bson:"_id,omitempty"`
	Fullname        string
	Username        string
	EncAccessToken  []byte
	HookID          int
	LastBuildOutput string
	LastBuildStatus string
}

var dbSession *mgo.Session
var sessions *mgo.Collection
var users *mgo.Collection
var repos *mgo.Collection
var accounts *mgo.Collection
var config *Configuration
var secretKey []byte

func main() {
	config = loadConfig()
	config.print()

	var err error
	secretKey, err = hex.DecodeString(config.SecretKey)
	if err != nil {
		panic(err)
	}

	oauthConf = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       []string{"user:email", "repo"},
		Endpoint:     githuboauth.Endpoint,
	}

	dbSession, err := mgo.Dial(config.MongoURL)
	if err != nil {
		panic(err)
	}
	defer dbSession.Close()

	sessions = dbSession.DB("hugo-pages").C("sessions")
	users = dbSession.DB("hugo-pages").C("users")
	repos = dbSession.DB("hugo-pages").C("repos")
	accounts = dbSession.DB("hugo-pages").C("accounts")

	router := gin.Default()
	router.Use(sessionMiddleware)

	router.NoRoute(func(c *gin.Context) {
		session := getSession(c)

		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"user":    session,
			"content": "404",
		})
	})

	router.Static("/public", "./public")

	t := template.Must(template.New("").Funcs(template.FuncMap{
		"Deref": func(i *int) int { return *i },
	}).ParseGlob("templates/*"))

	router.SetHTMLTemplate(t)

	/* Request handlers */
	router.GET("/login", login)
	router.POST("/logout", logout)
	router.GET("/callback", githubCallback)

	router.GET("/", index)
	router.POST("/", index)

	authorized := router.Group("/")
	authorized.Use(authorizationMiddleware)

	authorized.GET("/add-project", listRepos)
	authorized.GET("/only-repos", onlyRepos)
	authorized.POST("/add", addNewRepo)
	authorized.POST("/remove", removeAddedRepo)
	authorized.GET("/builds/*fullname", viewBuilds)
	authorized.GET("/only-builds", onlyBuilds)
	authorized.POST("/build-info", buildInfo)

	router.Run(":8080")
}

/* Helpers */

func newSessionID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func addSession(session *Session) error {
	err := sessions.Insert(session)
	if err != nil {
		log.Printf("Error adding session: %s", err.Error())
	}
	return err
}

func addUser(user *User) error {
	err := users.Insert(user)
	if err != nil {
		log.Printf("Error adding repo: %s", err.Error())
	}
	return err
}

func addRepo(repo *Repo, session *Session, token *oauth2.Token) error {
	err := repos.Insert(repo)
	if err != nil {
		if mgo.IsDup(err) {
			log.Println("Duplicate:", repo.Fullname)
			// We already have a hook added for this repo
			currentRepo := Repo{}
			err := repos.FindId(repo.ID).One(&currentRepo)
			if err != nil {
				log.Println(err)
				return err
			}

			err = deleteWebHook(token, repo.Fullname, currentRepo.HookID)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	hook, err := addWebHook(token, repo.Fullname)
	if err != nil {
		return err
	}

	change := bson.M{
		"$push": bson.M{
			"repos": repo.ID,
		},
	}

	ownerAndRepo := strings.Split(repo.Fullname, "/")

	_, err = accounts.UpsertId(ownerAndRepo[0], change)
	if err != nil {
		return err
	}

	change = bson.M{
		"$set": bson.M{
			"hookid": hook.ID,
		},
	}
	repos.UpdateId(repo.ID, change)
	if err != nil {
		return err
	}

	return nil
}

func removeRepo(repo *Repo, session *Session, token *oauth2.Token) error {
	currentRepo := Repo{}
	err := repos.FindId(repo.ID).One(&currentRepo)
	if err != nil {
		log.Println(err)
		return err
	}

	err = deleteWebHook(token, repo.Fullname, currentRepo.HookID)
	if err != nil {
		return err
	}

	err = repos.RemoveId(repo.ID)
	if err != nil {
		return err
	}

	change := bson.M{
		"$pull": bson.M{
			"repos": repo.ID,
		},
	}
	err = users.UpdateId(session.Username, change)
	if err != nil {
		return err
	}
	ownerAndRepo := strings.Split(repo.Fullname, "/")

	err = accounts.UpdateId(ownerAndRepo[0], change)
	if err != nil {
		return err
	}

	return nil
}

func getGHUser(token *oauth2.Token) *github.User {
	oauthClient := oauthConf.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	user, _, err := client.Users.Get("")
	if err != nil {
		fmt.Printf("client.Users.Get() failed with '%s'\n", err)
		return nil
	}
	return user
}

func getGHUserRepos(token *oauth2.Token, page int) ([]github.Repository, *github.Response) {
	oauthClient := oauthConf.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	repoListOpts := &github.RepositoryListOptions{
		Sort: "updated",
		ListOptions: github.ListOptions{
			PerPage: 50,
			Page:    page,
		},
	}
	repos, resp, err := client.Repositories.List("", repoListOpts)

	if err != nil {
		fmt.Printf("client.Repositories.List() failed with '%s'\n", err)
		return nil, nil
	}
	return repos, resp
}

func getGHUserOrgs(token *oauth2.Token) []github.Organization {
	oauthClient := oauthConf.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	orgs, _, err := client.Organizations.List("", nil)
	if err != nil {
		fmt.Printf("client.Repositories.List() failed with '%s'\n", err)
		return nil
	}
	return orgs
}

func addWebHook(token *oauth2.Token, fullname string) (*github.Hook, error) {
	ownerAndRepo := strings.Split(fullname, "/")
	oauthClient := oauthConf.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	web := "web"
	url := config.HookHandler
	hook := &github.Hook{
		Name:   &web,
		Events: []string{"push"},
		URL:    &url,
		Config: map[string]interface{}{
			"url":          url,
			"insecure_ssl": true,
			"secret":       "hugopagessecret",
			"content_type": "json",
		},
	}

	hook, _, err := client.Repositories.CreateHook(ownerAndRepo[0], ownerAndRepo[1], hook)

	return hook, err
}

func deleteWebHook(token *oauth2.Token, fullname string, id int) error {
	oauthClient := oauthConf.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	ownerAndRepo := strings.Split(fullname, "/")
	_, err := client.Repositories.DeleteHook(ownerAndRepo[0], ownerAndRepo[1], id)
	if err == nil {
		log.Printf("deleted hook %s %d", fullname, id)
	}

	return err
}

func tokenToJSON(token *oauth2.Token) (string, error) {
	var tokenString []byte
	tokenString, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	return string(tokenString), nil
}

func tokenFromJSON(jsonStr string) (*oauth2.Token, error) {
	var token oauth2.Token
	err := json.Unmarshal([]byte(jsonStr), &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}
