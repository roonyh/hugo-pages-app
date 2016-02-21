package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	oauthConf *oauth2.Config
	// random string for oauth2 API calls to protect against CSRF
	oauthStateString = "thisshouldberandom"
)

// User is a user
type User struct {
	ID          string `bson:"_id,omitempty"`
	Username    string
	AccessToken string
}

// Repo is a github repo
type Repo struct {
	ID          string `bson:"_id,omitempty"`
	Username    string
	AccessToken string
}

var dbSession *mgo.Session
var users *mgo.Collection
var repos *mgo.Collection
var config *Configuration

func main() {
	config = loadConfig()
	config.print()

	var oauthConf = &oauth2.Config{
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

	users = dbSession.DB("hugo-pages").C("users")
	repos = dbSession.DB("hugo-pages").C("repos")

	router := gin.Default()
	router.Use(sessionMiddleware)

	router.Static("/public", "./public")

	router.LoadHTMLGlob("templates/*")

	router.GET("/", func(c *gin.Context) {
		user := c.Keys["user"]
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"user":    user,
			"content": "ROOT",
		})
	})

	router.GET("/login", func(c *gin.Context) {
		url := oauthConf.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	router.GET("/callback", func(c *gin.Context) {
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

		fmt.Printf("Logged in as GitHub user: %s\n", *ghuser.Login)

		sessionID := newSessionID()
		tokenString, _ := tokenToJSON(token)

		fmt.Println("ses", sessionID)

		newUser := &User{
			ID:          sessionID,
			Username:    *ghuser.Login,
			AccessToken: tokenString,
		}

		addUser(newUser)

		c.SetCookie("use_ghpages", sessionID, 2*365*24*60*60, "/", "", false, true)

		c.Redirect(http.StatusTemporaryRedirect, "/")
	})

	router.GET("/repos", func(c *gin.Context) {
		userUncast, ok := c.Keys["user"]
		if ok != true {
			fmt.Println("Not logged in")
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		user, ok := userUncast.(User)
		if ok != true {
			fmt.Println("Error: Cant cast to User")
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		token, _ := tokenFromJSON(user.AccessToken)

		repos, resp := getGHUserRepos(token, 1)

		var areMore bool
		if resp != nil {
			areMore = resp.NextPage != 0
		}

		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"user":    user,
			"repos":   repos,
			"areMore": areMore,
			"content": "REPOS",
		})
	})

	router.GET("/only-repos", func(c *gin.Context) {
		userUncast, ok := c.Keys["user"]
		if ok != true {
			fmt.Println("Not logged in")
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		user, ok := userUncast.(User)
		if ok != true {
			fmt.Println("Error: Cant cast to User")
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		token, _ := tokenFromJSON(user.AccessToken)

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

		c.HTML(http.StatusOK, "repolist.tmpl", gin.H{
			"repos": repos,
		})
	})

	router.POST("/add/:owner/:repo", func(c *gin.Context) {
		userUncast, ok := c.Keys["user"]
		if ok != true {
			fmt.Println("Not logged in")
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		user, ok := userUncast.(User)
		if ok != true {
			fmt.Println("Error: Cant cast to User")
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		token, _ := tokenFromJSON(user.AccessToken)

		owner := c.Param("owner")
		reponame := c.Param("repo")

		err := addWebHook(token, owner, reponame)
		if err != nil {
			c.JSON(http.StatusNotAcceptable, gin.H{
				"error": err.Error(),
			})
			return
		}

		repo := &Repo{
			ID:          owner + "/" + reponame,
			Username:    user.Username,
			AccessToken: token.AccessToken,
		}
		fmt.Println(repo)
		addRepo(repo)

		c.JSON(http.StatusOK, nil)
	})

	router.Run(":8080")
}

func newSessionID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func addUser(user *User) {
	err := users.Insert(user)
	if err != nil {
		log.Fatal(err)
	}
}

func addRepo(repo *Repo) {
	err := repos.Insert(repo)
	if err != nil {
		log.Fatal(err)
	}
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

func addWebHook(token *oauth2.Token, owner, repo string) error {
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
	_, resp, err := client.Repositories.CreateHook(owner, repo, hook)
	fmt.Println(resp, err)
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

func sessionMiddleware(c *gin.Context) {
	sessionID, err := c.Cookie("use_ghpages")
	if err != nil {
		fmt.Println(err)
		return
	}

	result := User{}
	err = users.Find(bson.M{"_id": sessionID}).One(&result)
	if err != nil {
		fmt.Println(err)
		return
	}

	if c.Keys == nil {
		c.Keys = make(map[string]interface{})
	}
	c.Keys["user"] = result
	c.Next()
}
