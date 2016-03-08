package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func sessionMiddleware(c *gin.Context) {
	sessionID, err := c.Cookie("use_ghpages")
	if err != nil {
		fmt.Println(err)
		return
	}

	result := Session{}
	err = sessions.FindId(sessionID).One(&result)
	if err != nil {
		fmt.Println(err)
		return
	}

	c.Set("session", result)
}

func authorizationMiddleware(c *gin.Context) {
	_, ok := c.Get("session")
	fmt.Println(ok)
	if !ok {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"content": "404",
		})
		c.Abort()
	}
}

func getSession(c *gin.Context) *Session {
	sessionUncast, ok := c.Get("session")
	if ok != true {
		return nil
	}

	session, ok := sessionUncast.(Session)
	if ok != true {
		fmt.Println("Error: Cant cast to Session")
		return nil
	}

	return &session
}
