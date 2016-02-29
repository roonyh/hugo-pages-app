package main

import (
	"fmt"

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
