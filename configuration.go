package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Configuration contains config options for service
type Configuration struct {
	Address      string
	MongoURL     string
	HookHandler  string
	ClientID     string
	ClientSecret string
	SecretKey    string
}

func loadConfig() *Configuration {
	file, _ := os.Open("config.json")
	decoder := json.NewDecoder(file)
	configuration := &Configuration{}
	err := decoder.Decode(configuration)
	if err != nil {
		fmt.Println("error:", err)
		return nil
	}

	return configuration
}

func (c *Configuration) print() {
	fmt.Println("hook handler:", c.HookHandler, " mongo:", c.MongoURL)
}
