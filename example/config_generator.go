package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/devsisters/goquic"
)

func main() {
	cfg := goquic.GenerateSerializedServerConfig()

	b, err := json.Marshal(cfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
