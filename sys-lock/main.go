package main

import (
	"log"
	"time"

	"github.com/pkg/singlefile"
)

func main() {
	const key = "xyzzy"
	unlock, err := singlefile.Lock(key)
	if err != nil {
		log.Fatalf("could not aquire singlefile lock: %v", err)
	}
	defer unlock()

	reUnlock, err := singlefile.Lock(key)
	if err != nil {
		log.Fatalf("relock failed: %v\n", err)
	}
	defer reUnlock()

	time.Sleep(20 * time.Second)
}
