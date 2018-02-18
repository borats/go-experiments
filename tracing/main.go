package main

import (
	"fmt"
	"log"
	"time"
)

// work does some heavy work
func work() {
	//trace the total execution time
	defer func(s time.Time) {
		log.Printf("trace complete in %s", time.Now().Sub(s))
	}(time.Now())

	log.Println("working..")
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for range ticker.C {
			fmt.Printf(".")
		}
	}()
	// some heavy computation..
	time.Sleep(5 * time.Second)
}

func main() {
	work()
	log.Println("done")
}
