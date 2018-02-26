package main

import (
	"fmt"
	"log"
	"time"
)

// trace the total execution time
func trace(start time.Time) {
	log.Printf("trace complete in %s", time.Now().Sub(start))
}

// progressPrint prints dots every second
func progressPrint() {
	ticker := time.NewTicker(500 * time.Millisecond)
	for range ticker.C {
		fmt.Printf(".")
	}
}

// work does some heavy work
func work(traceFn func(time.Time)) {
	defer traceFn(time.Now())
	log.Println("working..")
	go progressPrint()
	time.Sleep(5 * time.Second)
}

func main() {
	work(trace)
	log.Println("done")
}
