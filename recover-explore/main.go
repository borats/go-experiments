package main

import (
	"fmt"
	"log"
	"sync"
	"github.com/davecgh/go-spew/spew"
)

func doPanic(wg *sync.WaitGroup) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("the code just panicked: %s\n", err)
			err = nil
		}
		spew.Dump(wg)
		wg.Done()
	}()
	fmt.Println("hello i will panic")
	panic("hello i panic'ed")
}

func dontPanic(wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Println("hello i do not panic")
}

func main() {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go dontPanic(&wg)
	go doPanic(&wg)
	wg.Wait()
}
