package main

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var x int64 = 0
	println(x)
	timer := time.NewTicker(5 * time.Second)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			x = atomic.AddInt64(&x, 1024)
			runtime.Gosched() // yield this goroutine
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			x = atomic.AddInt64(&x, -1024)
			runtime.Gosched() // yield this goroutine
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range timer.C {
			println(atomic.LoadInt64(&x))
		}
	}()
	wg.Wait()
	println(x)
}
