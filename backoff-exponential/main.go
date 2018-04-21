package main

// Explore backoff exponentially
import (
	"fmt"
	"net"
	"time"

	"github.com/cenkalti/backoff"
)

var (
	msg = "hello world!\n"
)

func main() {
	b := backoff.NewExponentialBackOff()
	for {
		s, err := net.Dial("tcp", "127.0.0.1:2222") // nc -vvkl 2222
		if err != nil {
			t := b.NextBackOff()
			if t == backoff.Stop {
				b.Reset()
			}
			fmt.Printf("error occurred: %+v. connecting again in %+v and closing socket\n", err, t)
			time.Sleep(t)
		} else {
			n, err := s.Write([]byte(msg))
			if err != nil {
				return
			}
			fmt.Printf("connected and wrote %d bytes\n", n)
		}
		if s != nil {
			s.Close()
		}
	}
}
