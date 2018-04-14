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
	b.MaxElapsedTime = 0 // indefinitely
	for {
		s, err := net.Dial("tcp", "127.0.0.1:2222") // nc -v -k -l 2222
		if err != nil {
			t := b.NextBackOff()
			fmt.Printf("err %s occurred. connecting again in %+v and closing socket\n", err, t)
			if s != nil {
				s.Close()
			}
			time.Sleep(t)
		} else {
			n, err := s.Write([]byte(msg))
			if err != nil {
				return
			}
			fmt.Printf("connected and wrote %d bytes\n", n)
			s.Close() // we are done
		}
	}
}
