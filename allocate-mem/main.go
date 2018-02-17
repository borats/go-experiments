package main

import (
	"log"

	"github.com/cznic/memory"
)

func main() {
	allocator := memory.Allocator{}
	b, err := allocator.Calloc(len("hello world"))
	if err != nil {
		panic(err)
	}
	// assign a byte slice to the address of b in heap
	copy(b, []byte("hello world"))

	// can't re-assign b as it changes the backing array
	//b = []byte("hello world")

	log.Printf(
		"b is: %+v, len: %d, cap: %d\n",
		b, len(b), cap(b),
	)
	if err = allocator.Free(b); err != nil {
		panic(err)
	}
}
