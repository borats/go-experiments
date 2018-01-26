package main

import (
	"log"

	"github.com/pkg/errors"
)

func main() {
	src := []int{1, 2, 3, 4, 5}
	log.Println(src)
	x, err := slowRemoveAt(2, src)
	if err != nil {
		log.Panic(err)
	}
	log.Printf("src = %+v\n", x)

	src1 := []int{1, 2, 3, 4, 5}
	src1 = okRemoveAt(2, src1)
	log.Printf("src1 = %+v\n", src1)

	src2 := []int{1, 2, 3, 4, 5}
	src2 = vFastRemoveAt(2, src2)
	log.Printf("src2 = %+v\n", src2)
}

// Shorter code, does not preserve the original
// slice index. Provides very faster deletion of
// a slice element by avoiding copy()'ing.
func vFastRemoveAt(i int, src []int) []int {
	src[i] = src[len(src)-1] // Copy last element to index i
	src[len(src)-1] = 0      // Erase last element (write zero value)
	src = src[:len(src)-1]   // Truncate slice
	return src
}

// Shorter code, little harder to understand but
// provides decent deletion speed of a slice element since
// use built-in copy() function. Lower cyclomatic complexity.
func okRemoveAt(i int, src []int) []int {
	copy(src[i:], src[i+1:])
	src[len(src)-1] = 0
	src = src[:len(src)-1]
	return src
}

// Easy to comprehend. Slower and more resource intensive
// implementation as we iterate over the slice, keep append()'ing the
// unmatched position in the slice.
func slowRemoveAt(i int, src []int) ([]int, error) {
	var n []int
	if i < 0 || i > len(src) {
		return nil, errors.New("invalid index")
	}
	for pos, item := range src {
		if pos != i {
			n = append(n, item)
		}
	}
	return n, nil
}
