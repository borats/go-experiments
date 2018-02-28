package main


import (
	"io"
	"os"
	"log"

)

func Copy(in io.ReadSeeker, out io.Writer) (int64, error) {
	w := io.MultiWriter(out, os.Stdout)

	var n int64
	var err error
	if n, err = io.Copy(w, in); err != nil {
		return 0, err
	}
	return n, nil
}

func main() {

	src, err := os.Open("/tmp/aa")
	if err != nil {
		log.Fatal(err)
	}


	dest, err := os.OpenFile("/tmp/bb", os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		log.Fatal(err)
	}
	Copy(src, dest)

	dest.Sync()
	defer src.Close()
	defer dest.Close()
}
