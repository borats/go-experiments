// +build linux darwin openbsd
// +build amd64

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/davecgh/go-spew/spew"
)

var (
	path  = flag.String("path", "/", "path to calculate the usage details on")
	debug = flag.Bool("debug", false, "spew statfs structure")
)

func init() {
	flag.Parse()
}

func main() {
	diskSize, err := diskCalc()
	if err != nil {
		log.Fatal(err)
	}

	if *debug == true {
		spew.Dump(diskSize)
	}
	fmt.Printf("total space %s = %.2f %s\n", *path, diskSize.total, unitStr)
	fmt.Printf("available space %s = %.2f %s\n", *path, diskSize.available, unitStr)
}
