package main

import (
	"fmt"
)

func printDebug(f string, ps ...interface{}) {
	if !debugFlag {
		return
	}
	fmt.Printf(f, ps...)
	fmt.Println()
}
