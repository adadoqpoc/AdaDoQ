package main

import (
	"fmt"
	"os"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	arguments := os.Args
	if len(arguments) <= 1 {
		fmt.Printf("Must run with either \"server\" or \"client\" argument\n")
		return
	}

	if arguments[1] == "server" {
		if err := startServer(); err != nil {
			fmt.Printf("Failed running server: %v\n", err)
		}
	} else if arguments[1] == "client" {
		if err := startClient(); err != nil {
			fmt.Printf("Failed running client: %v\n", err)
		}
	} else {
		fmt.Printf("Expected \"server\" or \"client\" argument, got %q\n", arguments[1])
	}
}
