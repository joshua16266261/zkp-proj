package main

import "fmt"

const wildcard = "*"

func main() {
	stringPatterns := []string{"abcdefghijkl", "de*"}
	clientString := "abcdefghijkl"
	proofIndex := uint64(0)
	offset := 0

	fmt.Println("---------------- PROTOCOL 0 ----------------")
	Protocol0(stringPatterns, clientString, proofIndex)

	fmt.Println("---------------- PROTOCOL 1 ----------------")
	Protocol1(stringPatterns, clientString, proofIndex, offset)
}
