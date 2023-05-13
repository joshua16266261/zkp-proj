package main

import (
	"fmt"
	"strings"
)

const wildcard = "*"

var alphabet = strings.Split("abcdefghijklmnopqrstuvwxyz", "")

func main() {
	stringPatterns := []string{"abc", "de*"}
	clientString := "xxabcx"
	proofIndex := uint64(0)
	offset := 2

	fmt.Println("---------------- PROTOCOL 0 ----------------")
	Protocol0(stringPatterns, clientString)

	fmt.Println("---------------- PROTOCOL 1 ----------------")
	Protocol1(stringPatterns, clientString, proofIndex, offset)
}
