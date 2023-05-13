package main

import (
	"fmt"
	"math/rand"
	"strings"
)

const wildcard = "*"

var alphabet = strings.Split("abcde", "")

func randPatternsAndString(numPatterns, patternLen, clientStringLen, numWildcards int) ([]string, string, uint64, int) {
	clientString := ""
	for i := 0; i < clientStringLen; i++ {
		clientString += alphabet[rand.Intn(len(alphabet))]
	}

	proofIndex := rand.Intn(numPatterns)
	offset := rand.Intn(clientStringLen - patternLen)

	patterns := make([]string, numPatterns)
	for i := range patterns {
		var pattern string

		if i == proofIndex {
			pattern = clientString[offset : offset+patternLen]
		} else {
			for j := 0; j < patternLen; j++ {
				pattern += alphabet[rand.Intn(len(alphabet))]
			}
		}

		patternBytes := []byte(pattern)
		wildcardIdx := rand.Perm(patternLen)[:numWildcards]
		for _, j := range wildcardIdx {
			patternBytes[j] = wildcard[0]
		}
		pattern = string(patternBytes)

		patterns[i] = pattern
	}

	return patterns, clientString, uint64(proofIndex), offset
}

func main() {
	// stringPatterns := []string{"abc", "de*"}
	// clientString := "xxabcx"
	// proofIndex := uint64(0)
	// offset := 2

	numPatterns := 6
	patternLen := 7
	clientStringLen := 10
	numWildcards := 3
	stringPatterns, clientString, proofIndex, offset := randPatternsAndString(numPatterns, patternLen, clientStringLen, numWildcards)
	fmt.Println("---------------- INPUT DATA ----------------")
	fmt.Println("Number of patterns:", numPatterns)
	fmt.Println("Pattern length:", patternLen)
	fmt.Println("Client string length:", clientStringLen)
	fmt.Println("Number of wildcards in each pattern:", numWildcards)
	// fmt.Println("Client string:", clientString)
	// fmt.Println("Matched pattern:", stringPatterns[proofIndex])

	fmt.Println("---------------- PROTOCOL 0 ----------------")
	Protocol0(stringPatterns, clientString)

	fmt.Println("---------------- PROTOCOL 1 ----------------")
	Protocol1(stringPatterns, clientString, proofIndex, offset)
}
