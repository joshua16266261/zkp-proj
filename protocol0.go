package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/hash"
)

func multiply(left []string, right []string) []string {
	product := []string{}
	for _, leftString := range left {
		for _, rightString := range right {
			product = append(product, leftString+rightString)
		}
	}
	return product
}

func expandWildcards(pattern string) []string {
	numWildcards := strings.Count(pattern, wildcard)
	if numWildcards == 0 {
		return []string{pattern}
	}

	// result := []string{string(pattern[0])}
	var result []string
	if pattern[0] == '*' {
		result = alphabet
	} else {
		result = []string{string(pattern[0])}
	}
	for i := 1; i < len(pattern); i++ {
		if pattern[i] == '*' {
			result = multiply(result, alphabet)
		} else {
			result = multiply(result, []string{string(pattern[i])})
		}
	}
	return result
}

func expandOffset(pattern string, maxOffset int) []string {
	// expandOffset takes a pattern and pads it with
	// i <= maxOffset wildcards on the left and maxOffset - i wildcards on the right
	// so that it accounts for all possible offsets

	padded := []string{}
	for i := 0; i <= maxOffset; i++ {
		leftPad := strings.Repeat(wildcard, i)
		rightPad := strings.Repeat(wildcard, maxOffset-i)
		padded = append(padded, leftPad+pattern+rightPad)
	}
	return padded
}

func expandPattern(pattern string, maxOffset int) []string {
	// expandPattern takes a pattern and expands both the offset and wildcards

	expanded := []string{}
	padded := expandOffset(pattern, maxOffset)
	for _, s := range padded {
		expanded = append(expanded, expandWildcards(s)...)
	}
	return expanded
}

func Protocol0(stringPatterns []string, clientString string) {
	// Expand out wildcards and offsets in patterns
	fmt.Println("Expanding patterns...")
	expandedPatterns := []string{}
	for _, pattern := range stringPatterns {
		expandedPatterns = append(expandedPatterns, expandPattern(pattern, len(clientString)-len(pattern))...)
	}

	// Find index of expanded pattern that matches clientString
	var proofIndex uint64
	for i, pattern := range expandedPatterns {
		if clientString == pattern {
			proofIndex = uint64(i)
			break
		}
	}

	// Hash patterns
	fmt.Println("Hashing expanded patterns...")
	var hashedPatterns [][]byte
	for _, pattern := range expandedPatterns {
		hashedPattern, err := getHash(pattern)
		if err != nil {
			fmt.Println("Error hashing pattern:", err)
			return
		}
		hashedPatterns = append(hashedPatterns, hashedPattern)
	}

	// Build merkle proof
	fmt.Println("Building merkle proof...")
	start := time.Now()
	var buf bytes.Buffer
	for _, pattern := range hashedPatterns {
		buf.Write(pattern)
	}

	hGo := hash.MIMC_BN254.New()
	segmentSize := 32
	merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(bytes.NewReader(buf.Bytes()), hGo, segmentSize, proofIndex)
	// The actual value of the leaf is proofPath[0]
	if err != nil {
		fmt.Println(err)
		return
	}
	duration := time.Since(start)
	fmt.Println("Prover time:", duration)

	// Verify merkle proof
	start = time.Now()
	isValidProof := merkletree.VerifyProof(hGo, merkleRoot, proofPath, proofIndex, uint64(len(expandedPatterns)))
	if !isValidProof {
		fmt.Println("failed to verify proof")
		return
	}

	// Hash client string
	hashedClientString, err := getHash(clientString)
	if err != nil {
		fmt.Println("Error hashing clientString:", err)
		return
	}

	// Check equality of clientString and pattern
	patternEqualsString := reflect.DeepEqual(hashedClientString, proofPath[0])
	if !patternEqualsString {
		fmt.Println("client string and pattern do not match")
		return
	}
	duration = time.Since(start)
	fmt.Println("Verifier time:", duration)

	fmt.Println("Verification succeeded")
}
