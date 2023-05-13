package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/txaty/go-merkletree"
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

type stringData struct {
	string
}

func (s *stringData) Serialize() ([]byte, error) {
	return []byte(s.string), nil
}

func Protocol0(stringPatterns []string, clientString string) {
	// Expand out wildcards and offsets in patterns
	fmt.Println("Expanding patterns...")
	expandedPatterns := []string{}
	for _, pattern := range stringPatterns {
		expandedPatterns = append(expandedPatterns, expandPattern(pattern, len(clientString)-len(pattern))...)
	}
	fmt.Println("Number of patterns after expansion:", len(expandedPatterns))

	// Build merkle tree
	fmt.Println("Building merkle tree...")
	start := time.Now()
	leaves := make([]merkletree.DataBlock, len(expandedPatterns))
	for i := range expandedPatterns {
		leaves[i] = &stringData{expandedPatterns[i]}
	}

	tree, err := merkletree.New(
		&merkletree.Config{
			Mode:          merkletree.ModeProofGenAndTreeBuild,
			RunInParallel: true,
		},
		leaves,
	)
	if err != nil {
		fmt.Println("failed to build merkle tree:", err)
		return
	}
	duration := time.Since(start)
	fmt.Println("Setup time:", duration)

	// Generate merkle proof
	fmt.Println("Generating merkle proof...")
	start = time.Now()
	proof, err := tree.Proof(&stringData{clientString})
	if err != nil {
		fmt.Println("failed to generate merkle proof:", err)
		return
	}
	duration = time.Since(start)
	fmt.Println("Prover time:", duration)

	// Verify merkle proof
	start = time.Now()
	isValidProof, err := tree.Verify(&stringData{clientString}, proof)
	if err != nil {
		fmt.Println("error verifying proof:", err)
		return
	}
	if !isValidProof {
		fmt.Println("invalid proof")
		return
	}
	duration = time.Since(start)
	fmt.Println("Verifier time:", duration)

	fmt.Println("Verification succeeded")
}
