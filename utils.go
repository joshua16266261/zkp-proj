package main

import (
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func getFieldElements(pattern string) [][]byte {
	// GetFieldElements converts each character of a string pattern into a field element
	var fieldElems [][]byte

	blockSize := bn254.BlockSize

	for _, char := range pattern {
		b := make([]byte, blockSize)
		b[blockSize-1] = byte(char)
		fieldElems = append(fieldElems, b)
	}
	return fieldElems
}

func getHash(pattern string) ([]byte, error) {
	// GetHash hashes a string pattern into a single field element

	converted := getFieldElements(pattern)
	var flattened []byte
	for _, elem := range converted {
		flattened = append(flattened, elem...)
	}

	return bn254.Sum(flattened)
}
