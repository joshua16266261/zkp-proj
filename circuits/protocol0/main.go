package protocol0

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	MerkleProof merkle.MerkleProof `gnark:",public"`
	ProofIndex  frontend.Variable  // TODO: Should this be public or private?
}

func (circuit *Circuit) Define(api frontend.API) error {
	hFunc, _ := mimc.NewMiMC(api)
	circuit.MerkleProof.VerifyProof(api, &hFunc, circuit.ProofIndex)

	// TODO: Verify that the value opened from the merkle tree is correct or something

	return nil
}

func main() {
	// Define pattern
	field := ecc.BN254.ScalarField()
	modNbBytes := len(field.Bytes())
	var buf bytes.Buffer
	numLeaves := uint16(4)
	for i := uint16(0); i < numLeaves; i++ {
		// FIXME: Each element in the committed vector is a field element of length modNbBytes bytes
		// How do we commit to a list of patterns?
		leaf := i
		b := new(bytes.Buffer)
		err := binary.Write(b, binary.LittleEndian, leaf)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
		}
		buf.Write(make([]byte, modNbBytes-b.Len()))
		buf.Write(b.Bytes())
	}

	hGo := hash.MIMC_BN254.New()
	segmentSize := 32
	proofIndex := uint64(1)
	merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(bytes.NewReader(buf.Bytes()), hGo, segmentSize, proofIndex)
	fmt.Println("merkleRoot 1", merkleRoot)
	if err != nil {
		fmt.Println(err)
		return
	}

	depth := 2

	var circuit Circuit
	circuit.MerkleProof.Path = make([]frontend.Variable, depth+1)

	r1cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}

	var merkleProof merkle.MerkleProof
	merkleProof.RootHash = merkleRoot

	merkleProof.Path = make([]frontend.Variable, depth+1)
	for i := 0; i < depth+1; i++ {
		merkleProof.Path[i] = proofPath[i]
	}

	assignment := &Circuit{
		MerkleProof: merkleProof,
		ProofIndex:  proofIndex,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Prove failed: %v\n", err)
		return
	}

	///////// Assignment for different index /////////
	proofIndex = uint64(2)
	merkleRoot, proofPath, _, err = merkletree.BuildReaderProof(bytes.NewReader(buf.Bytes()), hGo, segmentSize, proofIndex)
	fmt.Println("merkleRoot 2", merkleRoot)
	if err != nil {
		fmt.Println(err)
		return
	}

	var falseMerkleProof merkle.MerkleProof
	falseMerkleProof.RootHash = merkleRoot

	falseMerkleProof.Path = make([]frontend.Variable, depth+1)
	for i := 0; i < depth+1; i++ {
		falseMerkleProof.Path[i] = proofPath[i]
	}

	falseAssignment := &Circuit{
		MerkleProof: falseMerkleProof,
		ProofIndex:  proofIndex,
	}

	falseWitness, err := frontend.NewWitness(falseAssignment, ecc.BN254.ScalarField())
	falseProof, err := groth16.Prove(r1cs, pk, falseWitness)
	if err != nil {
		fmt.Printf("Prove failed: %v\n", err)
		return
	}

	///////// Public witness and verification /////////

	publicWitness, err := witness.Public()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")

	err = groth16.Verify(falseProof, vk, publicWitness)
	if err == nil {
		fmt.Printf("False verification should have failed but did not")
		return
	}
	fmt.Printf("verification failed successfully\n")

}

func Main() {
	// FIXME: This is pretty jank
	main()
}
