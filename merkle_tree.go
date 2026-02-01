package merkletree

import (
	"math/bits"
)

const (
	leafPrefix byte = 0x00 // leaf
	nodePrefix byte = 0x01 // not leaf
)

type TypeHashFunc func([]byte) ([]byte, error)
type Config struct {
	// If true, use 128-bit XXH hashing for tree building
	XXH128 bool
	// If true, an extra byte is prepended to all nodes to distinguish the domains of leaves and branches
	DomainSeperation bool
}

type MerkleTree struct {
	*Config
	// Maps leaf nodes to their index in the tree's leaf level.
	// This reverse-map is useful when generating proofs.
	leafMap map[string]int
	// hash function used for tree building.
	hashFunc TypeHashFunc
	// nodes contains the Merkle Tree's internal node structure.
	nodes [][][]byte

	// Merkle root node hash.
	Root []byte
	// Hashes of the raw input data for the Merkle leaves.
	Leaves [][]byte
	// Depth of the Merkle tree.
	Depth int
	// Number of leaves in the Merkle tree.
	LeafCount int
}

// New generates a new Merkle Tree with the specified configuration and leaf inputs.
func New(config *Config, input [][]byte) (*MerkleTree, error) {
	if len(input) <= 1 {
		return nil, ErrInvalidNumOfLeaves
	}
	if config == nil {
		config = new(Config)
	}

	m := &MerkleTree{
		Config:    config,
		LeafCount: len(input),
		Depth:     bits.Len(uint(len(input) - 1)),
	}

	if config.XXH128 {
		m.hashFunc = xxh3Hash128
	} else {
		m.hashFunc = xxh3Hash64
	}

	var err error
	// generate leaves
	m.Leaves, err = m.computeLeafNodes(input)
	if err != nil {
		return nil, err
	}
	m.leafMap = make(map[string]int)
	if err := m.grow(); err != nil {
		return nil, err
	}

	return m, nil
}
