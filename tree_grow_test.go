package merkletree

import (
	"bytes"
	"errors"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ErrHashFuncFailed = errors.New("mock hash func failed")
)

// Helper: build a reference tree using the same logic but with known-good concat & prefix application
// (useful for comparing roots when domain sep is on/off)
func buildReferenceTree(t *testing.T, inputs [][]byte, domainSep bool, use128 bool) []byte {
	t.Helper()

	hashFunc := xxh3Hash64
	if use128 {
		hashFunc = xxh3Hash128
	}

	// Compute leaves the same way
	leaves := make([][]byte, len(inputs))
	for i, d := range inputs {
		input := d
		if domainSep {
			input = make([]byte, 1+len(d))
			input[0] = leafPrefix
			copy(input[1:], d)
		}
		var err error
		leaves[i], err = hashFunc(input)
		require.NoError(t, err)
	}

	// Build layers with duplication
	current := leaves
	for len(current) > 1 {
		if len(current)%2 == 1 {
			current = append(current, current[len(current)-1])
		}

		next := make([][]byte, len(current)/2)
		for j := 0; j < len(current); j += 2 {
			raw := concatBytes(current[j], current[j+1])
			input := raw
			if domainSep {
				input = concatBytes([]byte{nodePrefix}, raw)
			}
			h, err := hashFunc(input)
			require.NoError(t, err)
			next[j/2] = h
		}
		current = next
	}

	if len(current) != 1 {
		t.Fatal("reference tree did not reduce to single root")
	}
	return current[0]
}

func TestGrow_BasicTrees(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		leafCount int
		domainSep bool
		useXXH128 bool
	}{
		{"2 leaves, no sep, XXH64", 2, false, false},
		{"3 leaves, no sep, XXH64", 3, false, false},
		{"4 leaves, no sep, XXH64", 4, false, false},
		{"5 leaves, no sep, XXH64", 5, false, false},
		{"8 leaves, no sep, XXH64", 8, false, false},

		{"3 leaves, with sep, XXH64", 3, true, false},
		{"5 leaves, with sep, XXH64", 5, true, false},

		{"4 leaves, no sep, XXH128", 4, false, true},
		{"5 leaves, with sep, XXH128", 5, true, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			input := generateRandomInputs(t, tt.leafCount)

			cfg := &Config{
				DomainSeperation: tt.domainSep,
				XXH128:           tt.useXXH128,
			}

			tree, err := New(cfg, input)
			require.NoError(t, err, "tree creation failed")

			// Build reference independently
			refRoot := buildReferenceTree(t, input, tt.domainSep, tt.useXXH128)

			assert.True(t, bytes.Equal(tree.Root, refRoot),
				"root mismatch for %s\n expected: %x\n got:      %x", tt.name, refRoot, tree.Root)
		})
	}
}

func TestGrow_HashErrorPropagation(t *testing.T) {
	input := generateRandomInputs(t, 4)

	mockHash := func(data []byte) ([]byte, error) {
		return nil, ErrHashFuncFailed
	}

	tree := &MerkleTree{
		Config: &Config{
			DomainSeperation: false,
		},
		hashFunc:  mockHash,
		LeafCount: len(input),
		Depth:     bits.Len(uint(len(input) - 1)),
		leafMap:   make(map[string]int),
	}

	// Leaves will fail
	_, err := tree.computeLeafNodes(input)
	assert.ErrorIs(t, err, ErrHashFuncFailed)

	// If we mock only internal hash (simulate leaf success)
	tree.hashFunc = func(data []byte) ([]byte, error) {
		// Pretend leaves succeeded earlier
		if len(data) == 32 || (len(data) == 33 && data[0] == leafPrefix) {
			return bytes.Repeat([]byte{0xAA}, 8), nil // fake hash
		}
		return nil, ErrHashFuncFailed
	}

	tree.Leaves, _ = tree.computeLeafNodes(input) // fake success
	err = tree.grow()
	assert.ErrorIs(t, err, ErrHashFuncFailed, "grow should propagate internal hash error")
}

func TestGrow_RootWithDomainSep(t *testing.T) {
	input := generateRandomInputs(t, 4)

	// Build twice: once with sep, once without
	treeSep, err := New(&Config{DomainSeperation: true}, input)
	require.NoError(t, err)

	treeNoSep, err := New(&Config{DomainSeperation: false}, input)
	require.NoError(t, err)

	assert.NotEqual(t, treeSep.Root, treeNoSep.Root,
		"roots should differ when domain separation is toggled")
}

func TestGrow_OddCountDuplication(t *testing.T) {
	input := generateRandomInputs(t, 3) // odd

	tree, err := New(nil, input)
	require.NoError(t, err)

	// After grow, level 0 should have 4 elements, last two equal
	assert.Len(t, tree.nodes[0], 4)
	assert.True(t, bytes.Equal(tree.nodes[0][2], tree.nodes[0][3]),
		"last leaf should be duplicated for odd count")

	// Root should be computable without panic
	assert.NotEmpty(t, tree.Root)
}
