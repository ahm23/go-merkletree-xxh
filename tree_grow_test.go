package merkletree

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ErrHashFuncFailed = errors.New("mock hash func failed")
)

// build a reference tree using the same logic but with known-good concat & prefix application
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

	current := leaves
	for len(current) > 1 {
		nextLevelSize := (len(current) + 1) >> 1 // Ceiling division
		next := make([][]byte, nextLevelSize)

		for j := 0; j < len(current); j += 2 {
			if j+1 >= len(current) {
				// Carry up the odd node unchanged
				next[j>>1] = current[j]
				continue
			}

			raw := concatBytes(current[j], current[j+1])
			input := raw
			if domainSep {
				input = concatBytes([]byte{nodePrefix}, raw)
			}
			h, err := hashFunc(input)
			require.NoError(t, err)
			next[j>>1] = h
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
		Depth:     calculateDepthUnbalanced(len(input)), // Use new depth calculation
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

func TestGrow_OddCountNoDuplication(t *testing.T) {
	input := generateRandomInputs(t, 3) // odd

	tree, err := New(nil, input)
	require.NoError(t, err)

	// After grow, level 0 should STILL have 3 elements (no duplication)
	assert.Len(t, tree.nodes[0], 3, "leaves should not be duplicated for odd count")

	// All leaves should be the original hashes (no artificial duplication)
	for i := 0; i < 3; i++ {
		assert.NotNil(t, tree.nodes[0][i])
	}

	// Level 1 should have 2 elements: hash(leaf0+leaf1) and leaf2 (carried up)
	assert.Len(t, tree.nodes[1], 2, "odd leaf should be carried up, creating 2 nodes at level 1")

	// Root should be computable without panic
	assert.NotEmpty(t, tree.Root)
}

func TestGrow_DepthCalculation(t *testing.T) {
	tests := []struct {
		leafCount     int
		expectedDepth int
	}{
		{1, 1},
		{2, 2},
		{3, 3}, // With carry-up: 3 -> 2 -> 1 (3 levels)
		{4, 3}, // 4 -> 2 -> 1 (3 levels)
		{5, 4}, // 5 -> 3 -> 2 -> 1 (4 levels)
		{8, 4}, // 8 -> 4 -> 2 -> 1 (4 levels)
	}

	for _, tt := range tests {
		t.Run("leaves_"+string(rune(tt.leafCount)), func(t *testing.T) {
			input := generateRandomInputs(t, tt.leafCount)
			tree, err := New(nil, input)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedDepth, tree.Depth,
				"incorrect depth for %d leaves", tt.leafCount)
		})
	}
}

func TestNew_ZeroLeaves(t *testing.T) {
	input := [][]byte{}

	tree, err := New(nil, input)
	assert.ErrorIs(t, err, ErrInvalidNumOfLeaves)
	assert.Nil(t, tree)
}

// Helper function for new depth calculation (add to your code if not already present)
func calculateDepthUnbalanced(leafCount int) int {
	if leafCount == 0 {
		return 0
	}
	depth := 1
	nodesAtLevel := leafCount
	for nodesAtLevel > 1 {
		nodesAtLevel = (nodesAtLevel + 1) >> 1
		depth++
	}
	return depth
}
