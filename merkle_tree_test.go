package merkletree

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to generate n random 32-byte "leaves"
func generateRandomLeaves(t *testing.T, n int) [][]byte {
	t.Helper()
	leaves := make([][]byte, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		require.NoError(t, err, "failed to generate random bytes")
		leaves[i] = b
	}
	return leaves
}

func TestNew(t *testing.T) {
	t.Parallel() // run subtests in parallel where possible

	t.Run("rejects invalid leaf counts", func(t *testing.T) {
		tests := []struct {
			name      string
			inputLen  int
			expectErr error
		}{
			{"zero leaves", 0, ErrInvalidNumOfLeaves},
			{"single leaf", 1, ErrInvalidNumOfLeaves},
		}

		for _, tt := range tests {
			tt := tt // capture range var
			t.Run(tt.name, func(t *testing.T) {
				input := generateRandomLeaves(t, tt.inputLen)
				tree, err := New(nil, input)
				assert.ErrorIs(t, err, tt.expectErr)
				assert.Nil(t, tree)
			})
		}
	})

	t.Run("creates valid tree with 2 leaves - default config", func(t *testing.T) {
		input := generateRandomLeaves(t, 2)
		tree, err := New(nil, input)
		require.NoError(t, err)
		require.NotNil(t, tree)

		assert.Equal(t, 2, tree.LeafCount)
		assert.Equal(t, 1, tree.Depth) // 2 leaves → depth 1 (root = hash(left||right))
		assert.Len(t, tree.Leaves, 2)
		assert.Len(t, tree.nodes, 1) // only level 0 (leaves) if Depth=1, adjust if grow adds root level differently
		assert.NotEmpty(t, tree.Root)
		assert.Len(t, tree.leafMap, 2)
	})

	t.Run("Depth calculation correct for various sizes", func(t *testing.T) {
		tests := []struct {
			n     int
			depth int
		}{
			{2, 1},
			{3, 2}, // bits.Len(3-1)=2 → depth 2
			{4, 2},
			{5, 3},
			{8, 3},
			{9, 4},
		}

		for _, tt := range tests {
			tt := tt
			t.Run("", func(t *testing.T) {
				input := generateRandomLeaves(t, tt.n)
				tree, err := New(nil, input)
				require.NoError(t, err)
				assert.Equal(t, tt.depth, tree.Depth, "wrong depth for %d leaves", tt.n)
			})
		}
	})

	t.Run("DomainSeparation affects leaf hashes", func(t *testing.T) {
		input := generateRandomLeaves(t, 4)

		// No domain separation
		treeNoSep, err := New(&Config{DomainSeperation: false}, input)
		require.NoError(t, err)

		// With domain separation
		treeSep, err := New(&Config{DomainSeperation: true}, input)
		require.NoError(t, err)

		// Leaf hashes should differ when prefix is applied
		for i := 0; i < len(input); i++ {
			assert.NotEqual(t, treeNoSep.Leaves[i], treeSep.Leaves[i],
				"leaf %d should differ with domain separation", i)
		}

		// Roots should also differ in most cases
		assert.NotEqual(t, treeNoSep.Root, treeSep.Root,
			"roots should differ when domain separation is toggled")
	})

	t.Run("XXH128 vs XXH64 produces different roots", func(t *testing.T) {
		input := generateRandomLeaves(t, 4)

		tree64, err := New(&Config{XXH128: false}, input)
		require.NoError(t, err)

		tree128, err := New(&Config{XXH128: true}, input)
		require.NoError(t, err)

		assert.NotEqual(t, tree64.Root, tree128.Root,
			"roots should differ between 64-bit and 128-bit XXH3")
	})

	t.Run("leafMap is correctly populated", func(t *testing.T) {
		input := generateRandomLeaves(t, 3)
		tree, err := New(nil, input)
		require.NoError(t, err)

		for i, leaf := range tree.Leaves {
			idx, ok := tree.leafMap[string(leaf)]
			assert.True(t, ok, "leaf %d not found in leafMap", i)
			assert.Equal(t, i, idx, "wrong index in leafMap for leaf %d", i)
		}
	})
}
