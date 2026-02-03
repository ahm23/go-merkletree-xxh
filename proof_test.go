package merkletree

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProof(t *testing.T) {
	t.Parallel()

	t.Run("rejects unknown leaf", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(nil, input)
		require.NoError(t, err)

		unknown := []byte("not-in-tree")
		proof, err := tree.ProofFromInput(unknown)
		assert.ErrorIs(t, err, ErrProofInvalidLeaf)
		assert.Nil(t, proof)
	})

	t.Run("generates valid proof for each leaf (even count, no domain sep)", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(&Config{DomainSeperation: false}, input)
		require.NoError(t, err)

		for i, data := range input {
			proof, err := tree.ProofFromInput(data)
			require.NoError(t, err, "proof for leaf %d", i)
			require.NotNil(t, proof)
			assert.Len(t, proof.Siblings, tree.Depth)
			assert.NotEmpty(t, proof.Siblings)

			// Verify using your Verify func
			ok, err := tree.Verify(data, tree.Root, proof, &Config{DomainSeperation: false})
			require.NoError(t, err)
			assert.True(t, ok, "verification failed for leaf %d", i)
		}
	})

	t.Run("proof verification succeeds with domain separation enabled", func(t *testing.T) {
		input := generateRandomInputs(t, 5) // odd count to test duplication
		tree, err := New(&Config{DomainSeperation: true}, input)
		require.NoError(t, err)

		for i, data := range input {
			proof, err := tree.ProofFromInput(data)
			require.NoError(t, err)

			ok, err := tree.Verify(data, tree.Root, proof, &Config{DomainSeperation: true})
			require.NoError(t, err)
			assert.True(t, ok, "domain sep: verification failed for leaf %d", i)
		}
	})

	t.Run("proof fails verification when leaf is wrong", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(nil, input)
		require.NoError(t, err)

		proof, err := tree.ProofFromInput(input[0])
		require.NoError(t, err)

		// Wrong data
		wrongData := generateRandomInputs(t, 1)[0]
		ok, err := tree.Verify(wrongData, tree.Root, proof, nil)
		require.NoError(t, err)
		assert.False(t, ok, "should fail for wrong leaf data")
	})

	t.Run("proof fails when sibling tampered", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(nil, input)
		require.NoError(t, err)

		proof, err := tree.ProofFromInput(input[0])
		require.NoError(t, err)

		// Tamper with first sibling
		tamperedProof := &Proof{
			Index:    proof.Index,
			Siblings: make([][]byte, len(proof.Siblings)),
		}
		copy(tamperedProof.Siblings, proof.Siblings)
		tamperedProof.Siblings[0] = bytes.Repeat([]byte{0xAA}, 32) // arbitrary tamper

		ok, err := tree.Verify(input[0], tree.Root, tamperedProof, nil)
		require.NoError(t, err)
		assert.False(t, ok, "should fail with tampered sibling")
	})

	t.Run("proof fails with wrong root", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(nil, input)
		require.NoError(t, err)

		proof, err := tree.ProofFromInput(input[0])
		require.NoError(t, err)

		wrongRoot := bytes.Repeat([]byte{0xFF}, len(tree.Root))
		ok, err := tree.Verify(input[0], wrongRoot, proof, nil)
		require.NoError(t, err)
		assert.False(t, ok, "should fail with incorrect root")
	})

	t.Run("proof path and siblings correct length", func(t *testing.T) {
		tests := []int{2, 3, 4, 8, 9}
		for _, n := range tests {
			input := generateRandomInputs(t, n)
			tree, err := New(nil, input)
			require.NoError(t, err)

			// Pick a random leaf index
			proof, err := tree.ProofFromInput(input[0])
			require.NoError(t, err)

			assert.Len(t, proof.Siblings, tree.Depth, "siblings length mismatch for %d leaves", n)
			// Index should have at most Depth bits set
			assert.True(t, proof.Index < (1<<tree.Depth), "path too large")
		}
	})
}
