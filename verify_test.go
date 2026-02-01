package merkletree

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	t.Parallel()

	t.Run("successful verification - even count, no domain sep", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(&Config{DomainSeperation: false}, input)
		require.NoError(t, err)

		for i, data := range input {
			proof, err := tree.Proof(data)
			require.NoError(t, err)

			ok, err := tree.Verify(data, tree.Root, proof, &Config{DomainSeperation: false})
			require.NoError(t, err)
			assert.True(t, ok, "verification failed for leaf %d", i)
		}
	})

	t.Run("successful verification - odd count, with domain sep", func(t *testing.T) {
		input := generateRandomInputs(t, 5) // odd → last leaf duplicated
		tree, err := New(&Config{DomainSeperation: true}, input)
		require.NoError(t, err)

		// Especially test the last (duplicated) leaf
		for i, data := range input {
			proof, err := tree.Proof(data)
			require.NoError(t, err)

			ok, err := tree.Verify(data, tree.Root, proof, tree.Config) // use tree's own config
			require.NoError(t, err)
			assert.True(t, ok, "verification failed for leaf %d (odd count)", i)
		}
	})

	t.Run("fails with wrong leaf data", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(nil, input)
		require.NoError(t, err)

		proof, err := tree.Proof(input[1]) // proof for second leaf
		require.NoError(t, err)

		wrongData := generateRandomInputs(t, 1)[0]
		ok, err := tree.Verify(wrongData, tree.Root, proof, nil)
		require.NoError(t, err)
		assert.False(t, ok, "should fail with incorrect leaf data")
	})

	t.Run("fails with tampered sibling", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(nil, input)
		require.NoError(t, err)

		proof, err := tree.Proof(input[0])
		require.NoError(t, err)

		tampered := &Proof{
			Path:     proof.Path,
			Siblings: make([][]byte, len(proof.Siblings)),
		}
		copy(tampered.Siblings, proof.Siblings)
		tampered.Siblings[0] = bytes.Repeat([]byte{0xFF}, len(proof.Siblings[0])) // tamper

		ok, err := tree.Verify(input[0], tree.Root, tampered, nil)
		require.NoError(t, err)
		assert.False(t, ok, "should fail with tampered sibling")
	})

	t.Run("fails with wrong root", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(nil, input)
		require.NoError(t, err)

		proof, err := tree.Proof(input[0])
		require.NoError(t, err)

		wrongRoot := bytes.Repeat([]byte{0xAA}, len(tree.Root))
		ok, err := tree.Verify(input[0], wrongRoot, proof, nil)
		require.NoError(t, err)
		assert.False(t, ok, "should fail with incorrect root")
	})

	t.Run("fails when domain separation flag mismatches", func(t *testing.T) {
		input := generateRandomInputs(t, 4)
		tree, err := New(&Config{DomainSeperation: true}, input)
		require.NoError(t, err)

		proof, err := tree.Proof(input[0])
		require.NoError(t, err)

		// Verify with wrong flag
		ok, err := tree.Verify(input[0], tree.Root, proof, &Config{DomainSeperation: false})
		require.NoError(t, err)
		assert.False(t, ok, "should fail when domain separation flag doesn't match tree")
	})

	t.Run("input validation - nil cases", func(t *testing.T) {
		tree := &MerkleTree{} // dummy

		proof := &Proof{} // dummy

		// Nil input
		ok, err := tree.Verify(nil, []byte("root"), proof, nil)
		assert.False(t, ok)
		assert.ErrorIs(t, err, ErrInputIsNil)

		// Nil proof
		ok, err = tree.Verify([]byte("data"), []byte("root"), nil, nil)
		assert.False(t, ok)
		assert.ErrorIs(t, err, ErrProofIsNil)
	})

	t.Run("minimal tree (2 leaves) verifies correctly", func(t *testing.T) {
		input := generateRandomInputs(t, 2)
		tree, err := New(&Config{DomainSeperation: true}, input)
		require.NoError(t, err)

		for i, data := range input {
			proof, err := tree.Proof(data)
			require.NoError(t, err)

			ok, err := tree.Verify(data, tree.Root, proof, tree.Config)
			require.NoError(t, err)
			assert.True(t, ok, "minimal tree verification failed for leaf %d", i)
		}
	})
}
