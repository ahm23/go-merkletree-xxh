package merkletree

import "errors"

type Proof struct {
	Siblings [][]byte
	Index    uint64
}

// Generates the Merkle proof for a leaf input using the previously generated Merkle tree structure.
func (m *MerkleTree) ProofFromInput(input []byte) (*Proof, error) {
	leaf, err := sproutLeaf(input, m.hashFunc, m.DomainSeperation)
	if err != nil {
		return nil, err
	}
	return m.ProofFromLeaf(leaf)
}

func (m *MerkleTree) ProofFromLeaf(leaf []byte) (*Proof, error) {
	idx, ok := m.leafMap[string(leaf)]
	if !ok {
		return nil, ErrProofInvalidLeaf
	}
	return m.Proof(idx)
}

func (m *MerkleTree) Proof(index int) (*Proof, error) {
	var (
		path     uint64
		siblings = make([][]byte, m.Depth)
	)

	currentIdx := index
	for level := 0; level < m.Depth; level++ {
		levelNodes := m.nodes[level]
		levelLen := len(levelNodes)

		var siblingIdx int
		isRightChild := currentIdx&1 == 1

		if isRightChild {
			path |= (1 << level) // bit 1 = right child (sibling left)
			siblingIdx = currentIdx - 1
		} else {
			// left child (bit 0 = sibling right)
			siblingIdx = currentIdx + 1
		}

		// Handle duplication edge case: if siblingIdx points to a duplicate (same as current)
		// In duplicate style, this happens when currentIdx is the original last odd index,
		// but since nodes[level] already has duplicate appended, sibling is valid and equal to leaf
		if siblingIdx >= levelLen {
			// This should NOT happen with duplication — but safety check
			return nil, errors.New("sibling index out of bounds - duplication bug?")
		}

		siblings[level] = levelNodes[siblingIdx]

		// For next level: parent index
		currentIdx >>= 1
	}

	return &Proof{
		Index:    path,
		Siblings: siblings,
	}, nil
}
