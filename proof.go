package merkletree

type Proof struct {
	Siblings [][]byte
	PathBits uint64
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
	if m.LeafCount == 1 {
		return &Proof{
			PathBits: 0,
			Siblings: [][]byte{},
		}, nil
	}

	var (
		path     uint64
		siblings = make([][]byte, 0)
	)

	currentIdx := index

	// traverse up to the level just below the root
	for level := 0; level < m.Depth-1; level++ {
		levelNodes := m.nodes[level]

		// determine sibling index
		var siblingIdx int
		isRightChild := currentIdx&1 == 1

		if isRightChild {
			siblingIdx = currentIdx - 1
		} else {
			siblingIdx = currentIdx + 1
		}

		// Only add sibling if it exists (handles carried-up nodes)
		if siblingIdx >= 0 && siblingIdx < len(levelNodes) {
			siblings = append(siblings, levelNodes[siblingIdx])

			// Set path bit for this level if we're a right child
			if isRightChild {
				path |= (1 << uint(len(siblings)-1))
			}
		}
		currentIdx >>= 1
	}

	return &Proof{
		PathBits: path,
		Siblings: siblings,
	}, nil
}
