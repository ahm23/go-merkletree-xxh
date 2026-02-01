package merkletree

type Proof struct {
	Siblings [][]byte
	Path     uint32
}

// Generates the Merkle proof for a leaf input using the previously generated Merkle tree structure.
func (m *MerkleTree) Proof(input []byte) (*Proof, error) {
	leaf, err := sproutLeaf(input, m.hashFunc, m.DomainSeperation)
	if err != nil {
		return nil, err
	}

	idx, ok := m.leafMap[string(leaf)]
	if !ok {
		return nil, ErrProofInvalidLeaf
	}

	var (
		path     uint32
		siblings = make([][]byte, m.Depth)
	)

	for i := 0; i < m.Depth; i++ {
		if idx&1 == 1 {
			siblings[i] = m.nodes[i][idx-1]
		} else {
			path += 1 << i
			siblings[i] = m.nodes[i][idx+1]
		}

		idx >>= 1
	}

	return &Proof{
		Path:     path,
		Siblings: siblings,
	}, nil
}
