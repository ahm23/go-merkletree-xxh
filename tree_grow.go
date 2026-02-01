package merkletree

// builds the Merkle tree
func (m *MerkleTree) grow() (err error) {
	m.nodes = make([][][]byte, m.Depth)
	m.nodes[0] = make([][]byte, m.LeafCount)
	copy(m.nodes[0], m.Leaves)

	for i := 0; i < m.Depth-1; i++ {
		m.nodes[i] = appendNodeIfOdd(m.nodes[i])
		nodeCount := len(m.nodes[i])
		m.nodes[i+1] = make([][]byte, nodeCount>>1)

		for j := 0; j < nodeCount; j += 2 {
			raw := concatBytes(m.nodes[i][j], m.nodes[i][j+1])
			if m.DomainSeperation {
				raw = concatBytes([]byte{nodePrefix}, raw)
			}

			if m.nodes[i+1][j>>1], err = m.hashFunc(raw); err != nil {
				return err
			}
		}
	}

	// Final root computation — apply domain separation here too for consistency
	rootInput := concatBytes(m.nodes[m.Depth-1][0], m.nodes[m.Depth-1][1])
	if m.DomainSeperation {
		rootInput = concatBytes([]byte{nodePrefix}, rootInput)
	}

	if m.Root, err = m.hashFunc(rootInput); err != nil {
		return err
	}

	return err
}

// computes the leaf nodes from the input data
func (m *MerkleTree) computeLeafNodes(input [][]byte) ([][]byte, error) {
	var (
		leaves = make([][]byte, m.LeafCount)
		err    error
	)

	for i := 0; i < m.LeafCount; i++ {
		if leaves[i], err = sproutLeaf(input[i], m.hashFunc, m.DomainSeperation); err != nil {
			return nil, err
		}
		m.leafMap[string(leaves[i])] = i
	}

	return leaves, nil
}

func sproutLeaf(data []byte, hashFunc TypeHashFunc, domainSeparation bool) ([]byte, error) {
	input := data
	if domainSeparation {
		input = make([]byte, 1+len(data))
		input[0] = leafPrefix
		copy(input[1:], data)
	}

	return hashFunc(input)
}

func appendNodeIfOdd(input [][]byte) [][]byte {
	if len(input)%2 == 0 {
		return input
	}
	return append(input, input[len(input)-1])
}
