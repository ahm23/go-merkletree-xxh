package merkletree

// builds the Merkle tree (no duplication)
func (m *MerkleTree) grow() error {
	totalNodes := m.LeafCount
	for n := m.LeafCount; n > 1; n = (n + 1) >> 1 {
		totalNodes += (n + 1) >> 1
	}

	m.nodes = make([][][]byte, 0, m.Depth)
	level := m.Leaves

	// i tried to make this as efficient as possible, less allocs
	var concatBuf []byte

	for len(level) > 1 {
		m.nodes = append(m.nodes, level)
		nextLevel := make([][]byte, (len(level)+1)>>1)

		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				nextLevel[i>>1] = level[i]
				continue
			}

			left := level[i]
			right := level[i+1]

			// Use pre-sized buffer instead of allocating
			needed := len(left) + len(right)
			if m.DomainSeperation {
				needed++ // for prefix
			}

			if cap(concatBuf) < needed {
				concatBuf = make([]byte, needed)
			}
			raw := concatBuf[:needed]

			// Inline concatenation (no function call overhead)
			if m.DomainSeperation {
				raw[0] = nodePrefix
				copy(raw[1:], left)
				copy(raw[1+len(left):], right)
			} else {
				copy(raw, left)
				copy(raw[len(left):], right)
			}

			var err error
			nextLevel[i>>1], err = m.hashFunc(raw)
			if err != nil {
				return err
			}
		}

		level = nextLevel
	}

	m.nodes = append(m.nodes, level)
	m.Root = level[0]
	m.Depth = len(m.nodes)

	return nil
}

// computes the leaf nodes from the input data
func (m *MerkleTree) computeLeafNodes(input [][]byte) ([][]byte, error) {
	leaves := make([][]byte, m.LeafCount)

	for i := 0; i < m.LeafCount; i++ {
		var err error
		leaves[i], err = sproutLeaf(input[i], m.hashFunc, m.DomainSeperation)
		if err != nil {
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
