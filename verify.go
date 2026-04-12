package merkletree

import "bytes"

// Checks if the leaf data is valid for a given Merkle tree proof root hash.
func Verify(input []byte, root []byte, proof *Proof, config *Config) (bool, error) {
	if input == nil {
		return false, ErrInputIsNil
	}

	if proof == nil {
		return false, ErrProofIsNil
	}

	if config == nil {
		config = new(Config)
	}

	var hashFunc TypeHashFunc
	if config.XXH128 {
		hashFunc = xxh3Hash128
	} else {
		hashFunc = xxh3Hash64
	}

	leaf, err := sproutLeaf(input, hashFunc, config.DomainSeperation)
	if err != nil {
		return false, err
	}

	if len(proof.Siblings) == 0 {
		return bytes.Equal(leaf, root), nil
	}

	result := leaf
	path := proof.Index

	for _, sibling := range proof.Siblings {
		var combined []byte

		// least significant bit of the remaining path
		if path&1 == 1 {
			// right child, sibling on left
			if config.DomainSeperation {
				combined = concatBytes([]byte{nodePrefix}, concatBytes(sibling, result))
			} else {
				combined = concatBytes(sibling, result)
			}
		} else {
			// left child, sibling on right
			if config.DomainSeperation {
				combined = concatBytes([]byte{nodePrefix}, concatBytes(result, sibling))
			} else {
				combined = concatBytes(result, sibling)
			}
		}

		result, err = hashFunc(combined)
		if err != nil {
			return false, err
		}

		path >>= 1
	}

	return bytes.Equal(result, root), nil
}
