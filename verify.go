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

	result := make([]byte, len(leaf))
	copy(result, leaf)

	path := proof.Index
	for _, sib := range proof.Siblings {
		var combined []byte

		if path&1 == 1 {
			// Right child: left = sibling, right = result
			if config.DomainSeperation {
				combined = concatBytes([]byte{nodePrefix}, concatBytes(sib, result))
			} else {
				combined = concatBytes(sib, result)
			}
		} else {
			// Left child: left = result, right = sibling
			if config.DomainSeperation {
				combined = concatBytes([]byte{nodePrefix}, concatBytes(result, sib))
			} else {
				combined = concatBytes(result, sib)
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
