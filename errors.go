package merkletree

import "errors"

var (
	ErrInvalidNumOfLeaves = errors.New("the number of leaves must be greater than 0")
	ErrProofInvalidLeaf   = errors.New("this leaf is not a member of the merkle tree")
	ErrProofInvalidIndex  = errors.New("there is no leaf for the given index")
	ErrInputIsNil         = errors.New("input is nil")
	ErrProofIsNil         = errors.New("proof is nil")
)
