package merkletree

import (
	"encoding/binary"

	"github.com/zeebo/xxh3"
)

// concatBytes concatenates two byte slices.
func concatBytes(a, b []byte) []byte {
	output := make([]byte, len(a)+len(b))
	copy(output, a)
	copy(output[len(a):], b)
	return output
}

func xxh3Hash64(input []byte) ([]byte, error) {
	h64 := xxh3.Hash(input) // 64-bit default
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, h64)
	return buf, nil
}

func xxh3Hash128(input []byte) ([]byte, error) {
	h128 := xxh3.Hash128(input)
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], h128.Hi)
	binary.BigEndian.PutUint64(buf[8:16], h128.Lo)
	return buf, nil
}
