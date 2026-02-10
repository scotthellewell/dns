package blocklist

import (
	"math"
	"sync"

	"github.com/spaolacci/murmur3"
)

// BloomFilter is a space-efficient probabilistic data structure for set membership testing.
type BloomFilter struct {
	mu      sync.RWMutex
	bits    []uint64
	size    uint64 // Number of bits
	hashNum uint   // Number of hash functions
	count   uint64 // Number of items added
}

// NewBloomFilter creates a new Bloom filter with the given expected number of items
// and desired false positive rate.
func NewBloomFilter(expectedItems int, fpRate float64) *BloomFilter {
	// Calculate optimal size and hash count
	// m = -n*ln(p) / (ln(2)^2)
	// k = (m/n) * ln(2)
	n := float64(expectedItems)
	if n < 1 {
		n = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01 // Default 1% false positive rate
	}

	m := -n * math.Log(fpRate) / (math.Ln2 * math.Ln2)
	k := (m / n) * math.Ln2

	size := uint64(math.Ceil(m))
	hashNum := uint(math.Ceil(k))
	if hashNum < 1 {
		hashNum = 1
	}

	// Round up to nearest 64 bits for efficient storage
	numWords := (size + 63) / 64

	return &BloomFilter{
		bits:    make([]uint64, numWords),
		size:    numWords * 64,
		hashNum: hashNum,
	}
}

// Add adds an item to the bloom filter.
func (bf *BloomFilter) Add(item string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	h1, h2 := bf.hash(item)
	for i := uint(0); i < bf.hashNum; i++ {
		pos := bf.position(h1, h2, i)
		bf.setBit(pos)
	}
	bf.count++
}

// MayContain returns true if the item might be in the set.
// False positives are possible, but false negatives are not.
func (bf *BloomFilter) MayContain(item string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	h1, h2 := bf.hash(item)
	for i := uint(0); i < bf.hashNum; i++ {
		pos := bf.position(h1, h2, i)
		if !bf.getBit(pos) {
			return false
		}
	}
	return true
}

// Count returns the number of items added to the filter.
func (bf *BloomFilter) Count() uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.count
}

// EstimatedFPRate returns the estimated false positive rate based on current fill.
func (bf *BloomFilter) EstimatedFPRate() float64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	// p = (1 - e^(-kn/m))^k
	k := float64(bf.hashNum)
	n := float64(bf.count)
	m := float64(bf.size)

	return math.Pow(1-math.Exp(-k*n/m), k)
}

// Clear resets the bloom filter.
func (bf *BloomFilter) Clear() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count = 0
}

// Size returns the size of the filter in bits.
func (bf *BloomFilter) Size() uint64 {
	return bf.size
}

// SizeBytes returns the size of the filter in bytes.
func (bf *BloomFilter) SizeBytes() uint64 {
	return bf.size / 8
}

// hash computes two 64-bit hashes for the item using MurmurHash3.
func (bf *BloomFilter) hash(item string) (uint64, uint64) {
	h1, h2 := murmur3.Sum128([]byte(item))
	return h1, h2
}

// position calculates the bit position for the i-th hash function.
// Uses the technique from "Less Hashing, Same Performance: Building a Better Bloom Filter"
func (bf *BloomFilter) position(h1, h2 uint64, i uint) uint64 {
	return (h1 + uint64(i)*h2) % bf.size
}

// setBit sets the bit at the given position.
func (bf *BloomFilter) setBit(pos uint64) {
	wordIdx := pos / 64
	bitIdx := pos % 64
	bf.bits[wordIdx] |= (1 << bitIdx)
}

// getBit gets the bit at the given position.
func (bf *BloomFilter) getBit(pos uint64) bool {
	wordIdx := pos / 64
	bitIdx := pos % 64
	return (bf.bits[wordIdx] & (1 << bitIdx)) != 0
}

// MergeFrom merges another bloom filter into this one.
// Both filters must have the same size and hash count.
func (bf *BloomFilter) MergeFrom(other *BloomFilter) error {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	if bf.size != other.size || bf.hashNum != other.hashNum {
		return &BloomFilterError{Message: "cannot merge bloom filters with different parameters"}
	}

	for i := range bf.bits {
		bf.bits[i] |= other.bits[i]
	}
	bf.count += other.count

	return nil
}

// BloomFilterError represents a bloom filter error.
type BloomFilterError struct {
	Message string
}

func (e *BloomFilterError) Error() string {
	return e.Message
}
