package battcrypt

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"unsafe"

	"golang.org/x/crypto/blowfish"
)

const size = sha512.Size * 32

var ErrUpgradeInvalid = errors.New("battcrypt: new upgrade cost must be higher than old upgrade cost")
var ErrCostRange = errors.New("battcrypt: a cost was outside of the acceptable range")

const MaxTime = 62
const MaxUpgrade = 63
const MaxMemory = 50

func costs(t_cost_1, t_cost_2, m_cost uint64) (t_cost_main, t_cost_upgrade, mem_size uint64, err error) {
	if t_cost_1 > MaxTime || t_cost_2 > MaxUpgrade || m_cost > MaxMemory {
		return 0, 0, 0, ErrCostRange
	}
	t_cost_main = uint64(t_cost_1&1+2) << (t_cost_1 >> 1)
	t_cost_upgrade = 1
	if t_cost_2 != 0 {
		t_cost_upgrade = uint64(3-t_cost_2&1) << ((t_cost_2 - 1) >> 1)
	}
	mem_size = 4 << m_cost
	return
}

func BATTCrypt(password, salt []byte, time, upgrade, memory uint64) (key [64]byte, err error) {
	t_cost_main, t_cost_upgrade, mem_size, err := costs(time, upgrade, memory)
	if err != nil {
		return
	}

	sha := sha512.New()

	data := make([]byte, size*(mem_size+1))
	mem := make([][]byte, mem_size)
	for i := range mem {
		mem[i] = data[:size:size]
		data = data[size:]
	}

	key = sha512.Sum512(salt)
	key = sha512.Sum512(append(key[:], password...))
	for u := uint64(0); u < t_cost_upgrade; u++ {
		key = battcrypt(key, sha, data, mem, t_cost_main, mem_size)
	}

	return
}

var emptyIV = make([]byte, blowfish.BlockSize)

func battcrypt(key [64]byte, sha hash.Hash, data []byte, mem [][]byte, t_cost_main, mem_size uint64) [64]byte {
	// Initialize blowfish
	blow, err := blowfish.NewCipher(key[:56])
	if err != nil {
		// only possible error is invalid key size
		panic(err)
	}
	cbc := cipher.NewCBCEncrypter(blow, emptyIV)

	// Initialize data
	data = data[:0]
	for i := uint64(0); i < 32; i++ {
		sha.Reset()
		binary.Write(sha, binary.BigEndian, &i)
		sha.Write(key[:])
		data = sha.Sum(data)
	}

	// Initialize mem
	for i := uint64(0); i < mem_size; i++ {
		cbc.CryptBlocks(data, data)
		copy(mem[i], data)
	}
	cbc.CryptBlocks(data, data)

	// Main loop
	for i := uint64(0); i < t_cost_main; i++ {
		for j := uint64(0); j < mem_size; j++ {
			r := binary.BigEndian.Uint64(data[size-8:]) & (mem_size - 1)
			fast_xor(mem[j], mem[j], mem[r])
			fast_xor(mem[j], mem[j], data)
			cbc.CryptBlocks(mem[j], mem[j])
			fast_xor(data, data, mem[j])
		}
	}

	// Finish
	sha.Reset()
	sha.Write(data)
	sha.Write(key[:])
	return sha512.Sum512(sha.Sum(nil))
}

func Strengthen(hash [64]byte, time, upgrade_old, upgrade_new, memory uint64) (key [64]byte, err error) {
	t_cost_main, t_cost_upgrade_old, mem_size, err := costs(time, upgrade_old, memory)
	if err != nil {
		return
	}
	_, t_cost_upgrade_new, _, err := costs(time, upgrade_new, memory)
	if err != nil {
		return
	}

	if t_cost_upgrade_old > t_cost_upgrade_new {
		err = ErrUpgradeInvalid
		return
	}
	key = hash
	if t_cost_upgrade_old == t_cost_upgrade_new {
		return
	}

	sha := sha512.New()

	data := make([]byte, size*(mem_size+1))
	mem := make([][]byte, mem_size)
	for i := range mem {
		mem[i] = data[:size:size]
		data = data[size:]
	}

	for u := t_cost_upgrade_old - 1; u < t_cost_upgrade_new; u++ {
		key = battcrypt(key, sha, data, mem, t_cost_main, mem_size)
	}

	return
}

// dst, x, and y must all be exactly size len.
func fast_xor(dst, x, y []byte) {
	const isize = size / unsafe.Sizeof(uint(0))
	idst := (*[isize]uint)(unsafe.Pointer(&dst[0]))
	ix := (*[isize]uint)(unsafe.Pointer(&x[0]))
	iy := (*[isize]uint)(unsafe.Pointer(&y[0]))

	for i := uintptr(0); i < isize; i++ {
		idst[i] = ix[i] ^ iy[i]
	}
}
