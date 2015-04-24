// Package battcrypt implements Steven Thomas's "Blowfish All The Things"
// cryptographic hash function.
//
// There are three costs that can be modified:
// - Time, with 0 being 2 iterations, 1 being 3, 2 being 4, 3 being 6, 4 being
//   8, 5 being 12, and so on.
// - Upgrade, with 0 being 1 iteration, 1 being 2, 2 being 3, 3 being 4, 4
//   being 6, 5 being 8, 6 being 12, and so on.
// - Memory, with each value above 0 taking twice as much memory as the
//   previous.
//
// If time and memory stay the same, upgrade can be increased without input
// from the user.
//
// For comparable complexity to bcrypt, set time to 1, upgrade to 0, and memory
// to bcrypt_cost - 2.
//
package battcrypt

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"unsafe"

	"github.com/BenLubar/battcrypt/blowfish"
)

// data block size
const size = sha512.Size * 32

var (
	ErrUpgradeInvalid = errors.New("battcrypt: new upgrade cost must be higher than old upgrade cost")
	ErrCostRange      = errors.New("battcrypt: a cost was outside of the acceptable range")
)

const (
	// time costs above MaxTime would overflow a uint64.
	MaxTime = 62
	// upgrade costs above MaxUpgrade would overflow a uint64.
	MaxUpgrade = 63
	// memory costs above MaxMemory would overflow a uint64.
	MaxMemory = 50
)

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

var blowPool = sync.Pool{
	New: func() interface{} {
		blow, err := blowfish.NewCipher(emptyKey)
		if err != nil {
			// only possible error is invalid key size
			panic(err)
		}
		return blow
	},
}

// BATTCrypt computes a cryptographic hash of password, salted by salt.
func BATTCrypt(password, salt []byte, time, upgrade, memory uint64) (key [64]byte, err error) {
	t_cost_main, t_cost_upgrade, mem_size, err := costs(time, upgrade, memory)
	if err != nil {
		return
	}

	sha := sha512.New()
	blow := blowPool.Get().(*blowfish.Cipher)
	defer blowPool.Put(blow)

	data := make([]byte, size*(mem_size+1))
	mem := make([][]byte, mem_size)
	for i := range mem {
		mem[i] = data[:size:size]
		data = data[size:]
	}

	sha.Reset()
	sha.Write(salt)
	sha.Sum(key[:0])

	sha.Reset()
	sha.Write(key[:])
	sha.Write(password)
	sha.Sum(key[:0])

	for u := uint64(0); u < t_cost_upgrade; u++ {
		key = battcrypt(key, sha, blow, data, mem, t_cost_main, mem_size)
	}

	return
}

var emptyKey = make([]byte, 56)
var emptyIV = make([]byte, blowfish.BlockSize)

func battcrypt(key [64]byte, sha hash.Hash, blow *blowfish.Cipher, data []byte, mem [][]byte, t_cost_main, mem_size uint64) [64]byte {
	var scratch [8]byte

	// Initialize blowfish
	err := blow.Reset(key[:56])
	if err != nil {
		// only possible error is invalid key size
		panic(err)
	}
	cbc := cipher.NewCBCEncrypter(blow, emptyIV)

	// Initialize data
	data = data[:0]
	for i := uint64(0); i < 32; i++ {
		sha.Reset()
		binary.BigEndian.PutUint64(scratch[:8], i)
		sha.Write(scratch[:8])
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
	sha.Sum(key[:0])

	sha.Reset()
	sha.Write(key[:])
	sha.Sum(key[:0])

	return key
}

// Strengthen can be used to increase the time complexity of a password hash
// without needing input from the user.
func Strengthen(old [64]byte, time, upgrade_old, upgrade_new, memory uint64) (key [64]byte, err error) {
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
	key = old
	if t_cost_upgrade_old == t_cost_upgrade_new {
		return
	}

	sha := sha512.New()
	blow := blowPool.Get().(*blowfish.Cipher)
	defer blowPool.Put(blow)

	data := make([]byte, size*(mem_size+1))
	mem := make([][]byte, mem_size)
	for i := range mem {
		mem[i] = data[:size:size]
		data = data[size:]
	}

	for u := t_cost_upgrade_old - 1; u < t_cost_upgrade_new; u++ {
		key = battcrypt(key, sha, blow, data, mem, t_cost_main, mem_size)
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
