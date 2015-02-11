
package tweetnacl

// #include "../c/tweetnacl.h"
import "C"

import (
	"unsafe"
	"crypto/rand"
	"log"
)	

type SignPublicKey [32]byte
type SignSecretKey [64]byte
type SignSeed [32]byte

func CryptoSignKeypairSeed(pub SignPublicKey, sec SignSecretKey, seed SignSeed) {
	C.crypto_sign_keypair_seed((*C.uchar)(unsafe.Pointer(&pub[0])),
		(*C.uchar)(unsafe.Pointer(&sec[0])),
		(*C.uchar)(unsafe.Pointer(&seed[0])))	
}

//export RandomBytes
func RandomBytes(cbuf *C.uchar, n C.int) {
	buf := C.GoBytes(unsafe.Pointer(cbuf), n)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf(err.Error())
		return
	}
	return
}

