package tweetnacl

type u8 byte
type u32 uint32
type u64 uint64
type i64 int64
type gf [16]i64

var _0 [16]u8
var _9 [32]u8 = [32]u8{
	9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

var gf0 gf
var gf1 gf = gf{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

var _121665 gf = gf{0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var D gf = gf{0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203}
var D2 gf = gf{0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406}
var X gf = gf{0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169}
var Y gf = gf{0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666}
var I gf = gf{0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83}

// L32 is rotate 32-bit integer left
func L32(x u32, c uint) u32 { return (x << c) | ((x & 0xffffffff) >> (32 - c)) }

// ld32 is load 32-bit integer little-endian
func ld32(x [4]u8) u32 {
	u := u32(x[3])
	u = (u << 8) | u32(x[2])
	u = (u << 8) | u32(x[1])
	return (u << 8) | u32(x[0])
}

// dl64 is load 64-bit integer big-endian
func dl64(x [8]u8) u64 {
	var u u64
	for i := 0; i < 8; i++ {
		u = (u << 8) | u64(x[i])
	}
	return u
}

// st32 is store 32-bit integer little-endian
func st32(x [4]u8, u u32) {
	for i := 0; i < 4; i++ {
		x[i] = u8(u)
		u >>= 8
	}
}

// ts64 is store 64-bit integer big-endian
func ts64(x [8]u8, u u64) {
	for i := 7; i >= 0; i-- {
		x[i] = u8(u)
		u >>= 8
	}
}

// vn is merged crypto_verify_16, crypto_verify_32
func vn(x []u8, y []u8, n int) u32 {
	if len(x) != n {
		return 0
	}
	if len(y) != n {
		return 0
	}

	var d u32
	for i := 0; i < n; i++ {
		d |= u32(x[i]) ^ u32(y[i])
	}
	return (1 & ((d - 1) >> 8)) - 1
}

func crypto_verify_16(x [16]u8, y [16]u8) u32 {
	return vn(x[:], y[:], 16)
}

func crypto_verify_32(x [32]u8, y [32]u8) u32 {
	return vn(x[:], y[:], 32)
}
