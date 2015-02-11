
#include "_cgo_export.h"

int crypto_sign_keypair_seed(u8 *pk, u8 *sk, const u8 *seed) {
  u8 d[64];
  gf p[4];
  int i;

  crypto_hash(d, seed, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p,d);
  pack(pk,p);

  FOR(i,32) sk[i] = seed[i];
  FOR(i,32) sk[32 + i] = pk[i];
  return 0;
}

void randombytes(u8 *buf, u64 n) {
  RandomBytes(buf, n);
}