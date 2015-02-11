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

void seed_to_scalar(u8 *res, const u8 *seed) {
  crypto_hash(d, seed, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;
}

int crypto_p2es_keygen(u8 *pk, u8 *server, u8 *client, const u8 *server_seed, const u8 *client_seed) {
  gf a,b;
  gf p[4];

  crypto_hash(server, server_seed, 32);
  crypto_hash(client, client_seed, 32);

  // Guarantee that when server and client are added together that the
  // result has bottom 3 bits clear, top bit clear, next-to-top bit set.
  server[0]  &= 248;
  client[0]  &= 248;
  server[31] &= 31;
  client[31] &= 127;
  client[31] |= 64;

  seed_to_scalar(server, server_seed);
  seed_to_scalar(client, client_seed);
  pack25519(a, server);
  pack25519(b, client);
  A(a,b);
  scalarbase(p, a);
  pack(pk, p);
}

int p2es_scalarmult(gf result[4], const u8 *receiver_public, const u8 *sender_private) {
  gf receiver_unpacked[4];
  if (unpackneg(receiver_unpacked, receiver_public) < 0) return -1;
  scalarmult(result, receiver_unpacked, sender_private);
  return 0;
}

int crypto_p2es_server(u8 *r, const u8 *receiver_public, const u8 *sender_private) {
  gf tmp[4];
  if (p2es_scalarmult(tmp, receiver_public, sender_private) < 0) return -1;
  pack(r, tmp);
  return 0;
}

int crypto_p2es_client(u8 *r, const u8 *server, const u8 *receiver_public, const u8 *sender_private) {
  gf a[4];
  gf b[4];
  u8 sk[32];
  if (unpackneg(a, server) < 0) return -1;
  if (p2es_scalarmult(b, receiver_public, sender_private) < 0) return -1;
  add(a,b);
  pack(sk, a);
  return crypto_core_hsalsa20(r, _0, sk, sigma);
}

void crypto_p2es_client_refresh(u8 *r, const u8 *key, const u8 *delta) {

  A(r, key, delta)
}

void crypto_p2es_server_refresh(u8 *r, const u8 *key, const u8 *delta) {
  Z(r, key, delta)
}
