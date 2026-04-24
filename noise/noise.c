// Noise_NX_25519_ChaChaPoly_BLAKE2b — C implementation
// Minimal initiator-side transport for bootstrap/client CLIs.

#include "noise.h"
#include "vendor/monocypher.h"
#include <string.h>
#include <stdint.h>

// BLAKE2b: HASHLEN=64, BLOCKBYTES=128 (vs BLAKE2s: 32 / 64).
#define BLAKE2B_BLOCKBYTES 128

#ifdef NOISE_DEBUG
#include <stdio.h>
static void dbg(const char *label, const uint8_t *b, size_t n) {
    fprintf(stderr, "[c]  %s = ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}
#else
#define dbg(l, b, n) ((void)0)
#endif

// ── Platform RNG ──────────────────────────────────────────────────────────────

#ifdef _WIN32
extern int __stdcall SystemFunction036(void *, unsigned long);
int noise_random(uint8_t *buf, size_t len) {
    return SystemFunction036(buf, (unsigned long)len) ? 0 : -1;
}
#elif defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
int noise_random(uint8_t *buf, size_t len) {
    while (len > 0) {
        long n = syscall(SYS_getrandom, buf, len, 0);
        if (n < 0) return -1;
        buf += n; len -= (size_t)n;
    }
    return 0;
}
#else  // macOS, BSD
#include <stdlib.h>
int noise_random(uint8_t *buf, size_t len) {
    arc4random_buf(buf, len);
    return 0;
}
#endif

// ── Crypto helpers ────────────────────────────────────────────────────────────

void noise_wipe(void *buf, size_t len) {
    crypto_wipe(buf, len);
}

static void noise_hash(uint8_t out[NOISE_HASH_LEN], const void *data, size_t len) {
    crypto_blake2b(out, NOISE_HASH_LEN, data, len);
}

static void noise_hmac(uint8_t out[NOISE_HASH_LEN], const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len) {
    uint8_t ipad[BLAKE2B_BLOCKBYTES], opad[BLAKE2B_BLOCKBYTES], k[BLAKE2B_BLOCKBYTES];
    memset(k, 0, BLAKE2B_BLOCKBYTES);
    if (key_len > BLAKE2B_BLOCKBYTES) noise_hash(k, key, key_len);
    else                              memcpy(k, key, key_len);

    for (int i = 0; i < BLAKE2B_BLOCKBYTES; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    crypto_blake2b_ctx S;
    uint8_t inner[NOISE_HASH_LEN];
    crypto_blake2b_init(&S, NOISE_HASH_LEN);
    crypto_blake2b_update(&S, ipad, BLAKE2B_BLOCKBYTES);
    crypto_blake2b_update(&S, data, data_len);
    crypto_blake2b_final(&S, inner);

    crypto_blake2b_init(&S, NOISE_HASH_LEN);
    crypto_blake2b_update(&S, opad, BLAKE2B_BLOCKBYTES);
    crypto_blake2b_update(&S, inner, NOISE_HASH_LEN);
    crypto_blake2b_final(&S, out);

    crypto_wipe(k, BLAKE2B_BLOCKBYTES);
    crypto_wipe(inner, NOISE_HASH_LEN);
}

// Noise HKDF with BLAKE2b: each output block is HASHLEN=64 bytes.
// ck stays HASHLEN; cipher keys are TRUNCATE(block, 32) at call sites.
static void noise_hkdf2(const uint8_t ck[NOISE_HASH_LEN], const uint8_t *ikm, size_t ikm_len,
                         uint8_t out1[NOISE_HASH_LEN], uint8_t out2[NOISE_HASH_LEN]) {
    uint8_t prk[NOISE_HASH_LEN];
    noise_hmac(prk, ck, NOISE_HASH_LEN, ikm, ikm_len);

    uint8_t one = 0x01;
    noise_hmac(out1, prk, NOISE_HASH_LEN, &one, 1);

    uint8_t tmp[NOISE_HASH_LEN + 1];
    memcpy(tmp, out1, NOISE_HASH_LEN);
    tmp[NOISE_HASH_LEN] = 0x02;
    noise_hmac(out2, prk, NOISE_HASH_LEN, tmp, sizeof(tmp));

    crypto_wipe(prk, NOISE_HASH_LEN);
}

// Returns 0 on success, -1 if DH produced all-zero output (weak/invalid key)
static int noise_dh(uint8_t out[32], const uint8_t secret[32], const uint8_t pub[32]) {
    crypto_x25519(out, secret, pub);
    // Reject all-zero shared secret (low-order point / invalid key)
    uint8_t zero[32] = {0};
    if (crypto_verify32(out, zero) == 0) {
        crypto_wipe(out, 32);
        return -1;
    }
    return 0;
}

// ── CipherState ───────────────────────────────────────────────────────────────

// `key`, if non-NULL, must point to NOISE_KEY_LEN (32) bytes.
static void cipher_init(noise_cipher_state_t *cs, const uint8_t *key) {
    if (key) {
        memcpy(cs->key, key, NOISE_KEY_LEN);
        cs->has_key = 1;
    } else {
        cs->has_key = 0;
    }
    cs->nonce = 0;
}

static void cipher_nonce_bytes(const noise_cipher_state_t *cs, uint8_t nonce[12]) {
    memset(nonce, 0, 12);
    uint64_t n = cs->nonce;
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(n & 0xff);
        n >>= 8;
    }
}

static int cipher_encrypt(noise_cipher_state_t *cs, uint8_t *out, size_t out_cap,
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t *pt, size_t pt_len) {
    if (!cs->has_key) {
        if (out_cap < pt_len) return -1;
        memcpy(out, pt, pt_len);
        return (int)pt_len;
    }
    if (cs->nonce == UINT64_MAX) return -1;  // nonce exhaustion
    if (out_cap < pt_len + NOISE_TAG_LEN) return -1;

    uint8_t nonce[12];
    cipher_nonce_bytes(cs, nonce);

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, cs->key, nonce);
    crypto_aead_write(&ctx, out, out + pt_len, ad, ad_len, pt, pt_len);
    crypto_wipe(&ctx, sizeof(ctx));
    cs->nonce++;
    return (int)(pt_len + NOISE_TAG_LEN);
}

static int cipher_decrypt(noise_cipher_state_t *cs, uint8_t *out, size_t out_cap,
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t *ct, size_t ct_len) {
    if (!cs->has_key) {
        if (out_cap < ct_len) return -1;
        memcpy(out, ct, ct_len);
        return (int)ct_len;
    }
    if (cs->nonce == UINT64_MAX) return -1;  // nonce exhaustion
    if (ct_len < NOISE_TAG_LEN) return -1;
    size_t pt_len = ct_len - NOISE_TAG_LEN;
    if (out_cap < pt_len) return -1;

    uint8_t nonce[12];
    cipher_nonce_bytes(cs, nonce);

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, cs->key, nonce);
    if (crypto_aead_read(&ctx, out, ct + pt_len, ad, ad_len, ct, pt_len) != 0) {
        crypto_wipe(&ctx, sizeof(ctx));
        return -1;
    }
    crypto_wipe(&ctx, sizeof(ctx));
    cs->nonce++;
    return (int)pt_len;
}

// ── SymmetricState ────────────────────────────────────────────────────────────

static const char PROTOCOL_NAME[] = "Noise_NX_25519_ChaChaPoly_BLAKE2b";

static void symmetric_init(noise_symmetric_state_t *ss) {
    // protocol_name (34 bytes) <= HASHLEN (64): zero-pad into h.
    memset(ss->h, 0, NOISE_HASH_LEN);
    memcpy(ss->h, PROTOCOL_NAME, sizeof(PROTOCOL_NAME) - 1);
    memcpy(ss->ck, ss->h, NOISE_HASH_LEN);
    cipher_init(&ss->cipher, NULL);
    dbg("h_after_init", ss->h, NOISE_HASH_LEN);
}

static void symmetric_mix_hash(noise_symmetric_state_t *ss, const uint8_t *data, size_t len) {
    crypto_blake2b_ctx S;
    crypto_blake2b_init(&S, NOISE_HASH_LEN);
    crypto_blake2b_update(&S, ss->h, NOISE_HASH_LEN);
    crypto_blake2b_update(&S, data, len);
    crypto_blake2b_final(&S, ss->h);
}

static void symmetric_mix_key(noise_symmetric_state_t *ss, const uint8_t *ikm, size_t ikm_len) {
    uint8_t out1[NOISE_HASH_LEN], out2[NOISE_HASH_LEN];
    dbg("mix_key ikm", ikm, ikm_len);
    noise_hkdf2(ss->ck, ikm, ikm_len, out1, out2);
    memcpy(ss->ck, out1, NOISE_HASH_LEN);
    // Cipher key = TRUNCATE(out2, 32) per Noise spec §5.3.
    cipher_init(&ss->cipher, out2);
    dbg("ck_after_mix", ss->ck, NOISE_HASH_LEN);
    dbg("k_after_mix", out2, NOISE_KEY_LEN);
    crypto_wipe(out1, NOISE_HASH_LEN);
    crypto_wipe(out2, NOISE_HASH_LEN);
}

static int symmetric_encrypt_and_hash(noise_symmetric_state_t *ss,
                                       uint8_t *out, size_t out_cap,
                                       const uint8_t *pt, size_t pt_len) {
    int ct_len = cipher_encrypt(&ss->cipher, out, out_cap, ss->h, NOISE_HASH_LEN, pt, pt_len);
    if (ct_len < 0) return -1;
    symmetric_mix_hash(ss, out, (size_t)ct_len);
    return ct_len;
}

static int symmetric_decrypt_and_hash(noise_symmetric_state_t *ss,
                                       uint8_t *out, size_t out_cap,
                                       const uint8_t *ct, size_t ct_len) {
    int pt_len = cipher_decrypt(&ss->cipher, out, out_cap, ss->h, NOISE_HASH_LEN, ct, ct_len);
    if (pt_len < 0) return -1;
    symmetric_mix_hash(ss, ct, ct_len);
    return pt_len;
}

static void symmetric_split(const noise_symmetric_state_t *ss,
                             noise_cipher_state_t *initiator,
                             noise_cipher_state_t *responder) {
    // Split: both HKDF outputs become cipher keys (each truncated to 32).
    uint8_t out1[NOISE_HASH_LEN], out2[NOISE_HASH_LEN];
    noise_hkdf2(ss->ck, (const uint8_t *)"", 0, out1, out2);
    cipher_init(initiator, out1);
    cipher_init(responder, out2);
    crypto_wipe(out1, NOISE_HASH_LEN);
    crypto_wipe(out2, NOISE_HASH_LEN);
}

// ── HandshakeState (NX initiator only) ────────────────────────────────────────

void noise_keypair_from_secret(noise_keypair_t *kp, const uint8_t secret[32]) {
    memcpy(kp->secret_key, secret, 32);
    crypto_x25519_public_key(kp->public_key, secret);
}

int noise_handshake_init(noise_handshake_t *hs,
                         const uint8_t remote_static_pub[32]) {
    memset(hs, 0, sizeof(*hs));
    memcpy(hs->rs, remote_static_pub, 32);
    symmetric_init(&hs->symmetric);
    // MixHash(prologue) — Noise spec requires this after initializing the symmetric state.
    // We don't support non-empty prologues, but MixHash([]) still updates h.
    symmetric_mix_hash(&hs->symmetric, (const uint8_t *)"", 0);
    dbg("h_after_prologue", hs->symmetric.h, NOISE_HASH_LEN);
    return 0;
}

// NX message 0 (initiator → responder): tokens = [e]
int noise_handshake_write(noise_handshake_t *hs,
                          const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap) {
    (void)payload;
    (void)payload_len;
#ifdef NOISE_TEST_HOOKS
    int fixed_e = (hs->message_index == -1);
    if (hs->complete || (hs->message_index != 0 && !fixed_e)) return -1;
#else
    if (hs->complete || hs->message_index != 0) return -1;
#endif
    if (out_cap < 32) return -1;
#ifdef NOISE_TEST_HOOKS
    if (!fixed_e)
#endif
    {
        if (noise_random(hs->e.secret_key, 32) < 0) return -1;
        crypto_x25519_public_key(hs->e.public_key, hs->e.secret_key);
    }
    dbg("our_e_pub", hs->e.public_key, 32);
    memcpy(out, hs->e.public_key, 32);
    symmetric_mix_hash(&hs->symmetric, hs->e.public_key, 32);
    // Per Noise spec, every message ends with EncryptAndHash(payload).
    // With no cipher key and empty payload, this reduces to MixHash(empty).
    symmetric_mix_hash(&hs->symmetric, (const uint8_t *)"", 0);
    dbg("h_after_our_e", hs->symmetric.h, NOISE_HASH_LEN);
    hs->message_index = 1;
    return 32;
}

// NX message 1 (responder → initiator): tokens = [e, ee, s, es]
int noise_handshake_read(noise_handshake_t *hs,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *out, size_t out_cap) {
    if (hs->complete || hs->message_index != 1) return -1;
    if (msg_len < 32 + 48 + 16) return -1;
    size_t off = 0;

    memcpy(hs->re, msg + off, 32);
    dbg("recv re", hs->re, 32);
    symmetric_mix_hash(&hs->symmetric, hs->re, 32);
    dbg("h_after_re", hs->symmetric.h, NOISE_HASH_LEN);
    off += 32;

    uint8_t dh_result[32], remote_static[32];
    if (noise_dh(dh_result, hs->e.secret_key, hs->re) < 0) return -1;
    dbg("ee_dh", dh_result, 32);
    symmetric_mix_key(&hs->symmetric, dh_result, 32);

    dbg("s_ct", msg + off, 48);
    dbg("h_before_decrypt_s", hs->symmetric.h, NOISE_HASH_LEN);
    int s_len = symmetric_decrypt_and_hash(&hs->symmetric, remote_static, sizeof(remote_static),
                                           msg + off, 48);
    dbg("s_len_bytes", (const uint8_t *)&s_len, sizeof(s_len));
    dbg("decrypted_rs", remote_static, 32);
    dbg("expected_rs", hs->rs, 32);
    if (s_len != 32) return -1;
    off += 48;
    if (crypto_verify32(remote_static, hs->rs) != 0) return -1;

    if (noise_dh(dh_result, hs->e.secret_key, remote_static) < 0) return -1;
    symmetric_mix_key(&hs->symmetric, dh_result, 32);
    crypto_wipe(dh_result, 32);
    crypto_wipe(remote_static, 32);

    dbg("payload_ct", msg + off, msg_len - off);
    dbg("h_before_decrypt_payload", hs->symmetric.h, NOISE_HASH_LEN);
    int pt_len = symmetric_decrypt_and_hash(&hs->symmetric, out, out_cap, msg + off, msg_len - off);
    dbg("payload_decrypt_rc", (const uint8_t *)&pt_len, sizeof(pt_len));
    if (pt_len < 0) return -1;

    hs->message_index = 2;
    hs->complete = 1;
    return pt_len;
}

int noise_handshake_split(const noise_handshake_t *hs, noise_transport_t *transport) {
    if (!hs->complete) return -1;
    noise_cipher_state_t initiator, responder;
    symmetric_split(&hs->symmetric, &initiator, &responder);
    transport->send = initiator;
    transport->recv = responder;
    return 0;
}

int noise_transport_write(noise_transport_t *t,
                          uint8_t *out, size_t out_cap,
                          const uint8_t *plaintext, size_t pt_len) {
    return cipher_encrypt(&t->send, out, out_cap, (const uint8_t *)"", 0, plaintext, pt_len);
}

int noise_transport_read(noise_transport_t *t,
                         uint8_t *out, size_t out_cap,
                         const uint8_t *ciphertext, size_t ct_len) {
    return cipher_decrypt(&t->recv, out, out_cap, (const uint8_t *)"", 0, ciphertext, ct_len);
}

#ifdef NOISE_TEST_HOOKS
void noise_handshake_set_fixed_ephemeral(noise_handshake_t *hs, const uint8_t priv[32]) {
    memcpy(hs->e.secret_key, priv, 32);
    crypto_x25519_public_key(hs->e.public_key, hs->e.secret_key);
    hs->message_index = -1;  // sentinel: "fixed ephemeral set, skip RNG"
}

void noise_handshake_debug_state(const noise_handshake_t *hs,
                                 uint8_t h_out[NOISE_HASH_LEN], uint8_t ck_out[NOISE_HASH_LEN],
                                 uint8_t k_out[NOISE_KEY_LEN], int *has_key_out) {
    memcpy(h_out, hs->symmetric.h, NOISE_HASH_LEN);
    memcpy(ck_out, hs->symmetric.ck, NOISE_HASH_LEN);
    memcpy(k_out, hs->symmetric.cipher.key, NOISE_KEY_LEN);
    *has_key_out = hs->symmetric.cipher.has_key;
}
#endif
