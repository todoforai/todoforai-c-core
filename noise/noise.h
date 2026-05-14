// Noise_NX_25519_ChaChaPoly_BLAKE2b — C implementation
// Minimal initiator-side transport for bootstrap/client CLIs.

#ifndef NOISE_H
#define NOISE_H

#include <stdint.h>
#include <stddef.h>

#define NOISE_TAG_LEN  16
#define NOISE_HASH_LEN 64   // BLAKE2b-512 output size
#define NOISE_KEY_LEN  32   // ChaCha20-Poly1305 key size

typedef struct {
    uint8_t public_key[32];
    uint8_t secret_key[32];
} noise_keypair_t;

typedef struct {
    uint8_t key[NOISE_KEY_LEN];
    int     has_key;
    uint64_t nonce;
} noise_cipher_state_t;

typedef struct {
    uint8_t ck[NOISE_HASH_LEN];
    uint8_t h[NOISE_HASH_LEN];
    noise_cipher_state_t cipher;
} noise_symmetric_state_t;

typedef struct {
    noise_cipher_state_t send;
    noise_cipher_state_t recv;
} noise_transport_t;

typedef struct {
    noise_symmetric_state_t symmetric;
    uint8_t          rs[32];     // remote static public (pinned or learned)
    int              rs_pinned;  // 1: verify rs on msg2; 0: learn it (TOFU)
    noise_keypair_t  e;          // local ephemeral
    uint8_t          re[32];     // remote ephemeral public
    int              message_index;
    int              complete;
} noise_handshake_t;

// Initialize NX handshake as initiator.
// remote_static_pub != NULL: pin and verify on msg2 (normal connect).
// remote_static_pub == NULL: learn responder's static key on msg2 (TOFU,
//   used during credential acquisition). Caller reads it from `hs->rs`
//   after a successful `noise_handshake_read`.
int noise_handshake_init(noise_handshake_t *hs,
                         const uint8_t *remote_static_pub);

// Write handshake message, returns bytes written to out, or -1 on error
int noise_handshake_write(noise_handshake_t *hs,
                          const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap);

// Read handshake message, returns payload bytes written to out, or -1 on error
int noise_handshake_read(noise_handshake_t *hs,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *out, size_t out_cap);

// Split into transport state after handshake complete
int noise_handshake_split(const noise_handshake_t *hs, noise_transport_t *transport);

// Encrypt a transport message, returns bytes written or -1
int noise_transport_write(noise_transport_t *t,
                          uint8_t *out, size_t out_cap,
                          const uint8_t *plaintext, size_t pt_len);

// Decrypt a transport message, returns plaintext bytes or -1
int noise_transport_read(noise_transport_t *t,
                         uint8_t *out, size_t out_cap,
                         const uint8_t *ciphertext, size_t ct_len);

// Generate keypair from secret key (derive public via X25519)
void noise_keypair_from_secret(noise_keypair_t *kp, const uint8_t secret[32]);

#ifdef NOISE_TEST_HOOKS
// TEST-ONLY: override the ephemeral that noise_handshake_write will use.
// Must be called after noise_handshake_init, before noise_handshake_write.
void noise_handshake_set_fixed_ephemeral(noise_handshake_t *hs, const uint8_t priv[32]);

// TEST-ONLY: snapshot current SymmetricState (h, ck, k, has_key).
void noise_handshake_debug_state(const noise_handshake_t *hs,
                                 uint8_t h_out[NOISE_HASH_LEN], uint8_t ck_out[NOISE_HASH_LEN],
                                 uint8_t k_out[NOISE_KEY_LEN], int *has_key_out);
#endif

// Platform-native secure random. Returns 0 on success, -1 on failure.
int noise_random(uint8_t *buf, size_t len);

// Wipe sensitive memory.
void noise_wipe(void *buf, size_t len);

#endif
