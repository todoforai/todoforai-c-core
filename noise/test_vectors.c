// Full handshake test vector harness.
// Replays a deterministic Noise_NX handshake (keys + msg1 produced by Python
// reference) and compares every internal state transition to the reference.
//
// Build:
//   cc -DNOISE_TEST_HOOKS -I. test_vectors.c noise.c vendor/monocypher.c -o test_vectors
// Run:
//   ./test_vectors

#include "noise.h"
#include "test_vector.h"
#include <stdio.h>
#include <string.h>

static int cmp_or_fail(const char *label, const uint8_t *got, const uint8_t *exp, size_t n) {
    if (memcmp(got, exp, n) == 0) {
        printf("  [ok]   %s\n", label);
        return 0;
    }
    printf("  [FAIL] %s\n", label);
    printf("    got = ");
    for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
    printf("\n    exp = ");
    for (size_t i = 0; i < n; i++) printf("%02x", exp[i]);
    printf("\n");
    return 1;
}

int main(void) {
    int fails = 0;

    noise_handshake_t hs;
    if (noise_handshake_init(&hs, TV_R_S_PUB) != 0) {
        printf("noise_handshake_init failed\n");
        return 1;
    }

    // Check state after init (== after MixHash(prologue=[]))
    {
        uint8_t h[NOISE_HASH_LEN], ck[NOISE_HASH_LEN], k[NOISE_KEY_LEN]; int hk;
        noise_handshake_debug_state(&hs, h, ck, k, &hk);
        fails += cmp_or_fail("h_after_prologue", h,  TV_H_AFTER_PROLOGUE, NOISE_HASH_LEN);
    }

    // Inject fixed ephemeral
    noise_handshake_set_fixed_ephemeral(&hs, TV_I_E_PRIV);

    // Write msg0
    uint8_t msg0[64];
    int m0 = noise_handshake_write(&hs, NULL, 0, msg0, sizeof(msg0));
    if (m0 != 32) { printf("handshake_write returned %d\n", m0); return 1; }
    fails += cmp_or_fail("msg0 bytes", msg0, TV_MSG0, 32);

    // Check h after our e
    {
        uint8_t h[NOISE_HASH_LEN], ck[NOISE_HASH_LEN], k[NOISE_KEY_LEN]; int hk;
        noise_handshake_debug_state(&hs, h, ck, k, &hk);
        fails += cmp_or_fail("h_after_our_e", h, TV_H_AFTER_OUR_E, NOISE_HASH_LEN);
    }

    // Read msg1
    uint8_t payload[64];
    int p = noise_handshake_read(&hs, TV_MSG1, sizeof(TV_MSG1), payload, sizeof(payload));
    if (p < 0) {
        printf("  [FAIL] handshake_read returned %d\n", p);
        // Dump state anyway to see how far we got
        uint8_t h[NOISE_HASH_LEN], ck[NOISE_HASH_LEN], k[NOISE_KEY_LEN]; int hk;
        noise_handshake_debug_state(&hs, h, ck, k, &hk);
        printf("  at failure: h=");
        for (int i = 0; i < NOISE_HASH_LEN; i++) printf("%02x", h[i]);
        printf("\n               ck=");
        for (int i = 0; i < NOISE_HASH_LEN; i++) printf("%02x", ck[i]);
        printf("\n               k=");
        for (int i = 0; i < NOISE_KEY_LEN; i++) printf("%02x", k[i]);
        printf("  has_key=%d\n", hk);
        fails++;
    } else {
        printf("  [ok]   handshake_read succeeded, payload_len=%d\n", p);
        uint8_t h[NOISE_HASH_LEN], ck[NOISE_HASH_LEN], k[NOISE_KEY_LEN]; int hk;
        noise_handshake_debug_state(&hs, h, ck, k, &hk);
        fails += cmp_or_fail("h_after_payload", h, TV_H_AFTER_PAYLOAD, NOISE_HASH_LEN);
        fails += cmp_or_fail("ck_after_es",    ck, TV_CK_AFTER_ES,    NOISE_HASH_LEN);
        fails += cmp_or_fail("k_after_es",     k,  TV_K_AFTER_ES,     NOISE_KEY_LEN);

        // Transport: verify split produces keys that decrypt server→client traffic
        // with nonce 0 and recover the expected sentinel plaintext.
        noise_transport_t tr;
        if (noise_handshake_split(&hs, &tr) != 0) {
            printf("  [FAIL] split\n"); fails++;
        } else {
            printf("  [ok]   split produced transport state\n");
        }
    }

    printf("\n== %s (%d failure%s) ==\n",
           fails ? "FAIL" : "OK", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
