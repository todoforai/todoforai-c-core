// Test harness for Noise primitives used by noise.c.
// Verifies BLAKE2b, HMAC-BLAKE2b, HKDF(BLAKE2b), and the derived
// "h_after_init" value against reference outputs computed with Python's
// hmac + hashlib.blake2b.
//
// Build:
//   cc -I. test_noise.c vendor/monocypher.c -o test_noise
// Run:
//   ./test_noise

#include "vendor/monocypher.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define HLEN   64
#define BLOCKB 128

static int hex_to_bytes(uint8_t *out, size_t out_len, const char *hex) {
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static int check_hex(const char *name, const uint8_t *got, size_t got_len, const char *expected_hex) {
    uint8_t exp[256];
    if (hex_to_bytes(exp, got_len, expected_hex) < 0) {
        printf("  [!] %s: bad expected hex (len=%zu)\n", name, got_len);
        return 1;
    }
    if (memcmp(got, exp, got_len) == 0) {
        printf("  [ok]   %s\n", name);
        return 0;
    }
    printf("  [FAIL] %s\n", name);
    printf("    got = ");
    for (size_t i = 0; i < got_len; i++) printf("%02x", got[i]);
    printf("\n    exp = %s\n", expected_hex);
    return 1;
}

// ── HMAC-BLAKE2b (exact copy of logic in noise.c) ────────────────────────────

static void tst_hmac(uint8_t out[HLEN], const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len) {
    uint8_t ipad[BLOCKB], opad[BLOCKB], k[BLOCKB];
    memset(k, 0, BLOCKB);
    if (key_len > BLOCKB) crypto_blake2b(k, HLEN, key, key_len);
    else                  memcpy(k, key, key_len);

    for (int i = 0; i < BLOCKB; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    crypto_blake2b_ctx S;
    uint8_t inner[HLEN];
    crypto_blake2b_init(&S, HLEN);
    crypto_blake2b_update(&S, ipad, BLOCKB);
    crypto_blake2b_update(&S, data, data_len);
    crypto_blake2b_final(&S, inner);

    crypto_blake2b_init(&S, HLEN);
    crypto_blake2b_update(&S, opad, BLOCKB);
    crypto_blake2b_update(&S, inner, HLEN);
    crypto_blake2b_final(&S, out);
}

// ── HKDF-2 (Noise-style: 2 outputs from CK + IKM) ────────────────────────────

static void tst_hkdf2(const uint8_t ck[HLEN], const uint8_t *ikm, size_t ikm_len,
                      uint8_t out1[HLEN], uint8_t out2[HLEN]) {
    uint8_t prk[HLEN];
    tst_hmac(prk, ck, HLEN, ikm, ikm_len);
    uint8_t one = 0x01;
    tst_hmac(out1, prk, HLEN, &one, 1);
    uint8_t tmp[HLEN + 1];
    memcpy(tmp, out1, HLEN);
    tmp[HLEN] = 0x02;
    tst_hmac(out2, prk, HLEN, tmp, sizeof(tmp));
}

// ── Tests ────────────────────────────────────────────────────────────────────

static int test_blake2b(void) {
    printf("\n[BLAKE2b]\n");
    int fails = 0;
    uint8_t out[HLEN];

    crypto_blake2b(out, HLEN, (const uint8_t *)"", 0);
    fails += check_hex("blake2b(\"\")", out, HLEN,
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");

    crypto_blake2b(out, HLEN, (const uint8_t *)"abc", 3);
    fails += check_hex("blake2b(\"abc\")", out, HLEN,
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

    const char *pn = "Noise_NX_25519_ChaChaPoly_BLAKE2b";
    crypto_blake2b(out, HLEN, (const uint8_t *)pn, strlen(pn));
    fails += check_hex("blake2b(protocol_name)", out, HLEN,
        "076bcf76c93b48711b91a0414223f73abed0be1d1f3196f99fa59fb92195872c"
        "ae1fd449aa626e16fe5b554f8092b30591a6a66d1845d3e7a91a717269e2e24b");

    return fails;
}

static int test_hmac_blake2b(void) {
    printf("\n[HMAC-BLAKE2b]\n");
    int fails = 0;
    uint8_t out[HLEN];
    tst_hmac(out, (const uint8_t *)"key", 3,
             (const uint8_t *)"The quick brown fox jumps over the lazy dog", 43);
    fails += check_hex("hmac(\"key\",\"The quick...\")", out, HLEN,
        "92294f92c0dfb9b00ec9ae8bd94d7e7d8a036b885a499f149dfe2fd2199394aa"
        "af6b8894a1730cccb2cd050f9bcf5062a38b51b0dab33207f8ef35ae2c9df51b");
    return fails;
}

static int test_hkdf_blake2b(void) {
    printf("\n[HKDF-BLAKE2b]\n");
    int fails = 0;
    uint8_t ck[HLEN] = {0}, ikm[32], o1[HLEN], o2[HLEN];
    for (int i = 0; i < 32; i++) ikm[i] = (uint8_t)i;
    tst_hkdf2(ck, ikm, 32, o1, o2);
    fails += check_hex("hkdf(ck=0, ikm=0..31) out1", o1, HLEN,
        "5f00fc95cfc2e3645f60393222f709d9e4c41314a55392eb5c5b7b04e33096fd"
        "014a71113695694a85ad56af0bc25c94ff08bfd0dbc8bb5e2862aa4b983877a5");
    fails += check_hex("hkdf(ck=0, ikm=0..31) out2", o2, HLEN,
        "a5e3c028beff14c78b280cb3da7e47935530922fa7cbdebfdcb8d5564207ad22"
        "514c6c17bf2ebd1e5bfbbc84e8136f87cb9a6c79b74ab82c875a3d907c96d94a");
    return fails;
}

static int test_symmetric_init_state(void) {
    printf("\n[SymmetricState init + MixHash(prologue=[])]\n");
    int fails = 0;

    // Protocol name (34 bytes) <= HASHLEN (64): zero-pad into h0.
    // h_after_prologue = blake2b(h0 || "")
    const char *pn = "Noise_NX_25519_ChaChaPoly_BLAKE2b";
    uint8_t h0[HLEN];
    memset(h0, 0, HLEN);
    memcpy(h0, pn, strlen(pn));

    uint8_t h[HLEN];
    crypto_blake2b_ctx S;
    crypto_blake2b_init(&S, HLEN);
    crypto_blake2b_update(&S, h0, HLEN);
    crypto_blake2b_final(&S, h);

    fails += check_hex("h_after_prologue", h, HLEN,
        "305bf2f1cc890fdb6e02aa20fdfcaf6519c21e3132354e7223155af0dfe7ed7c"
        "7ca65981ee79c135a501527b4650aa8e0249a3b4005cedee3e945cf51b09a4ef");
    return fails;
}

int main(void) {
    int fails = 0;
    fails += test_blake2b();
    fails += test_hmac_blake2b();
    fails += test_hkdf_blake2b();
    fails += test_symmetric_init_state();

    printf("\n== %s (%d failure%s) ==\n",
           fails ? "FAIL" : "OK", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
