#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>

// ============================================================
//  ENCRYPTION (AEAD e CBC)
// ============================================================
typedef enum {
    CIPHER_MODE_CBC,
    CIPHER_MODE_GCM,
    CIPHER_MODE_CCM,
} cipher_mode_t;

typedef struct {
    const char          *config_name;   // keyword nel file .ini
    const char          *ossl_name;     // per EVP_CIPHER_fetch()
    const EVP_CIPHER*  (*evp_fn)(void); // getter diretto, NULL se usi fetch
    uint16_t             iana_id;       // RFC 8247
    size_t               key_len;       // byte
    size_t               iv_len;        // byte
    size_t               icv_len;       // byte (tag per AEAD, 0 per CBC)
    cipher_mode_t        mode;
} enc_algo_t;

// ============================================================
//  PRF / HASH (usati sia come PRF che come integrity)
// ============================================================
typedef struct {
    const char          *config_name;
    const char          *ossl_name;     // per EVP_MD_fetch()
    const EVP_MD*      (*evp_fn)(void);
    uint16_t             iana_id_prf;   // RFC 8247 Transform Type 2
    uint16_t             iana_id_auth;  // RFC 8247 Transform Type 3 (0 se n/a)
    size_t               digest_len;    // byte, output completo
    size_t               trunc_len;     // byte, dopo troncamento IKE (es. 12 per SHA1-96)
} hash_algo_t;

// ============================================================
//  KEM / KEY EXCHANGE
// ============================================================
typedef struct {
    const char  *config_name;
    const char  *ossl_name;         // per EVP_PKEY_CTX_new_from_name()
    uint16_t     iana_id;           // RFC 8247 Transform Type 4 / draft PQ
    size_t       pubkey_len;        // encapsulation key (o DH pubkey)
    size_t       ciphertext_len;    // 0 per DH classico
    size_t       secret_len;        // shared secret output
    bool         is_kem;            // false = DH, true = KEM asimmetrico
} kem_algo_t;

// ============================================================
//  DIGITAL SIGNATURE
// ============================================================
typedef struct {
    const char  *config_name;
    const char  *ossl_name;         // es. "ED25519", "ML-DSA-65"
    uint16_t     iana_id;           // RFC 7427 / draft PQ
    size_t       pubkey_len;
    size_t       sig_len;           // 0 se variabile (es. RSA)
    bool         is_pq;
} sig_algo_t;

// ============================================================
//  Suite completa — quello che viene popolato dal config
// ============================================================
typedef struct {
    const enc_algo_t  *enc;
    const hash_algo_t *prf;
    const hash_algo_t *auth;
    const kem_algo_t  *kex;
    const sig_algo_t  *sig;    // NULL se non usata
} cipher_suite_t_2;

// ============================================================
//  API del registry
// ============================================================
const enc_algo_t*  enc_by_name (const char *name);
const hash_algo_t* hash_by_name(const char *name);
const kem_algo_t*  kem_by_name (const char *name);
const sig_algo_t*  sig_by_name (const char *name);

const kem_algo_t*  kem_by_iana (uint16_t id);