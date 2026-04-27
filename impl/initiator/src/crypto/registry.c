#include "../../include/crypto/registry.h"
#include <openssl/evp.h>
#include <string.h>

/**
 * Provide the mapping between the keyword used in the config file with the implementation used in Openssl 
*/


// ------------------------------------------------------------
//  Encryption
// ------------------------------------------------------------
static const enc_algo_t enc_table[] = {
    //  config        ossl                evp_fn               iana   klen  ivlen icvlen  mode
    { "aes128-cbc", "AES-128-CBC",  EVP_aes_128_cbc,   0x000C,  16,   16,    0,  CIPHER_MODE_CBC },
    { "aes256-cbc", "AES-256-CBC",  EVP_aes_256_cbc,   0x000D,  32,   16,    0,  CIPHER_MODE_CBC },
    { "aes128-gcm", "AES-128-GCM",  EVP_aes_128_gcm,   0x0014,  16,   12,   16,  CIPHER_MODE_GCM },
    { "aes256-gcm", "AES-256-GCM",  EVP_aes_256_gcm,   0x0015,  32,   12,   16,  CIPHER_MODE_GCM },
};

// ------------------------------------------------------------
//  Hash
// ------------------------------------------------------------
static const hash_algo_t hash_table[] = {
    //  config          ossl       evp_fn       iana_prf  iana_auth  dlen  trunc
    { "hmac-sha1",   "SHA1",   EVP_sha1,    0x0002,   0x0002,    20,   12  },
    { "hmac-sha256", "SHA256", EVP_sha256,  0x0005,   0x000C,    32,   16  },
    { "hmac-sha384", "SHA384", EVP_sha384,  0x0006,   0x000D,    48,   24  },
    { "hmac-sha512", "SHA512", EVP_sha512,  0x0007,   0x000E,    64,   32  },
};

// ------------------------------------------------------------
//  KEM / Key Exchange
// ------------------------------------------------------------
static const kem_algo_t kem_table[] = {
    //  config       ossl           iana    publen  ctlen  sslen  is_kem
    { "x25519",    "X25519",       31,   32,     0,    32,   false },
    { "mlkem512",  "ML-KEM-512",   35,  800,   768,    32,   true  },
};

// ------------------------------------------------------------
//  Digital Signature
// ------------------------------------------------------------
static const sig_algo_t sig_table[] = {
    //  config        ossl          iana    publen  siglen  is_pq
    // Aggiungere falcon
    { "ed25519",    "ED25519",    0x0008,    32,     64,   false },
    { "mldsa87",    "ML-DSA-87",  0x0903,  2592,   4595,   true  },
};

// ------------------------------------------------------------
//  Lookup 
// ------------------------------------------------------------
#define LOOKUP_BY_NAME(table, field, value)                         \
    for (size_t i = 0; i < sizeof(table)/sizeof(table[0]); i++)     \
        if (strcasecmp(table[i].field, value) == 0)                 \
            return &table[i];                                       \
    return NULL

const enc_algo_t*  enc_by_name (const char *n) { LOOKUP_BY_NAME(enc_table,  config_name, n); }
const hash_algo_t* hash_by_name(const char *n) { LOOKUP_BY_NAME(hash_table, config_name, n); }
const kem_algo_t*  kem_by_name (const char *n) { LOOKUP_BY_NAME(kem_table,  config_name, n); }
const sig_algo_t*  sig_by_name (const char *n) { LOOKUP_BY_NAME(sig_table,  config_name, n); }

const kem_algo_t*  kem_by_iana(uint16_t id) {
    for (size_t i = 0; i < sizeof(kem_table)/sizeof(kem_table[0]); i++)
        if (kem_table[i].iana_id == id) return &kem_table[i];
    return NULL;
}