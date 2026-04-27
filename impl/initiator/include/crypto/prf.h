// include/crypto/prf.h
// Nessun contesto — funzioni pure

#include <stdint.h>
#include <stdlib.h>
#include "registry.h"

int prf(
    const uint8_t      *key,  size_t key_len,
    const uint8_t      *data, size_t data_len,
    uint8_t            *out,  size_t *out_len,
    const hash_algo_t  *algo
);

int prf_plus_2(
    const uint8_t     *skeyseed, size_t skeyseed_len,
    const uint8_t     *ni,       size_t ni_len,
    const uint8_t     *nr,       size_t nr_len,
    const uint8_t     *spi_i,
    const uint8_t     *spi_r,
    uint8_t           *out,      size_t out_len,
    const hash_algo_t *algo
);

