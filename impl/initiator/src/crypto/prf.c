#include "../../include/crypto/crypto.h"
#include "../../include/log.h"
#include "../../include/ike/constant.h"
#include <openssl/hmac.h> 

int prf(
    const uint8_t     *key,  size_t key_len,
    const uint8_t     *data, size_t data_len,
    uint8_t           *out,  size_t *out_len,
    const hash_algo_t *algo
){
    if (!key || !data || !out || !algo) {
        log_error("[PRF] NULL input");
        return EXIT_FAILURE;
    }

    unsigned int len = 0;
    if (!HMAC(algo->evp_fn(), key, key_len, data, data_len, out, &len)) {
        log_error("[PRF] HMAC failed");
        return EXIT_FAILURE;
    }

    *out_len = len;
    return EXIT_SUCCESS;
}


/*
int prf_plus_2(
    const uint8_t     *skeyseed, size_t skeyseed_len,
    const uint8_t     *ni,       size_t ni_len,
    const uint8_t     *nr,       size_t nr_len,
    const uint8_t     *spi_i,
    const uint8_t     *spi_r,
    uint8_t           *out,      size_t out_len,
    const hash_algo_t *algo)
{
    if (!skeyseed || !ni || !nr || !spi_i || !spi_r || !out || !algo) {
        log_error("[PRF+] NULL input");
        return EXIT_FAILURE;
    }


    size_t   digest_len = algo->digest_len;
    size_t   base_len   = ni_len + nr_len + 2 * SPI_LENGTH_BYTE;


    // buffer massimo = T(i-1) | base | counter
    size_t   buf_len = digest_len + base_len + 1;
    uint8_t *buf     = malloc(buf_len);
    if (!buf) return EXIT_FAILURE;

    // scrivi la parte base una volta sola — non cambia mai
    uint8_t *base = buf + digest_len;  // base parte dopo lo slot T(i-1)
    size_t   off  = 0;
    memcpy(base + off, ni,    ni_len);          off += ni_len;
    memcpy(base + off, nr,    nr_len);          off += nr_len;
    memcpy(base + off, spi_i, SPI_LENGTH_BYTE); off += SPI_LENGTH_BYTE;
    memcpy(base + off, spi_r, SPI_LENGTH_BYTE); off += SPI_LENGTH_BYTE;
    // base[off] = counter, settato nel loop

    // digest corrente — stack, digest_len <= 64 (SHA512)
    uint8_t  digest[64];
    size_t   digest_out_len;
    size_t   generated  = 0;
    uint8_t  counter    = 1;
    int      ret        = EXIT_FAILURE;

    while (generated < out_len) {

        base[off] = counter;  // aggiorna il counter in-place

        if (counter == 1) {
            // prima iterazione: input = base | counter  (senza T(i-1))
            if (prf(skeyseed, skeyseed_len, base, base_len + 1, digest, &digest_out_len, algo) != EXIT_SUCCESS) 
                goto done;
        } else {
            // iterazioni successive: input = T(i-1) | base | counter
            // T(i-1) è già in buf[0..digest_len-1] dal giro precedente
            if (prf(skeyseed,  skeyseed_len, buf, buf_len, digest, &digest_out_len, algo) != EXIT_SUCCESS) 
                goto done;
        }

        // copia nel buffer di output — l'ultimo blocco può essere parziale
        size_t copy = (out_len - generated < digest_len)
             ? out_len - generated
             : digest_len;
        memcpy(out + generated, digest, copy);
        generated += copy;

        // salva T(i) in testa al buffer per la prossima iterazione
        memcpy(buf, digest, digest_len);
        counter++;
    }

    ret = EXIT_SUCCESS;
    done:
        // azzera il materiale sensibile prima di liberare
        secure_free(buf, buf_len);
        return ret;
}

*/