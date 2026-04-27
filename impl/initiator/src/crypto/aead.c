
/*
int aead_encrypt(const aead_ctx_t *ctx,
const uint8_t *plain,  size_t plain_len,
const uint8_t *aad,    size_t aad_len,
uint8_t *cipher, uint8_t *iv_out, uint8_t *tag_out)
{
    uint8_t nonce[12];
    memcpy(nonce, ctx->salt, 4);
    if (getrandom(nonce + 4, 8, 0) != 8) return EXIT_FAILURE;
    memcpy(iv_out, nonce + 4, 8);
    
    int ret = EXIT_FAILURE, len = 0, final_len = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return EXIT_FAILURE;
    
    if (EVP_EncryptInit_ex(c, ctx->algo->evp_fn(), NULL, NULL, NULL)  <= 0) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)     <= 0) goto done;
    if (EVP_EncryptInit_ex(c, NULL, NULL, ctx->key, nonce)             <= 0) goto done;
    if (aad && EVP_EncryptUpdate(c, NULL, &len, aad, aad_len)          <= 0) goto done;
    if (EVP_EncryptUpdate(c, cipher, &len, plain, plain_len)           <= 0) goto done;
    if (EVP_EncryptFinal_ex(c, cipher + len, &final_len)               <= 0) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG,
    ctx->algo->tag_len, tag_out)               <= 0) goto done;
    ret = EXIT_SUCCESS;
    done:
    EVP_CIPHER_CTX_free(c);
    return ret;
}
*/