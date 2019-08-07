#include <server/crypto/HKDF.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

using namespace hap::server::crypto;

std::vector<uint8_t> HKDF::derive(
    size_t key_length, 
    const uint8_t* salt, size_t salt_length, 
    const uint8_t* secret, size_t secret_length, 
    const uint8_t* info, size_t info_length)
{
    std::vector<uint8_t> key(key_length, 0);

    // Initialize private key context for HKDF algorithm
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if(pctx != NULL)
    {
        // Initilize private key derivation context
        // Set extract and expand mode for HKDF algorithm
        // Set HKDF salt buffer
        // Set HKDF secret key buffer
        // Set HKDF info buffer
        // Derive shared key

        int hkdfval = 0;
        if((hkdfval = EVP_PKEY_derive_init(pctx)))
        if((hkdfval = EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)))
        if((hkdfval = EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512())))
        if((hkdfval = EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_length)))
        if((hkdfval = EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_length)))
        if((hkdfval = EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_length)))
        if((hkdfval = EVP_PKEY_derive(pctx, key.data(), &key_length)))
        {
            EVP_PKEY_CTX_free(pctx);

            // If actual length is different from required length return empty key
            // to notify the error
            if(key_length != key.size())
            {
                // TODO: log error
                key.clear();
            }

            return key;
        }
        EVP_PKEY_CTX_free(pctx);
    }
    
    // TODO: log error

    key.clear();
    return key;
}