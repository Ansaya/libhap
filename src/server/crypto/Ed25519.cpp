#include <server/crypto/Ed25519.h>

#include <openssl/err.h>
#include <openssl/evp.h>

using namespace hap::server::crypto;

bool Ed25519::verify(
    const uint8_t* buffer, size_t buffer_length, 
    const uint8_t* key, size_t key_size,
    const uint8_t* sign, size_t sign_length)
{
    // Allocate message digest context
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if(mctx != NULL)
    {
        // Allocate public key for ED25519 verification
        EVP_PKEY* pkey = 
            EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key, key_size);
        if(pkey != NULL)
        {
            // Initialize digest verification context
            if(EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey) == 1)
            {
                // Verify result against given signature
                int valid = 
                    EVP_DigestVerify(mctx, sign, sign_length, buffer, buffer_length);
                if(valid == 1 || valid == 0)
                {
                    EVP_PKEY_free(pkey);
                    EVP_MD_CTX_free(mctx);

                    return valid;
                }
            }
            EVP_PKEY_free(pkey);
        }
        EVP_MD_CTX_free(mctx);
    }

    // TODO: log error

    return false;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Ed25519::generatePair()
{
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> priv_pub = 
        std::make_pair<std::vector<uint8_t>,std::vector<uint8_t>>(
            std::vector<uint8_t>(key_length, 0), 
            std::vector<uint8_t>(key_length, 0));

    std::vector<uint8_t>& priv = priv_pub.first;
    std::vector<uint8_t>& pub = priv_pub.second;
    size_t priv_l = priv.size(), pub_l = pub.size();

    // Initialize Ed25519 key context
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if(pctx != NULL)
    {
        // Initialize key generator context for Ed25519
        if(EVP_PKEY_keygen_init(pctx) == 1)
        {
            // Generate key pair
            EVP_PKEY* pkey;
            if(EVP_PKEY_keygen(pctx, &pkey) == 1)
            {
                // Retrieve private and public key
                if(EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_l))
                if(EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_l))
                {
                    EVP_PKEY_free(pkey);
                    EVP_PKEY_CTX_free(pctx);

                    return priv_pub;
                }
                EVP_PKEY_free(pkey);
            }
        }
        EVP_PKEY_CTX_free(pctx);
    }

    // TODO: log error
    
    priv.clear();
    pub.clear();

    return priv_pub;
}

std::vector<uint8_t> Ed25519::sign(
    const uint8_t* buffer, size_t buffer_length, 
    const uint8_t* priv_key, size_t priv_key_length)
{
    std::vector<uint8_t> sign(sign_length, 0);
    size_t sign_l = sign.size();

    // Allocate message digest context
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if(mctx != NULL)
    {
        // Allocate private key for signing (public key is derived during the call)
        EVP_PKEY* pkey = 
            EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv_key, priv_key_length);
        if(pkey != NULL)
        {
            // Initialize digest signing context (no digest is computed, only signature)
            // Generate signature

            if(EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) == 1)
            if(EVP_DigestSign(mctx, sign.data(), &sign_l, buffer, buffer_length) == 1)
            {
                EVP_PKEY_free(pkey);
                EVP_MD_CTX_free(mctx);

                return sign;
            }
            EVP_PKEY_free(pkey);
        }
        EVP_MD_CTX_free(mctx);
    }

    // TODO: log error

    sign.clear();

    return sign;
}

std::vector<uint8_t> Ed25519::derive(
    const uint8_t* skey, size_t skey_size,
    const uint8_t* c_pkey, size_t c_pkey_size)
{
    std::vector<uint8_t> secret(key_length, 0);
    size_t secretl = secret.size();

    // Initialize secret key with given one
    EVP_PKEY* e_skey = 
            EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, skey, skey_size);
    if(e_skey != NULL)
    {
        // Initialize client public key with given one
        EVP_PKEY* e_c_pkey = 
            EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, c_pkey, c_pkey_size);
        if(e_c_pkey != nullptr)
        {
            // Initialize pkey context with secret key
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(e_skey, NULL);
            if(pctx != nullptr)
            {
                // Initialize shared secret derivation context
                // Set client public key as peer key
                // Derive shared secret from skey and c_pkey
                if(EVP_PKEY_derive_init(pctx) == 1)
                if(EVP_PKEY_derive_set_peer(pctx, e_c_pkey) == 1)
                if(EVP_PKEY_derive(pctx, secret.data(), &secretl) == 1)
                {
                    EVP_PKEY_CTX_free(pctx);
                    EVP_PKEY_free(e_c_pkey);
                    EVP_PKEY_free(e_skey);

                    return secret;
                }
                EVP_PKEY_CTX_free(pctx);
            }
            EVP_PKEY_free(e_c_pkey);
        }
        EVP_PKEY_free(e_skey);
    }

    // TODO: log error

    secret.clear();
    return secret;
}