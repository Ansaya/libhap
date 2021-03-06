#include <server/crypto/ChaCha20Poly1305.h>

#include <openssl/err.h>
#include <openssl/evp.h>

using namespace hap::server::crypto;

static inline std::vector<uint8_t> _encrypt(
    const uint8_t* data, size_t data_length, 
    const uint8_t* aad, uint8_t aad_length,
    const uint8_t* secret, const uint8_t nonce[8],
    std::vector<uint8_t>* vtag) noexcept
{
    // Initialize output buffer with sufficient size
    std::vector<uint8_t> out(aad_length + data_length + EVP_MAX_BLOCK_LENGTH, 0);

    // Prepend Additional Authenticated Data to output buffer
    for(uint8_t i = 0; i < aad_length; ++i)
    {
        out[i] = *aad;
        aad++;
    }
    int outl, tmpl, evpval = 0;

    // Attempt encryption
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if(cctx != NULL)
    {
        // Initialize cipher context for ChaCha20 with Ploy1305
        // Set iv length to 8 instead of 12
        // Set symmetric key and nonce
        // Encrypt data in buffer
        // Finalize data encryption

        if((evpval = EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)))
        if((evpval = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, 8, NULL)))
        if((evpval = EVP_EncryptInit_ex(cctx, NULL, NULL, secret, nonce)))
        if((evpval = EVP_EncryptUpdate(cctx, out.data() + aad_length, &outl, data, data_length)))
        if((evpval = EVP_EncryptFinal_ex(cctx, out.data() + aad_length + outl, &tmpl)))
        {
            out.resize(aad_length + outl + tmpl);

            // Store poly1305 verification tag for encrypted data if necessary
            if(vtag != nullptr)
            {
                vtag->resize(ChaCha20Poly1305::vtag_length);
                if((evpval = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, 
                    ChaCha20Poly1305::vtag_length, (void*)vtag->data())))
                {
                    EVP_CIPHER_CTX_free(cctx);

                    return out;
                }
            }
            else
            {
                EVP_CIPHER_CTX_free(cctx);

                return out;
            }
        }
        EVP_CIPHER_CTX_free(cctx);
    }
    
    // TODO: log error
    out.clear();
    if(vtag != nullptr)
    {
        vtag->clear();
    }

    return out;
}

std::vector<uint8_t> ChaCha20Poly1305::encrypt(
    const uint8_t* data, size_t data_length, 
    const uint8_t* aad, uint8_t aad_length,
    const uint8_t* secret, const uint8_t nonce[8],
    std::vector<uint8_t>& vtag) noexcept
{
    return _encrypt(data, data_length, aad, aad_length, secret, nonce, &vtag);
}

std::vector<uint8_t> ChaCha20Poly1305::encrypt(
    const uint8_t* data, size_t data_length, 
    const uint8_t* aad, uint8_t aad_length,
    const uint8_t* secret, const uint8_t nonce[8]) noexcept
{
    return _encrypt(data, data_length, aad, aad_length, secret, nonce, nullptr);
}

std::vector<uint8_t> ChaCha20Poly1305::decrypt(
    const uint8_t* data, size_t data_length, 
    uint8_t aad_length, const uint8_t* vtag, 
    const uint8_t* secret, const uint8_t nonce[8]) noexcept
{
    data_length -= aad_length;
    data += aad_length;
    std::vector<uint8_t> out(data_length + EVP_MAX_BLOCK_LENGTH, 0);
    int outl, tmpl, evpval = 0;

    // Attempt decryption
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if(cctx != NULL)
    {
        // Initialize cipher context for ChaCha20 with Ploy1305
        // Set iv length to 8 instead of 12
        // Set expected poly1305 verification tag
        // Set secret key and nonce
        // Decrypt data in buffer
        // Finalize data decryption

        if((evpval = EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)))
        if((evpval = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, 8, NULL)))
        if((evpval = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, 
            ChaCha20Poly1305::vtag_length, (void*)(vtag))))
        if((evpval = EVP_DecryptInit_ex(cctx, NULL, NULL, secret, nonce)))
        if((evpval = EVP_DecryptUpdate(cctx, out.data(), &outl, data, data_length)))
        if((evpval = EVP_DecryptFinal_ex(cctx, out.data() + outl, &tmpl)))
        {
            EVP_CIPHER_CTX_free(cctx);

            // Set output buffer to the actual decrypted data length
            out.resize(outl + tmpl);

            return out;
        }
        EVP_CIPHER_CTX_free(cctx);
    }

    // TODO: log error
    out.clear();

    return out;
}