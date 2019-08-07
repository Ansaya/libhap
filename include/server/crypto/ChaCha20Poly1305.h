#ifndef HAP_SERVER_CRYPTO_CHACHA20POLY1305
#define HAP_SERVER_CRYPTO_CHACHA20POLY1305

#include <cstdint>
#include <vector>

namespace hap {
namespace server {
namespace crypto {

    class ChaCha20Poly1305
    {
    public:

        static constexpr uint8_t key_length = 32;

        static constexpr uint8_t vtag_length = 16;

        /**
         * @brief Encrypt given plain buffer using secret key and nonce
         * 
         * @param data Data buffer to encrypt
         * @param data_length Data buffer length
         * @param aad Additional Authenticated Data buffer
         * @param aad_length Additional Authenticated Data length
         * @param secret Secret key of @key_length bytes
         * @param nonce Nonce to use
         * @return std::vector<uint8_t> Encrypted data buffer
         */
        static std::vector<uint8_t> encrypt(
            const uint8_t* data, size_t data_length, 
            const uint8_t* aad, uint8_t aad_length,
            const uint8_t* secret, const uint8_t nonce[8]);

        /**
         * @brief ncrypt given plain buffer using secret key and nonce
         * 
         * @note Content inside vtag will be erased during the call
         * 
         * @param data Data buffer to encrypt
         * @param data_length Data buffer length
         * @param aad Additional Authenticated Data buffer
         * @param aad_length Additional Authenticated Data length
         * @param secret Secret key of @key_length bytes
         * @param nonce Nonce to use
         * @param vtag Verification tag for returned encrypted data buffer
         * @return std::vector<uint8_t> Encrypted data buffer
         */
        static std::vector<uint8_t> encrypt(
            const uint8_t* data, size_t data_length, 
            const uint8_t* aad, uint8_t aad_length,
            const uint8_t* secret, const uint8_t nonce[8],
            std::vector<uint8_t>& vtag);

        /**
         * @brief Decrypt given encrypted buffer using secret key and nonce
         * 
         * @param data Data buffer to decrypt
         * @param data_length Data buffer length (including @aad_length)
         * @param aad_length Additional Authenticated Data length
         * @param vtag Verification tag of @vtag_length bytes
         * @param secret Secret key of @key_length bytes
         * @param nonce Nonce to use
         * @return std::vector<uint8_t> Plain data buffer
         */
        static std::vector<uint8_t> decrypt(
            const uint8_t* data, size_t data_length, 
            uint8_t aad_length, const uint8_t* vtag, 
            const uint8_t* secret, const uint8_t nonce[8]);
    };

}
}
}

#endif