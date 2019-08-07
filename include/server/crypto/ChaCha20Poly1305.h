#ifndef HAP_SERVER_CRYPTO_CHACHA20POLY1305
#define HAP_SERVER_CRYPTO_CHACHA20POLY1305

#include <cstdint>
#include <vector>

#define HAP_SERVER_CRYPTO_CHACHA20_KEY_LENGTH   32
#define HAP_SERVER_CRYPTO_POLY1305_VTAG_LENGTH  16

namespace hap {
namespace server {
namespace crypto {

    class ChaCha20Poly1305
    {
    public:
        /**
         * @brief Encrypt given plain buffer using secret key and nonce
         * 
         * @param data Data buffer to encrypt
         * @param data_length Data buffer length
         * @param secret Secret key of 32 bytes
         * @param nonce Nonce to use
         * @return std::vector<uint8_t> Encrypted data buffer
         */
        static std::vector<uint8_t> encrypt(
            const uint8_t* data, size_t data_length, 
            const uint8_t* secret, const uint8_t nonce[8]);

        /**
         * @brief ncrypt given plain buffer using secret key and nonce
         * 
         * @note Content inside vtag will be erased during the call
         * 
         * @param data Data buffer to encrypt
         * @param data_length Data buffer length
         * @param secret Secret key of 32 bytes
         * @param nonce Nonce to use
         * @param vtag Verification tag for returned encrypted data buffer
         * @return std::vector<uint8_t> Encrypted data buffer
         */
        static std::vector<uint8_t> encrypt(
            const uint8_t* data, size_t data_length, 
            const uint8_t* secret, const uint8_t nonce[8],
            std::vector<uint8_t>& vtag);

        /**
         * @brief Decrypt given encrypted buffer using secret key and nonce
         * 
         * @param data Data buffer to decrypt
         * @param data_length Data buffer length
         * @param vtag Verification tag of 16 bytes
         * @param secret Secret key of 32 bytes
         * @param nonce Nonce to use
         * @return std::vector<uint8_t> Plain data buffer
         */
        static std::vector<uint8_t> decrypt(
            const uint8_t* data, size_t data_length, 
            const uint8_t* vtag, 
            const uint8_t* secret, const uint8_t nonce[8]);
    };

}
}
}

#endif