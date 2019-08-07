#ifndef HAP_SERVER_CRYPTO_ED25519
#define HAP_SERVER_CRYPTO_ED25519

#include <hap_export.h>

#include <cstdint>
#include <tuple>
#include <vector>

#define HAP_SERVER_CRYPTO_ED25519_KEY_LENGTH    32
#define HAP_SERVER_CRYPTO_ED25519_SIGN_LENGTH   HAP_SERVER_CRYPTO_ED25519_KEY_LENGTH * 2

namespace hap {
namespace server {
namespace crypto {

    class Ed25519
    {
    public:
        /**
         * @brief Generate private/public key pair for Ed25519 algorithm
         * 
         * @return std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Pair of private and public key 
         */
        HAP_EXPORT static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generatePair();

        /**
         * @brief Generate buffer signature from given private/public key pair
         * 
         * @param buffer Buffer to create signature of
         * @param buffer_length Buffer length
         * @param priv_key Private key buffer
         * @param priv_key_length Private key length
         * @return std::vector<uint8_t> Signature of given buffer
         */
        HAP_EXPORT static std::vector<uint8_t> sign(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t* priv_key, size_t priv_key_length);

        /**
         * @brief Verify buffer against signature using key with Ed25519
         * 
         * @param buffer Buffer to verify
         * @param buffer_length Buffer length
         * @param key Public key buffer to use
         * @param key_size Publick key length
         * @param sign Verification signature buffer
         * @param sign_length Signature length
         * @return true If verification process was succesful
         * @return false If verification wasn't successful or some error occurred
         */
        HAP_EXPORT static bool verify(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t* key, size_t key_size,
            const uint8_t* sign, size_t sign_length);

        /**
         * @brief Derive shared secret from given secret key and client public key
         * 
         * @param skey Secret key buffer
         * @param skey_size Secret key length
         * @param c_pkey Clinet public key buffer
         * @param c_pkey_size Client public key length
         * @return HAP_EXPORT derive Shared secret derived or empty vector if error occurred
         */
        HAP_EXPORT static std::vector<uint8_t> derive(
            const uint8_t* skey, size_t skey_size,
            const uint8_t* c_pkey, size_t c_pkey_size);

    };

}
}
}

#endif