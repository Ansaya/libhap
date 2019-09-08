#ifndef HAP_SERVER_CRYPTO_HKDF
#define HAP_SERVER_CRYPTO_HKDF

#include <cstdint>
#include <vector>

namespace hap {
namespace server {
namespace crypto {

    class HKDF
    {
    public:
        /**
         * @brief Compute HKDF hash using SHA512 algorithm and given parameters
         * 
         * @param key_length Desired output key length
         * @param salt Salt buffer
         * @param salt_length Salt buffer length
         * @param secret Secret key buffer
         * @param secret_length Secret key buffer length
         * @param info Info buffer
         * @param info_length Info buffer length
         * 
         * @return std::vector<uint8_t> Computed key or empty vector if exception occurred
         */
        static std::vector<uint8_t> derive(
            size_t key_length, 
            const uint8_t* salt, size_t salt_length, 
            const uint8_t* secret, size_t secret_length, 
            const uint8_t* info, size_t info_length);

    };

}
}
}

#endif