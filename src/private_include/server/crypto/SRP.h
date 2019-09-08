#ifndef HAP_SERVER_CRYPTO_SRP
#define HAP_SERVER_CRYPTO_SRP

#include <cstdint>
#include <vector>

namespace hap {
namespace server {
namespace crypto {

    typedef struct srp_ctx_t SRP_CTX;

    class SRP
    {
    public:
        /**
         * @brief Initialize SRP context with given group size
         * 
         * @note Valid group ids are "1024", "1536", "2048", "3072", "4096", "6144" and "8192"
         * 
         * @param id Group size id 
         * @return SRP_CTX* Initilized SRP context or NULL if error occurred
         */
        static SRP_CTX* ctxNew(const char* id);

        /**
         * @brief Free given SRP context
         * 
         * @param srp_ctx SRP context to free
         */
        static void ctxFree(SRP_CTX* srp_ctx);

        /**
         * @brief Generate server public key from given parameters
         * 
         * @note In case of error given SRP context is left in an invalid state
         * 
         * @param srp_ctx SRP context
         * @param username SRP username
         * @param password SRP password
         * @return std::vector<uint8_t> Server public key or empty vector if error occurred
         */
        static std::vector<uint8_t> generateKey(
            SRP_CTX* srp_ctx,
            const char* username, const char* password);

        /**
         * @brief Generate server public key and client' salt from given parameters 
         * 
         * @note In case of error given SRP context and salt are left in an invalid state
         * 
         * @param srp_ctx SRP context
         * @param salt Output salt for the client
         * @param username SRP username
         * @param password SRP password
         * @return std::vector<uint8_t> Server public key or empty vector if error occurred
         */
        static std::vector<uint8_t> generateKey(
            SRP_CTX* srp_ctx, 
            std::vector<uint8_t>& salt, 
            const char* username, const char* password);

        /**
         * @brief Compute SRP shared secret from given context and client public key
         * 
         * @param srp_ctx SRP context
         * @param c_pkey Client public key
         * @return std::vector<uint8_t> SRP shared secret or empty vector if error occurred
         */
        static std::vector<uint8_t> computeSecret(
            SRP_CTX* srp_ctx, 
            const std::vector<uint8_t>& c_pkey);

        /**
         * @brief Verify client proof
         * 
         * @detials Verify that given c_proof correctly compares to 
         *          SHA512(SHA512(N)^SHA512(g), SHA512(username), salt, c_pkey, pkey, secret)
         * 
         * @param srp_ctx SRP context
         * @param secret SRP shared secret
         * @param c_proof Client public key
         * @return int 1 on success, 0 on mismatch, negative value if error occurred
         */
        static int verifyProof(
            SRP_CTX* srp_ctx, 
            const std::vector<uint8_t>& secret,
            const std::vector<uint8_t>& c_proof);

        /**
         * @brief Compute server proof
         * 
         * @param c_pkey Client public key
         * @param c_proof Client proof
         * @param secret SRP shared secret
         * @return std::vector<uint8_t> Server proof or empty vector if error occurred
         */
        static std::vector<uint8_t> computeProof(
            const std::vector<uint8_t>& c_pkey,
            const std::vector<uint8_t>& c_proof,
            const std::vector<uint8_t>& secret);
    };

}
}
}

#endif