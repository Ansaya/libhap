#ifndef HAP_SERVER_PAIRINGHANDLER
#define HAP_SERVER_PAIRINGHANDLER

#include "EncryptionKeyStore.h"
#include "crypto/SRP.h"
#include "tlv/TLVData.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace hap {
namespace server {

    /**
     * @brief Pairing procedure handler for HomeKit Accessory Protocol SRP pairing
     *        and ChaCha20-Poly1305 data encryption/decryption
     * 
     */
    class PairingHandler
    {
    public:
        /**
         * @brief Construct a new Pairing Handler object
         * 
         * @param accessory_id Accessory ID
         * @param setup_code Static setup code (XXX-XX-XXX format)
         * @param e_key_store Encryption key store
         */
        PairingHandler(
            const std::string& accessory_id,
            const std::string& setup_code, 
            std::shared_ptr<EncryptionKeyStore> e_key_store);

        /**
         * @brief Construct a new Pairing Handler object
         * 
         * @param accessory_id Accessory ID
         * @param setup_code_display Setup code display function for random code generator
         * @param e_key_store Encryption key store
         */
        PairingHandler(
            const std::string& accessory_id,
            std::function<void(std::string setup_code)> setup_code_display,
            std::shared_ptr<EncryptionKeyStore> e_key_store);

        virtual ~PairingHandler();

        /**
         * @brief Handle Pair Setup requests
         * 
         * @param tlv_data Controller request TLV data
         * @return tlv::TLVData Accessory response TLV data
         */
        tlv::TLVData pairSetup(const tlv::TLVData& tlv_data);

        /**
         * @brief Handle Pair Verify requests
         * 
         * @param tlv_data Controller request TLV data
         * @return tlv::TLVData Accessory response TLV data
         */
        tlv::TLVData pairVerify(const tlv::TLVData& tlv_data);

        /**
         * @brief 
         * 
         * @param tlv_data Controller request TLV data
         * @return tlv::TLVData Accessory response TLV data
         */
        tlv::TLVData pairings(const tlv::TLVData& tlv_data);

        /**
         * @brief Check pairing state
         * 
         * @note Controller verification state will change after a correct
         *       Pair-Setup or Pair-Verify message sequence
         * 
         * @return true When controller has been verified
         * @return false When controller is not yet verified
         */
        bool clientVerified() const;

        /**
         * @brief Encrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to encrypt
         * @param nonce Encryption nonce
         * @return std::vector<uint8_t> Encrypted buffer (empty if !clientVerified())
         */
        std::vector<uint8_t> encrypt(
            const std::vector<uint8_t>& buffer, 
            const uint8_t nonce[8]) const;

        /**
         * @brief Encrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to encrypt
         * @param buffer_length Buffer length
         * @param nonce Encryption nonce
         * @return std::vector<uint8_t> Encrypted buffer (empty if !clientVerified())
         */
        std::vector<uint8_t> encrypt(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t nonce[8]) const;

        /**
         * @brief Decrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to decrypt
         * @param nonce Decryption nonce
         * @return std::vector<uint8_t> Decrypted buffer (empty if !clientVerified())
         */
        std::vector<uint8_t> decrypt(
            const std::vector<uint8_t>& buffer, 
            const uint8_t nonce[8]) const;

        /**
         * @brief Decrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to decrypt
         * @param buffer_length Buffer length
         * @param nonce Decryption nonce
         * @return std::vector<uint8_t> Decrypted buffer (empty if !clientVerified())
         */
        std::vector<uint8_t> decrypt(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t nonce[8]) const;

    private:

        enum PairingState 
        {
            M1  = 1,
            M2  = 2,
            M3  = 3,
            M4  = 4,
            M5  = 5,
            M6  = 6
        };

        enum PairingFlag
        {
            kPairingFlag_Transient      = 0x00000010,
            kPairingFlag_Split          = 0x01000000
        };

        /* HAP Accessory ID */
        const std::string _accessoryID;

        /* Current setup code */
        std::string _setupCode;
        std::function<void(std::string setup_code)> _setupCodeDisplay;

        std::shared_ptr<EncryptionKeyStore> _eKeyStore;

        crypto::SRP_CTX* _srpContext;
        uint32_t _currentPairingFlags;
        std::vector<uint8_t> _sharedSecret;
        std::vector<uint8_t> _sessionKey;

        bool _clientVerified;

        /* Pair Setup procedure methods */

        /**
         * @brief Parse M1 request from controller and construct M2 response
         * 
         * @param tlv_data Received M1 content from controller
         * @return tlv::TLVData M2 response for controller
         */
        tlv::TLVData _startResponse(const tlv::TLVData& tlv_data);

        /**
         * @brief Parse M3 request from controller and construct M4 response
         * 
         * @param tlv_data Received M3 content from controller
         * @return tlv::TLVData M4 response for controller
         */
        tlv::TLVData _verifyResponse(const tlv::TLVData& tlv_data);

        /**
         * @brief Parse M5 request from controller and construct M6 response
         * 
         * @param tlv_data Received M5 content from controller
         * @return tlv::TLVData M6 response for controller
         */
        tlv::TLVData _exchangeResponse(const tlv::TLVData& tlv_data);


        /* Pair Verify procedure methods */

        /**
         * @brief Parse M1 verify request from controller and construct M2 response
         * 
         * @param tlv_data Received M1 content from controller
         * @return tlv::TLVData M2 response for controller
         */
        tlv::TLVData _verifyStartResponse(const tlv::TLVData& tlv_data);

        /**
         * @brief Parse M3 verify request from controller and construct M4 response
         * 
         * @param tlv_data Received M3 content from controller
         * @return tlv::TLVData M4 response for controller
         */
        tlv::TLVData _verifyFinishResponse(const tlv::TLVData& tlv_data);

        /**
         * @brief Encrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to encrypt
         * @param buffer_length Buffer length
         * @param nonce Encryption nonce
         * @param has_size Prepend 2-bytes encrypted buffer + vtag length to output buffer
         * @return std::vector<uint8_t> Output buffer containing encrypted buffer and vtag
         */
        std::vector<uint8_t> _encrypt(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t nonce[8], bool has_size) const;

        /**
         * @brief Decrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to decrypt (encrypted data + vtag)
         * @param buffer_length Buffer length
         * @param nonce Decryption nonce
         * @param has_size Given buffer has 2-bytes encrypted data + vtag length prepended
         * @return std::vector<uint8_t> 
         */
        std::vector<uint8_t> _decrypt(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t nonce[8], bool has_size) const;

        /**
         * @brief Generate a random setup code
         * 
         * @details A random setup code is genereted if _setupCodeDisplay function 
         *          is set to a valid function pointer, else _setupCode is returned.
         *          In case of errors during random code generation or display an 
         *          empty string is returned.
         * 
         * @return std::string New setup code or static one. Empty in case of error
         */
        std::string _generateSetupCode() const;

    };

}
}

#endif