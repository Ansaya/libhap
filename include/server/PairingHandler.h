#ifndef HAP_SERVER_PAIRINGHANDLER
#define HAP_SERVER_PAIRINGHANDLER

#include "crypto/EncryptionKeyStore.h"
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
         * @param setup_code Static setup code (XXX-XX-XXX format)
         * @param e_key_store Encryption key store
         */
        PairingHandler(std::shared_ptr<crypto::EncryptionKeyStore> e_key_store);

        PairingHandler(const PairingHandler&) = delete;
        PairingHandler& operator=(const PairingHandler&) = delete;

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

        /* Current setup code */
        std::string _setupCode;
        std::function<void(std::string setup_code)> _setupCodeDisplay;

        std::shared_ptr<EncryptionKeyStore> _eKeyStore;

        crypto::SRP_CTX* _srpContext;
        uint32_t _currentPairingFlags;
        std::vector<uint8_t> _sharedSecret;
        std::vector<uint8_t> _sessionKey;
        std::vector<uint8_t> _accessoryToController;
        std::vector<uint8_t> _controllerToAccessory;

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
         * @brief Computed read/write session keys from current session key
         * 
         * @return true When read/write keys are correctly computed from session key
         * @return false When some error occurred during keys computation
         */
        bool _enableSecurity();

        /**
         * @brief Encrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to encrypt
         * @param buffer_length Buffer length
         * @param secret Secret key buffer
         * @param nonce Encryption nonce
         * @param has_size Prepend 2-bytes encrypted buffer + vtag length to output buffer
         * @return std::vector<uint8_t> Output buffer containing encrypted buffer and vtag
         */
        std::vector<uint8_t> _encrypt(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t* secret,
            const uint8_t nonce[8], bool has_size) const;

        /**
         * @brief Decrypt given buffer using nonce and ChaCha20-Poly1305 algorithm
         * 
         * @param buffer Buffer to decrypt (encrypted data + vtag)
         * @param buffer_length Buffer length
         * @param secret Secret key buffer
         * @param nonce Decryption nonce
         * @param has_size Given buffer has 2-bytes encrypted data + vtag length prepended
         * @return std::vector<uint8_t> 
         */
        std::vector<uint8_t> _decrypt(
            const uint8_t* buffer, size_t buffer_length, 
            const uint8_t* secret,
            const uint8_t nonce[8], bool has_size) const;

    };

}
}

#endif