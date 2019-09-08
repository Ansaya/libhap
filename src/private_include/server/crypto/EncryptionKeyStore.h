#ifndef HAP_SERVER_CRYPTO_ENCRYPTIONKEYSTORE
#define HAP_SERVER_CRYPTO_ENCRYPTIONKEYSTORE

#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace hap {
namespace server {
namespace crypto {

    class EncryptionKeyStore
    {
    public:
        /**
         * @brief Construct a new Encryption Key Store for given accessory mac
         * 
         * @details Encrypted key store initialized with a non-empty file_store will backup
         *          stored keys on given file; if a non-empty file is found, keys are loaded
         *          from it
         * 
         * @param mac_addr Accessory MAC associated to the key store
         * @param setup_code Accessory setup code
         * @param file_store Key store backup file
         */
        EncryptionKeyStore(
            const std::string& mac_addr, 
            const std::string& setup_code,
            const std::string& file_store = "");

        /**
         * @brief Construct a new Encryption Key Store for given accessory mac
         * 
         * @details Encrypted key store initialized with a non-empty file_store will backup
         *          stored keys on given file; if a non-empty file is found, keys are loaded
         *          from it
         * 
         * @param mac_addr Accessory MAC associated to the key store
         * @param display_setup_code Setup code display function to display randomly generated codes
         * @param file_store Key store backup file
         */
        EncryptionKeyStore(
            const std::string& mac_addr, 
            std::function<bool(std::string setupCode)> display_setup_code,
            const std::string& file_store = "");

        EncryptionKeyStore(const EncryptionKeyStore&) = delete;
        EncryptionKeyStore& operator=(const EncryptionKeyStore&) = delete;

        ~EncryptionKeyStore();

        /**
         * @brief Get associated accessory MAC
         * 
         * @return const std::string& Accessory MAC
         */
        const std::string& getMAC() const;

        /**
         * @brief Get accessory setup code
         * 
         * @note Returned code could be static or randomly generated on each call
         *       depending on key store initialization; if empty string is returned
         *       it means display_setup_code function returned false (could't display code to user)
         * 
         * @return std::string Accessory setup code formatted as XXX-XX-XXX
         */
        std::string getSetupCode() const;

        /**
         * @brief Store a key for given controller id
         * 
         * @note If a key is already present it is overwritten
         * 
         * @param controller_id Controller id
         * @param key Key to store
         */
        void storeKey(const std::vector<uint8_t>& controller_id, const std::vector<uint8_t>& key);

        /**
         * @brief Get stored key for required controller id if any
         * 
         * @param controller_id Controller id
         * @return const std::vector<uint8_t>* Key related to given controller id or nullptr if no key is found
         */
        const std::vector<uint8_t>* getKey(const std::vector<uint8_t>& controller_id) const;

        /**
         * @brief Remove key associated to given controller id
         * 
         * @param controller_id Controller id
         */
        void removeKey(const std::vector<uint8_t>& controller_id);

    private:
        const std::string _associatedMAC;
        const std::string _setupCode;
        const std::function<bool(std::string setupCode)> _displaySetupCode;
        const std::string _fileName;
        std::mutex _mFile;
        std::map<std::vector<uint8_t>, std::vector<uint8_t>> _keyStore;
        mutable std::mutex _mKeyStore;

        /**
         * @brief Update backup file with current _keyStore values
         * 
         */
        void _keyStoreBackup();
    };

}
}
}

#endif