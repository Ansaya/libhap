#ifndef HAP_SERVER_ENCRYPTIONKEYSTORE
#define HAP_SERVER_ENCRYPTIONKEYSTORE

#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace hap {
namespace server {

    class EncryptionKeyStore
    {
    public:
        EncryptionKeyStore();
        
        EncryptionKeyStore(const std::string& file_store);

        EncryptionKeyStore(const EncryptionKeyStore&) = delete;

        EncryptionKeyStore& operator=(const EncryptionKeyStore&) = delete;

        ~EncryptionKeyStore();

        void storeKey(const std::vector<uint8_t>& controller_id, const std::vector<uint8_t>& key);

        const std::vector<uint8_t>* getKey(const std::vector<uint8_t>& controller_id) const;

        void removeKey(const std::vector<uint8_t>& controller_id);

    private:
        const std::string _fileName;
        std::mutex _mFile;
        std::map<std::vector<uint8_t>, std::vector<uint8_t>> _keyStore;

    };

}
}

#endif