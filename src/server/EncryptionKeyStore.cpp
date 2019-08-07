#include <server/EncryptionKeyStore.h>

#include <fstream>

using namespace hap::server;

EncryptionKeyStore::EncryptionKeyStore()
    : _fileName("")
{
}
        
EncryptionKeyStore::EncryptionKeyStore(const std::string& file_store)
    : _fileName(file_store)
{

}

EncryptionKeyStore::~EncryptionKeyStore()
{
}

void EncryptionKeyStore::storeKey(
    const std::vector<uint8_t>& controller_id, 
    const std::vector<uint8_t>& key)
{

}

const std::vector<uint8_t>* EncryptionKeyStore::getKey(
    const std::vector<uint8_t>& controller_id) const
{
    return nullptr;
}

void EncryptionKeyStore::removeKey(
    const std::vector<uint8_t>& controller_id)
{

}