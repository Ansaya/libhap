#include <server/EncryptionKeyStore.h>

#include <openssl/err.h>
#include <openssl/rand.h>

using namespace hap::server;
        
EncryptionKeyStore::EncryptionKeyStore(
    const std::string& mac_addr, 
    const std::string& setup_code,
    const std::string& file_store)
    : _associatedMAC(mac_addr), _setupCode(setup_code), _displaySetupCode(nullptr), 
    _fileName(file_store)
{
    if(!file_store.empty())
    {
        // TODO: initialize _keyStore from file
    }
}

EncryptionKeyStore::EncryptionKeyStore(
    const std::string& mac_addr, 
    std::function<bool(std::string)> display_setup_code,
    const std::string& file_store)
    : _associatedMAC(mac_addr), _setupCode(""), _displaySetupCode(display_setup_code), 
    _fileName(file_store)
{
    if(!file_store.empty())
    {
        // TODO: initialize _keyStore from file
    }
}

EncryptionKeyStore::~EncryptionKeyStore()
{
}

const std::string& EncryptionKeyStore::getMAC() const
{
    return _associatedMAC;
}

std::string EncryptionKeyStore::getSetupCode() const
{
    if(_displaySetupCode == nullptr)
    {
        return _setupCode;
    }
    else
    {
        // Conversion function from unsigned char to 0-9 digit char
        std::function<char(uint8_t)> randToDigit = [](uint8_t rand) 
        {
            return std::to_string((int)((double)rand * 10 / (UINT8_MAX + 1))).front();
        };

        // Initialize a random buffer for the 8 digits code
        uint8_t rand_buffer[8];
        int retval = RAND_bytes(rand_buffer, sizeof(rand_buffer));
        if(retval != 1)
        {
            unsigned long err_code = ERR_get_error();
            const char* err_string = ERR_error_string(err_code, NULL);

            // TODO: log error
            return std::string();
        }
        else
        {
            // Store the new setup code in XXX-XX-XXX format
            std::string random_code = "" +
                randToDigit(rand_buffer[0]) + randToDigit(rand_buffer[1]) + randToDigit(rand_buffer[2]) +
                '-' + randToDigit(rand_buffer[3]) + randToDigit(rand_buffer[4]) + '-' +
                randToDigit(rand_buffer[5]) + randToDigit(rand_buffer[6]) + randToDigit(rand_buffer[7]);

            // Display random setup code to the user
            bool display_succesful = false;
            try {
                display_succesful = _displaySetupCode(random_code);
            }
            catch(std::exception& e)
            {
                // TODO: log error
            }

            if(display_succesful)
            {
                return random_code;
            }
            else
            {
                return std::string();
            }
        }
    }
}

void EncryptionKeyStore::storeKey(
    const std::vector<uint8_t>& controller_id, 
    const std::vector<uint8_t>& key)
{
    std::scoped_lock w_lock(_mKeyStore, _mFile);

    const auto& it = _keyStore.find(controller_id);
    if(it == _keyStore.end())
    {
        _keyStore.emplace(controller_id, key);
    }
    else
    {
        it->second = key;
    }
    
    _keyStoreBackup();
}

const std::vector<uint8_t>* EncryptionKeyStore::getKey(
    const std::vector<uint8_t>& controller_id) const
{
    std::lock_guard lock(_mKeyStore);

    const auto& it = _keyStore.find(controller_id);
    if(it != _keyStore.end())
    {
        return &(it->second);
    }

    return nullptr;
}

void EncryptionKeyStore::removeKey(
    const std::vector<uint8_t>& controller_id)
{
    std::scoped_lock w_lock(_mKeyStore, _mFile);

    _keyStore.erase(controller_id);

    _keyStoreBackup();
}

void EncryptionKeyStore::_keyStoreBackup()
{
    if(!_fileName.empty())
    {
        // TODO: write _keyStore to file
    }
}