#include <catch2/catch.hpp>

#include <server/crypto/ChaCha20Poly1305.h>

#include <server/crypto/Ed25519.h>
#include <server/crypto/HKDF.h>

static constexpr std::array<uint8_t, 24> hkdf_verify_salt 
    {'P','a','i','r','-','V','e','r','i','f','y','-','E','n','c','r','y','p','t','-','S','a','l','t'};
static constexpr std::array<uint8_t, 24> hkdf_verify_info 
    {'P','a','i','r','-','V','e','r','i','f','y','-','E','n','c','r','y','p','t','-','I','n','f','o'};

static constexpr std::array<uint8_t, 12> hkdf_control_salt
    {'C','o','n','t','r','o','l','-','S','a','l','t'};

static constexpr std::array<uint8_t, 27> hkdf_control_read
    {'C','o','n','t','r','o','l','-','R','e','a','d','-','E','n','c','r','y','p','t','i','o','n','-','K','e','y'};

static constexpr std::array<uint8_t, 28> hkdf_control_write
    {'C','o','n','t','r','o','l','-','W','r','i','t','e','-','E','n','c','r','y','p','t','i','o','n','-','K','e','y'};

using namespace hap::server::crypto;

TEST_CASE("ChaCha20 with Poly1305 encryption", "[ChaCha20Poly1305]")
{
    // Generate new Ed25519 key pair for accessory
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> priv_pub = 
        Ed25519::generatePair();
    std::vector<uint8_t>& AccessoryLTSK = priv_pub.first;
    std::vector<uint8_t>& AccessoryLTPK = priv_pub.second;

    // Generate new Ed25519 key pair for controller
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> c_priv_pub = 
        Ed25519::generatePair();
    std::vector<uint8_t>& iOSDeviceLTSK = c_priv_pub.first;
    std::vector<uint8_t>& iOSDeviceLTPK = c_priv_pub.second;

    // Derive shared secret from private key and controller public key
    std::vector<uint8_t> secret = Ed25519::derive(AccessoryLTSK.data(), 
        AccessoryLTSK.size(), iOSDeviceLTPK.data(), iOSDeviceLTPK.size());

    // Derive session key from secret
    std::vector<uint8_t> sessionKey = HKDF::derive(ChaCha20Poly1305::key_length, 
        hkdf_verify_salt.data(), hkdf_verify_salt.size(),
        secret.data(), secret.size(),
        hkdf_verify_info.data(), hkdf_verify_info.size());
    
    const uint8_t* nonce = (const uint8_t*)"Ts-Msg01";
    std::vector<uint8_t> message = {'M','y',' ','s','u','p','e','r',' ','i','m','p','o','r','a','t','a','n','t',' ','m','e','s','s','a','g','e'};
    uint16_t message_length = message.size();

    // Encrypt message with prepended length
    std::vector<uint8_t> vtag;
    std::vector<uint8_t> encrypted_message = ChaCha20Poly1305::encrypt(
        message.data(), message.size(), 
        (const uint8_t*)&message_length, sizeof(message_length), 
        sessionKey.data(), nonce, vtag);

    REQUIRE(encrypted_message.size() == (sizeof(message_length) + message_length));
    REQUIRE(message_length == *(const uint16_t*)encrypted_message.data());

    std::vector<uint8_t> decrypted_message = ChaCha20Poly1305::decrypt(
        encrypted_message.data(), encrypted_message.size(),
        sizeof(message_length), vtag.data(), sessionKey.data(), nonce);

    REQUIRE(decrypted_message.size() == message_length);

    bool same = true;
    for(size_t i = 0; i < message_length; ++i)
    {
        if(message[i] != decrypted_message[i])
        {
            same = false;
            break;
        }
    }
    REQUIRE(same);
}