#include <catch2/catch.hpp>

#include <server/crypto/Ed25519.h>

using namespace hap::server::crypto;

TEST_CASE("Ed25519 key pair generator", "[Ed25519]")
{
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> priv_pub;

    REQUIRE_NOTHROW(priv_pub = Ed25519::generatePair());
    
    std::vector<uint8_t>& priv = priv_pub.first;
    std::vector<uint8_t>& pub = priv_pub.second;

    REQUIRE_FALSE(priv.empty());
    REQUIRE_FALSE(pub.empty());

    REQUIRE(priv.size() == Ed25519::key_length);
    REQUIRE(pub.size() == Ed25519::key_length);

    bool same_priv_pub = true;
    for(size_t i = 0; i < priv.size(); ++i)
    {
        if(priv[i] != pub[i])
        {
            same_priv_pub = false;
            break;
        }
    }
    REQUIRE_FALSE(same_priv_pub);
}

TEST_CASE("Ed25519 buffer sign", "[Ed25519]")
{
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> priv_pub = 
        Ed25519::generatePair();
    
    std::vector<uint8_t>& priv = priv_pub.first;
    std::vector<uint8_t>& pub = priv_pub.second;

    const uint8_t* buffer = (const uint8_t*)"My-test-buffer-to-be-signed-with-ed25519";
    std::vector<uint8_t> signature;

    REQUIRE_NOTHROW(signature = Ed25519::sign(buffer, 40, priv.data(), priv.size()));

    REQUIRE_FALSE(signature.empty());
    REQUIRE(signature.size() == Ed25519::sign_length);
}

TEST_CASE("Ed25519 sign verification", "[Ed25519]")
{
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> priv_pub = 
        Ed25519::generatePair();
    
    std::vector<uint8_t>& priv = priv_pub.first;
    std::vector<uint8_t>& pub = priv_pub.second;

    const uint8_t* buffer = (const uint8_t*)"My-test-buffer-to-be-signed-and-verified";
    std::vector<uint8_t> signature = Ed25519::sign(buffer, 40, priv.data(), priv.size());
    
    bool correct_identity = false;

    REQUIRE_NOTHROW(correct_identity = Ed25519::verify(buffer, 40, 
        pub.data(), pub.size(), signature.data(), signature.size()));

    REQUIRE(correct_identity);

    // Invalid 32 bytes public key
    std::vector<uint8_t> wrong_pub = 
        {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2};

    REQUIRE_NOTHROW(correct_identity = Ed25519::verify(buffer, 40, 
        wrong_pub.data(), wrong_pub.size(), signature.data(), signature.size()));

    REQUIRE_FALSE(correct_identity);
}

TEST_CASE("Ed25519 secret derivation", "[Ed25519]")
{
    // Server key pair
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> priv_pub = 
        Ed25519::generatePair();
    std::vector<uint8_t>& skey = priv_pub.first;
    std::vector<uint8_t>& pkey = priv_pub.second;

    // Client key pair
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> c_priv_pub = 
        Ed25519::generatePair();
    std::vector<uint8_t>& c_skey = priv_pub.first;
    std::vector<uint8_t>& c_pkey = priv_pub.second;

    // Derived server secret
    std::vector<uint8_t> secret = Ed25519::derive(skey.data(), 
        skey.size(), c_pkey.data(), c_pkey.size());

    // Derived client secret
    std::vector<uint8_t> c_secret = Ed25519::derive(c_skey.data(), 
        c_skey.size(), pkey.data(), pkey.size());

    REQUIRE_FALSE(secret.empty());
    REQUIRE(secret.size() == c_secret.size());

    bool mismatch = false;
    for(size_t i = 0; i < secret.size(); ++i)
    {
        if(secret[i] != c_secret[i])
        {
            mismatch = true;
            break;
        }
    }

    REQUIRE_FALSE(mismatch);
}