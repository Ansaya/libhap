#include <catch2/catch.hpp>

#include <server/crypto/SRP.h>

using namespace hap::server::crypto;

TEST_CASE("SRP generate key", "[SRP]")
{
    SRP_CTX* srp_ctx;
    
    REQUIRE_NOTHROW(srp_ctx = SRP::ctxNew("3072"));

    std::vector<uint8_t> srp_key = 
        SRP::generateKey(srp_ctx, "Pair-Setup", "123-45-678");

    REQUIRE(srp_key.size());
}