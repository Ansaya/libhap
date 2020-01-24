#include <catch2/catch.hpp>

#include <server/crypto/SRP.h>

#include <openssl/bn.h>

using namespace hap::server::crypto;

TEST_CASE("Generate key and secret", "[SRP]")
{
    const char* username = "alice";
    const char* password = "password123";
    BIGNUM *priv_key_BN, *pkey_BN, *salt_BN, *c_pkey_BN, *secret_BN, *session_key_BN;
    BN_hex2bn(&priv_key_BN, "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20");
    BN_hex2bn(&pkey_BN,     "40F57088A482D4C7733384FE0D301FDDCA9080AD7D4F6FDF09A01006C3CB6D56"
                            "2E41639AE8FA21DE3B5DBA7585B275589BDB279863C562807B2B99083CD1429C"
                            "DBE89E25BFBD7E3CAD3173B2E3C5A0B174DA6D5391E6A06E465F037A40062548"
                            "39A56BF76DA84B1C94E0AE208576156FE5C140A4BA4FFC9E38C3B07B88845FC6"
                            "F7DDDA93381FE0CA6084C4CD2D336E5451C464CCB6EC65E7D16E548A273E8262"
                            "84AF2559B6264274215960FFF47BDD63D3AFF064D6137AF769661C9D4FEE4738"
                            "2603C88EAA0980581D07758461B777E4356DDA5835198B51FEEA308D70F75450"
                            "B71675C08C7D8302FD7539DD1FF2A11CB4258AA70D234436AA42B6A0615F3F91"
                            "5D55CC3B966B2716B36E4D1A06CE5E5D2EA3BEE5A1270E8751DA45B60B997B0F"
                            "FDB0F9962FEE4F03BEE780BA0A845B1D9271421783AE6601A61EA2E342E4F2E8"
                            "BC935A409EAD19F221BD1B74E2964DD19FC845F60EFC09338B60B6B256D8CAC8"
                            "89CCA306CC370A0B18C8B886E95DA0AF5235FEF4393020D2B7F3056904759042");
    BN_hex2bn(&salt_BN,     "BEB25379D1A8581EB5A727673A2441EE");
    BN_hex2bn(&c_pkey_BN,   "FAB6F5D2615D1E323512E7991CC37443F487DA604CA8C9230FCB04E541DCE628"
                            "0B27CA4680B0374F179DC3BDC7553FE62459798C701AD864A91390A28C93B644"
                            "ADBF9C00745B942B79F9012A21B9B78782319D83A1F8362866FBD6F46BFC0DDB"
                            "2E1AB6E4B45A9906B82E37F05D6F97F6A3EB6E182079759C4F6847837B62321A"
                            "C1B4FA68641FCB4BB98DD697A0C73641385F4BAB25B793584CC39FC8D48D4BD8"
                            "67A9A3C10F8EA12170268E34FE3BBE6FF89998D60DA2F3E4283CBEC1393D52AF"
                            "724A57230C604E9FBCE583D7613E6BFFD67596AD121A8707EEC4694495703368"
                            "6A155F644D5C5863B48F61BDBF19A53EAB6DAD0A186B8C152E5F5D8CAD4B0EF8"
                            "AA4EA5008834C3CD342E5E0F167AD04592CD8BD279639398EF9E114DFAAAB919"
                            "E14E850989224DDD98576D79385D2210902E9F9B1F2D86CFA47EE244635465F7"
                            "1058421A0184BE51DD10CC9D079E6F1604E7AA9B7CF7883C7D4CE12B06EBE160"
                            "81E23F27A231D18432D7D1BB55C28AE21FFCF005F57528D15A88881BB3BBB7FE");
    BN_hex2bn(&secret_BN,   "F1036FECD017C8239C0D5AF7E0FCF0D408B009E36411618A60B23AABBFC38339"
                            "7268231214BAACDC94CA1C53F442FB51C1B027C318AE238E16414D60D1881B66"
                            "486ADE10ED02BA33D098F6CE9BCF1BB0C46CA2C47F2F174C59A9C61E2560899B"
                            "83EF61131E6FB30B714F4E43B735C9FE6080477C1B83E4093E4D456B9BCA492C"
                            "F9339D45BC42E67CE6C02C243E49F5DA42A869EC855780E84207B8A1EA6501C4"
                            "78AAC0DFD3D22614F531A00D826B7954AE8B14A985A429315E6DD3664CF47181"
                            "496A94329CDE8005CAE63C2F9CA4969BFE84001924037C446559BDBB9DB9D4DD"
                            "142FBCD75EEF2E162C843065D99E8F05762C4DB7ABD9DB203D41AC85A58C05BD"
                            "4E2DBF822A934523D54E0653D376CE8B56DCB4527DDDC1B994DC7509463A7468"
                            "D7F02B1BEB1685714CE1DD1E71808A137F788847B7C6B7BFA1364474B3B7E894"
                            "78954F6A8E68D45B85A88E4EBFEC13368EC0891C3BC86CF50097880178D86135"
                            "E728723458538858D715B7B247406222C1019F53603F016952D497100858824C");
    BN_hex2bn(&session_key_BN, "5CBC219DB052138EE1148C71CD4498963D682549CE91CA24F098468F06015BEB"
                            "6AF245C2093F98C3651BCA83AB8CAB2B580BBF02184FEFDF26142F73DF95AC50");

    SRP_CTX* srp_ctx = SRP::ctxNew("3072");

    std::vector<uint8_t> priv_key(BN_num_bytes(priv_key_BN), 0), 
        pkey(BN_num_bytes(pkey_BN), 0), 
        salt(BN_num_bytes(salt_BN), 0),
        c_pkey(BN_num_bytes(c_pkey_BN), 0),
        secret(BN_num_bytes(secret_BN), 0),
        session_key(BN_num_bytes(session_key_BN), 0);
    BN_bn2bin(priv_key_BN, priv_key.data());        BN_free(priv_key_BN);
    BN_bn2bin(pkey_BN, pkey.data());                BN_free(pkey_BN);
    BN_bn2bin(salt_BN, salt.data());                BN_free(salt_BN);
    BN_bn2bin(c_pkey_BN, c_pkey.data());            BN_free(c_pkey_BN);
    BN_bn2bin(secret_BN, secret.data());            BN_free(secret_BN);
    BN_bn2bin(session_key_BN, session_key.data());  BN_free(session_key_BN);

    const std::vector<uint8_t> salt_cpy(salt);

    std::vector<uint8_t> s_pkey = SRP::generateKey(srp_ctx, priv_key, salt, username, password);

    // Salt should not have been modified
    REQUIRE(salt.size() == salt_cpy.size());
    REQUIRE(!CRYPTO_memcmp(salt.data(), salt_cpy.data(), salt_cpy.size()));

    // Check computed key
    REQUIRE(s_pkey.size() == 384);
    REQUIRE(!CRYPTO_memcmp(s_pkey.data(), pkey.data(), pkey.size()));

    std::vector<uint8_t> s_secret = SRP::computeSecret(srp_ctx, c_pkey);

    // Check computed premaster secret
    REQUIRE(s_secret.size() == 384);
    REQUIRE(!CRYPTO_memcmp(s_secret.data(), secret.data(), secret.size()));

    SRP::ctxFree(srp_ctx);
}