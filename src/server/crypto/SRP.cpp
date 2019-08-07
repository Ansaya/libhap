#include <server/crypto/SRP.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/srp.h>

using namespace hap::server::crypto;

struct hap::server::crypto::srp_ctx_t
{
    SRP_gN* gN;
    BIGNUM* salt;
    BIGNUM* verifier;
    BIGNUM* b;
    BIGNUM* pkey;
    EVP_MD_CTX* c_proof;

    srp_ctx_t(SRP_gN* gN, EVP_MD_CTX* c_proof) 
        : gN(gN), salt(NULL), verifier(NULL), b(NULL), 
        pkey(NULL), c_proof(c_proof)
    {}

    ~srp_ctx_t()
    {
        OPENSSL_free(salt);
        OPENSSL_free(verifier);
        OPENSSL_free(b);
        OPENSSL_free(pkey);
        EVP_MD_CTX_free(c_proof);
    }
};


SRP_CTX* SRP::ctxNew(const char* id)
{
    // Initialize SRP group from id
    SRP_gN* gN = SRP_get_default_gN(id);
    if(gN == NULL) return NULL;

    // Initialize proof hash computation H(H(N)^H(g), H(username), salt, c_pkey, pkey, secret)
    EVP_MD_CTX* c_proof = EVP_MD_CTX_new();
    if(c_proof != NULL)
    {
        // Get N and g as bytes
        std::vector<uint8_t> N(BN_bn2bin(gN->N, NULL), 0), 
            g(BN_bn2bin(gN->g, NULL), 0);
        N.resize(BN_bn2bin(gN->N, N.data()));
        g.resize(BN_bn2bin(gN->g, g.data()));

        // Compute H(N) and H(g)
        std::vector<uint8_t> hN(EVP_MAX_MD_SIZE, 0), hg(EVP_MAX_MD_SIZE, 0);
        if(EVP_Digest(N.data(), N.size(), hN.data(), NULL, EVP_sha512(), NULL) == 1)
        if(EVP_Digest(g.data(), g.size(), hg.data(), NULL, EVP_sha512(), NULL) == 1)
        {
            // Compute H(N)^H(g)
            std::vector<uint8_t>& hNxorhg = hN;
            for(size_t i = 0; i < hNxorhg.size(); ++i)
            {
                hNxorhg[i] ^= hg[i];
            }
            
            // Update proof hash with its first parameter H(N)^H(g)
            if(EVP_DigestUpdate(c_proof, hNxorhg.data(), hNxorhg.size()) == 1)
            {
                return new srp_ctx_t(gN, c_proof);
            }
        }
    }

    return NULL;
}

void SRP::ctxFree(SRP_CTX* srp_ctx)
{
    if(srp_ctx != nullptr)
        delete srp_ctx;
}

static inline std::vector<uint8_t> _generateKey(
    SRP_CTX* srp_ctx, 
    std::vector<uint8_t>* salt, 
    const char* username, const char* password)
{
    std::vector<uint8_t> pkey;

    if(srp_ctx == nullptr || srp_ctx->salt != NULL || 
        srp_ctx->verifier != NULL || srp_ctx->b != NULL || 
        srp_ctx->pkey != NULL) return pkey;

    // Compute SRP session salt and verifier
    if(SRP_create_verifier_BN(username, password, 
        &srp_ctx->salt, &srp_ctx->verifier, srp_ctx->gN->N, srp_ctx->gN->g) != 1)
    {
        // TODO: log error
        return pkey;
    }

    // Generate some randomness for public key
    uint8_t v_rand[32];
    RAND_bytes(v_rand, sizeof(v_rand));
    srp_ctx->b = BN_bin2bn(v_rand, sizeof(v_rand), NULL);
    if(srp_ctx->b == NULL) 
    { 
        return pkey; 
    }

    // Compute accessory public key
    srp_ctx->pkey = SRP_Calc_B(srp_ctx->b, srp_ctx->gN->N, srp_ctx->gN->g, srp_ctx->verifier);
    if(SRP_Verify_B_mod_N(srp_ctx->pkey, srp_ctx->gN->N) != 1)
    {
        // TODO: log error
        return pkey;
    }
            
    // Store SRP salt and accessory public key as uint8_t vectors
    std::vector<uint8_t> v_salt(BN_num_bytes(srp_ctx->salt), 0);
    v_salt.resize(BN_bn2bin(srp_ctx->salt, v_salt.data()));
    pkey.resize(BN_num_bytes(srp_ctx->pkey), 0);
    pkey.resize(BN_bn2bin(srp_ctx->pkey, pkey.data()));
    if(pkey.empty() || v_salt.empty())
    {
        // TODO: log error
        pkey.clear();
        return pkey;
    }
    
    // Update client proof hash with H(username) and salt -> H(H(N)^H(g), H(username), salt)
    std::vector<uint8_t> hUsername(EVP_MAX_MD_SIZE, 0);
    if(EVP_Digest(username, strlen(username), hUsername.data(), NULL, EVP_sha512(), NULL) != 1
        || EVP_DigestUpdate(srp_ctx->c_proof, hUsername.data(), hUsername.size()) != 1
        || EVP_DigestUpdate(srp_ctx->c_proof,v_salt.data(), v_salt.size()) != 1)
    {
        // TODO: log error
        pkey.clear();
        return pkey;
    }
    
    // Return salt if necessary
    if(salt != nullptr)
    {
        salt->assign(v_salt.begin(), v_salt.end());
    }

    return pkey;
}

std::vector<uint8_t> SRP::generateKey(
    SRP_CTX* srp_ctx,
    const char* username, const char* password)
{
    return _generateKey(srp_ctx, nullptr, username, password);
}

std::vector<uint8_t> SRP::generateKey(
    SRP_CTX* srp_ctx, 
    std::vector<uint8_t>& salt, 
    const char* username, const char* password)
{
    return _generateKey(srp_ctx, &salt, username, password);
}

std::vector<uint8_t> SRP::computeSecret(
    SRP_CTX* srp_ctx, 
    const std::vector<uint8_t>& c_pkey)
{
    std::vector<uint8_t> secret;

    if(srp_ctx == nullptr) return secret;

    // Update client proof hash with client pkey -> H(H(N)^H(g), H(username), salt, c_pkey)
    if(EVP_DigestUpdate(srp_ctx->c_proof, c_pkey.data(), c_pkey.size()) != 1)
    {
        // TODO: log error
        return secret;
    }

    // Convert controller pkey to BIGNUM
    BIGNUM* controller_pkey = BN_bin2bn(c_pkey.data(), c_pkey.size(), NULL);
    if(controller_pkey == NULL)
    {
        return secret;
    }

    // Compute u parameter
    BIGNUM* u = SRP_Calc_u(controller_pkey, srp_ctx->pkey, srp_ctx->gN->N);
    if(u == NULL)
    {
        OPENSSL_free(controller_pkey);

        // TODO: log error
        return secret;
    }

    // Compute shared secret
    BIGNUM* bn_secret = SRP_Calc_server_key(controller_pkey, srp_ctx->verifier, u, 
        srp_ctx->b, srp_ctx->gN->N);
    if(bn_secret == NULL)
    {
        OPENSSL_free(controller_pkey);
        OPENSSL_free(u);

        // TODO: log error
        return secret;
    }

    // Store secret as byte vector
    secret.resize(BN_num_bytes(bn_secret));
    secret.resize(BN_bn2bin(bn_secret, secret.data()));
    if(secret.empty())
    {
        OPENSSL_free(bn_secret);

        // TODO: log error
        return secret;
    }

    return secret;
}

int SRP::verifyProof(
    SRP_CTX* srp_ctx, 
    const std::vector<uint8_t>& secret,
    const std::vector<uint8_t>& c_proof)
{
    if(srp_ctx == nullptr) return -1;

    // Get pkey bytes vector
    std::vector<uint8_t> pkey(BN_bn2bin(srp_ctx->pkey, NULL));
    pkey.resize(BN_bn2bin(srp_ctx->pkey, pkey.data()));
    if(pkey.empty())
    {
        // TODO: log error
        return -1;
    }

    // Complete client proof computation with pkey and secret
    // -> H(H(N)^H(g), H(username), salt, c_pkey, pkey, secret)
    std::vector<uint8_t> server_c_proof(EVP_MAX_MD_SIZE, 0);
    if(EVP_DigestUpdate(srp_ctx->c_proof, pkey.data(), pkey.size()) == 1)
    if(EVP_DigestUpdate(srp_ctx->c_proof, secret.data(), secret.size()) == 1)
    if(EVP_DigestFinal(srp_ctx->c_proof, server_c_proof.data(), NULL) == 1)
    {
        // Compare computed proof with client proof from client
        return server_c_proof.size() == c_proof.size() &&
            memcmp(c_proof.data(), server_c_proof.data(), server_c_proof.size());
    }

    // TODO: log error
    return -1;
}

std::vector<uint8_t> SRP::computeProof(
    const std::vector<uint8_t>& c_pkey,
    const std::vector<uint8_t>& c_proof,
    const std::vector<uint8_t>& secret)
{
    std::vector<uint8_t> proof(EVP_MAX_MD_SIZE, 0);

    // Compute server proof as H(c_pkey, c_proof, secret)
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if(mdctx != NULL)
    {
        if(EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) == 1)
        if(EVP_DigestUpdate(mdctx, c_pkey.data(), c_pkey.size()) == 1)
        if(EVP_DigestUpdate(mdctx, c_proof.data(), c_proof.size()) == 1)
        if(EVP_DigestUpdate(mdctx, secret.data(), secret.size()) == 1)
        if(EVP_DigestFinal_ex(mdctx, proof.data(), NULL) == 1)
        {
            return proof;
        }
        EVP_MD_CTX_free(mdctx);
    }

    // TODO: log error

    proof.clear();
    return proof;
}