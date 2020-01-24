#include <server/crypto/SRP.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/srp.h>

#include <string>

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
        std::vector<uint8_t> N(BN_num_bytes(gN->N), 0), g(BN_num_bytes(gN->g), 0);
        BN_bn2bin(gN->N, N.data());
        BN_bn2bin(gN->g, g.data());

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
            if(EVP_DigestInit_ex(c_proof, EVP_sha512(), NULL) == 1)
            if(EVP_DigestUpdate(c_proof, hNxorhg.data(), hNxorhg.size()) == 1)
            {
                return new srp_ctx_t(gN, c_proof);
            }
        }
        EVP_MD_CTX_free(c_proof);
    }

    return NULL;
}

void SRP::ctxFree(SRP_CTX* srp_ctx)
{
    if(srp_ctx != nullptr)
        delete srp_ctx;
}

/**
 * @brief Compute verifier and public server key as specified in SRP-6a version
 * 
 * @param verifier Verifier result
 * @param pkey Public server key result
 * @param username Client username
 * @param password Client password
 * @param g_BN Generator
 * @param N_BN Modulus
 * @param b_BN Private server key
 * @param salt_BN Salt
 * @return int Return 1 on success, 0 on error
 */
static int _SRP_create_verifier_pkey(
    BIGNUM** verifier, 
    BIGNUM** pkey,
    const char* username, 
    const char* password, 
    const BIGNUM* g_BN, 
    const BIGNUM* N_BN, 
    const BIGNUM* b_BN,
    const BIGNUM* salt_BN)
{
    std::vector<uint8_t> x(EVP_MAX_MD_SIZE, 0), up(EVP_MAX_MD_SIZE, 0), k(EVP_MAX_MD_SIZE, 0);
    std::vector<uint8_t> gPAD(BN_num_bytes(N_BN), 0), N(BN_num_bytes(N_BN), 0), salt(BN_num_bytes(salt_BN), 0);
    BN_bn2binpad(g_BN, gPAD.data(), gPAD.size());
    BN_bn2bin(N_BN, N.data());
    BN_bn2bin(salt_BN, salt.data());

    std::string user_pass(username);
    user_pass.append(":");
    user_pass.append(password);
    
    // up = H(I | ':' | p)
    int succ = EVP_Digest(user_pass.data(), user_pass.size(), up.data(), NULL, EVP_sha512(), NULL);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(md_ctx != NULL)
    {
        // k = H(N, g)
        succ &= EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);
        succ &= EVP_DigestUpdate(md_ctx, N.data(), N.size());
        succ &= EVP_DigestUpdate(md_ctx, gPAD.data(), gPAD.size());
        succ &= EVP_DigestFinal_ex(md_ctx, k.data(), NULL);

        // x = H(s, H(I | ':' | p))
        succ &= EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);
        succ &= EVP_DigestUpdate(md_ctx, salt.data(), salt.size());
        succ &= EVP_DigestUpdate(md_ctx, up.data(), up.size());
        succ &= EVP_DigestFinal_ex(md_ctx, x.data(), NULL);

        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
    }

    BIGNUM* k_BN = BN_bin2bn(k.data(), k.size(), NULL);
    BIGNUM* x_BN = BN_bin2bn(x.data(), x.size(), NULL);
    BIGNUM* kv = BN_new();

    if(*verifier == NULL)
    {
        *verifier = BN_new();
    }
    if(*pkey == NULL)
    {
        *pkey = BN_new();
    }
    
    BN_CTX* bn_ctx = BN_CTX_new();

    // verifier = g^x % N
    succ &= BN_mod_exp(*verifier, g_BN, x_BN, N_BN, bn_ctx);

    // pkey = (kv + g^b) % N
    succ &= BN_mul(kv, k_BN, *verifier, bn_ctx);
    succ &= BN_mod_exp(*pkey, g_BN, b_BN, N_BN, bn_ctx);
    succ &= BN_mod_add(*pkey, *pkey, kv, N_BN, bn_ctx);

    BN_CTX_free(bn_ctx);
    BN_free(kv);

    succ &= SRP_Verify_B_mod_N(*pkey, N_BN);

    return succ;
}

static inline std::vector<uint8_t> _generateKey(
    SRP_CTX* srp_ctx, 
    const std::vector<uint8_t>* priv_key,
    std::vector<uint8_t>* salt, 
    const char* username, const char* password)
{
    std::vector<uint8_t> pkey;

    if(srp_ctx == nullptr || srp_ctx->salt != NULL || 
        srp_ctx->verifier != NULL || srp_ctx->b != NULL || 
        srp_ctx->pkey != NULL) return pkey;

    // Set user provided salt if any
    if(salt != nullptr && salt->size() == 16)
    {
        srp_ctx->salt = BN_bin2bn(salt->data(), salt->size(), NULL);
    }
    else
    {
         // Generate some randomness for salt
        uint8_t v_rand[16];
        RAND_bytes(v_rand, sizeof(v_rand));
        srp_ctx->salt = BN_bin2bn(v_rand, sizeof(v_rand), NULL);
    }    

    // Set user provided private key or generate one
    if(priv_key != nullptr && priv_key->size() == 32)
    {
        srp_ctx->b = BN_bin2bn(priv_key->data(), priv_key->size(), NULL);
    }
    else
    {
        // Generate some randomness for private key
        uint8_t v_rand[32];
        RAND_bytes(v_rand, sizeof(v_rand));
        srp_ctx->b = BN_bin2bn(v_rand, sizeof(v_rand), NULL);
    }
    
    if(srp_ctx->b == NULL) 
    {
        return pkey; 
    }

    // Compute verifier and public key
    if(_SRP_create_verifier_pkey(&srp_ctx->verifier, &srp_ctx->pkey, 
        username, password, srp_ctx->gN->g, srp_ctx->gN->N, srp_ctx->b, srp_ctx->salt) != 1)
    {
        // TODO: log error
        return pkey;
    }
            
    // Store SRP salt and public key as uint8_t vectors
    std::vector<uint8_t> v_salt(BN_num_bytes(srp_ctx->salt), 0);
    BN_bn2bin(srp_ctx->salt, v_salt.data());
    pkey.resize(BN_num_bytes(srp_ctx->pkey), 0);
    BN_bn2bin(srp_ctx->pkey, pkey.data());
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
        || EVP_DigestUpdate(srp_ctx->c_proof, v_salt.data(), v_salt.size()) != 1)
    {
        // TODO: log error
        pkey.clear();
        return pkey;
    }
    
    // Return salt if necessary
    if(salt != nullptr && salt->empty())
    {
        salt->assign(v_salt.begin(), v_salt.end());
    }

    return pkey;
}

std::vector<uint8_t> SRP::generateKey(
    SRP_CTX* srp_ctx,
    const char* username, const char* password)
{
    return _generateKey(srp_ctx, nullptr, nullptr, username, password);
}

std::vector<uint8_t> SRP::generateKey(
    SRP_CTX* srp_ctx, 
    std::vector<uint8_t>& salt, 
    const char* username, const char* password)
{
    return _generateKey(srp_ctx, nullptr, &salt, username, password);
}

std::vector<uint8_t> SRP::generateKey(
    SRP_CTX* srp_ctx, 
    const std::vector<uint8_t>& priv_key,
    std::vector<uint8_t>& salt, 
    const char* username, const char* password)
{
    return _generateKey(srp_ctx, &priv_key, &salt, username, password);
}

static int _SRP_compute_secret(
    BIGNUM** secret_BN, 
    const BIGNUM* b_BN,
    const BIGNUM* pkey_BN, 
    const BIGNUM* verifier,
    const BIGNUM* c_pkey_BN, 
    const BIGNUM* N_BN)
{
    std::vector<uint8_t> u(EVP_MAX_MD_SIZE, 0), pkey(BN_num_bytes(N_BN), 0), c_pkey(BN_num_bytes(N_BN), 0);
    BN_bn2binpad(pkey_BN, pkey.data(), pkey.size());
    BN_bn2binpad(c_pkey_BN, c_pkey.data(), c_pkey.size());

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    int succ = md_ctx != NULL;
    if(succ)
    {
        // u = H(PAD(c_pkey), PAD(pkey))
        succ &= EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);
        succ &= EVP_DigestUpdate(md_ctx, c_pkey.data(), c_pkey.size());
        succ &= EVP_DigestUpdate(md_ctx, pkey.data(), pkey.size());
        succ &= EVP_DigestFinal_ex(md_ctx, u.data(), NULL);

        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
    }

    BIGNUM* u_BN = BN_bin2bn(u.data(), u.size(), NULL);
    if(*secret_BN == NULL)
    {
        *secret_BN = BN_new();
    }

    BN_CTX* bn_ctx = BN_CTX_new();

    // secret_BN = (c_pkey * verifier ^ u) ^ b % N
    succ &= BN_mod_exp(*secret_BN, verifier, u_BN, N_BN, bn_ctx);
    succ &= BN_mod_mul(*secret_BN, *secret_BN, c_pkey_BN, N_BN, bn_ctx);
    succ &= BN_mod_exp(*secret_BN, *secret_BN, b_BN, N_BN, bn_ctx);

    BN_CTX_free(bn_ctx);
    
    return succ;
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

    // Compute shared secret
    BIGNUM* bn_secret = NULL;
    if(_SRP_compute_secret(&bn_secret, srp_ctx->b, srp_ctx->pkey, srp_ctx->verifier, controller_pkey, srp_ctx->gN->N) != 1)
    {
        OPENSSL_free(controller_pkey);

        // TODO: log error
        return secret;
    }
    OPENSSL_free(controller_pkey);

    // Store secret as byte vector
    secret.resize(BN_num_bytes(bn_secret), 0);
    if(!BN_bn2bin(bn_secret, secret.data()))
    {
        OPENSSL_free(bn_secret);

        // TODO: log error
        secret.clear();
        return secret;
    }
    OPENSSL_free(bn_secret);

    return secret;
}

int SRP::verifyProof(
    SRP_CTX* srp_ctx, 
    const std::vector<uint8_t>& secret,
    const std::vector<uint8_t>& c_proof)
{
    if(srp_ctx == nullptr || c_proof.size() != EVP_MAX_MD_SIZE) return -1;

    // Get pkey bytes vector
    std::vector<uint8_t> pkey(BN_num_bytes(srp_ctx->pkey), 0);
    BN_bn2bin(srp_ctx->pkey, pkey.data());
    if(pkey.empty())
    {
        // TODO: log error
        return -1;
    }

    // Complete client proof computation with pkey and secret
    // -> H(H(N)^H(g), H(username), salt, c_pkey, pkey, secret)
    std::vector<uint8_t> server_c_proof(EVP_MAX_MD_SIZE, 0);
    if(EVP_DigestUpdate(srp_ctx->c_proof, secret.data(), secret.size()) == 1)
    if(EVP_DigestFinal_ex(srp_ctx->c_proof, server_c_proof.data(), NULL) == 1)
    {
        // Compare computed proof with client proof from client
        return CRYPTO_memcmp(c_proof.data(), server_c_proof.data(), server_c_proof.size());
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
            EVP_MD_CTX_free(mdctx);
            return proof;
        }
        EVP_MD_CTX_free(mdctx);
    }

    // TODO: log error

    proof.clear();
    return proof;
}