#include <server/PairingHandler.h>

#include <server/crypto/ChaCha20Poly1305.h>
#include <server/crypto/Ed25519.h>
#include <server/crypto/HKDF.h>
#include <server/tlv/TLVType.h>
#include <server/tlv/TLVMethod.h>
#include <server/tlv/TLVError.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#define HAP_SERVER_HKDF_TRANSIENT_SALT      (const uint8_t*)"Pair-Setup-Encrypt-Salt"
#define HAP_SERVER_HKDF_TRANSIENT_INFO      (const uint8_t*)"Pair-Setup-Encrypt-Info"

#define HAP_SERVER_HKDF_CONTROLLER_SALT     (const uint8_t*)"Pair-Setup-Controller-Sign-Salt"
#define HAP_SERVER_HKDF_CONTROLLER_INFO     (const uint8_t*)"Pair-Setup-Controller-Sign-Info"

#define HAP_SERVER_HKDF_ACCESSORY_SALT      (const uint8_t*)"Pair-Setup-Accessory-Sign-Salt"
#define HAP_SERVER_HKDF_ACCESSORY_INFO      (const uint8_t*)"Pair-Setup-Accessory-Sign-Info"

#define HAP_SERVER_HKDF_VERIFY_SALT         (const uint8_t*)"Pair-Verify-Encrypt-Salt"
#define HAP_SERVER_HKDF_VERIFY_INFO         (const uint8_t*)"Pair-Verify-Encrypt-Info"

using namespace hap::server;


PairingHandler::PairingHandler(
    const std::string& accessory_id,
    const std::string& setup_code, 
    std::shared_ptr<EncryptionKeyStore> e_key_store)
    : _accessoryID(accessory_id), 
    _setupCode(setup_code), _setupCodeDisplay(nullptr), _eKeyStore(e_key_store), 
    _srpContext(nullptr), _currentPairingFlags(0), _sessionKey(HAP_SERVER_CRYPTO_CHACHA20_KEY_LENGTH, 0),
    _clientVerified(false)
{
    bool valid_setup_code = setup_code.size() == 10
		&& std::isdigit(setup_code[0]) && std::isdigit(setup_code[1]) && std::isdigit(setup_code[2])
		&& setup_code[3] == '-'
		&& std::isdigit(setup_code[4]) && std::isdigit(setup_code[5])
		&& setup_code[6] == '-'
		&& std::isdigit(setup_code[7]) && std::isdigit(setup_code[8]) && std::isdigit(setup_code[9]);

    if(!valid_setup_code)
    {
        throw std::invalid_argument("Setup code must be formatted as XXX-XX-XXX where X is 0-9 digit");
    }
}

PairingHandler::PairingHandler(
    const std::string& accessory_id,
    std::function<void(std::string setup_code)> setup_code_display,
    std::shared_ptr<EncryptionKeyStore> e_key_store)
    : _accessoryID(accessory_id),
     _setupCode(""), _setupCodeDisplay(setup_code_display), _eKeyStore(e_key_store),
    _srpContext(nullptr),_currentPairingFlags(0), _sessionKey(HAP_SERVER_CRYPTO_CHACHA20_KEY_LENGTH, 0),
    _clientVerified(false)
{
}

PairingHandler::~PairingHandler()
{
    crypto::SRP::ctxFree(_srpContext);
}

tlv::TLVData PairingHandler::pairSetup(const tlv::TLVData& tlv_data)
{
    tlv::TLVData response;

    PairingState state = (PairingState)tlv_data.getItem(tlv::kTLVType_State)->front();

    switch (state)
    {
    case M1:
        response = _startResponse(tlv_data);
        break;

    case M3:
        response = _verifyResponse(tlv_data);
        break;

    case M5:
        response = _exchangeResponse(tlv_data);
        break;
    
    default:
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        break;
    }

    return response;
}

tlv::TLVData PairingHandler::pairVerify(const tlv::TLVData& tlv_data)
{
    tlv::TLVData response;

    PairingState state = (PairingState)tlv_data.getItem(tlv::kTLVType_State)->front();

    switch (state)
    {
    case M1:
        response = _verifyStartResponse(tlv_data);
        break;

    case M3:
        response = _verifyFinishResponse(tlv_data);
        break;
    
    default:
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        break;
    }

    return response;
}

tlv::TLVData PairingHandler::pairings(const tlv::TLVData& tlv_data)
{

}

std::vector<uint8_t> PairingHandler::encrypt(
    const std::vector<uint8_t>& buffer, const uint8_t nonce[8]) const
{
    if(_clientVerified)
        return _encrypt(buffer.data(), buffer.size(), nonce, false);
    else
        return std::vector<uint8_t>();
}

std::vector<uint8_t> PairingHandler::encrypt(
    const uint8_t* buffer, size_t buffer_length, 
    const uint8_t nonce[8]) const
{
    if(_clientVerified)
        return _encrypt(buffer, buffer_length, nonce, false);
    else
        return std::vector<uint8_t>();
}

std::vector<uint8_t> PairingHandler::decrypt(
    const std::vector<uint8_t>& buffer, const uint8_t nonce[8]) const
{
    if(_clientVerified)
        return _decrypt(buffer.data(), buffer.size(), nonce, false);
    else
        return std::vector<uint8_t>();
}

std::vector<uint8_t> PairingHandler::decrypt(
    const uint8_t* buffer, size_t buffer_length, 
    const uint8_t nonce[8]) const
{
    if(_clientVerified)
        return _decrypt(buffer, buffer_length, nonce, false);
    else
        return std::vector<uint8_t>();
}

/* Pair Setup procedure methods */

tlv::TLVData PairingHandler::_startResponse(const tlv::TLVData& tlv_data)
{
    // Set response state to M2
    tlv::TLVData response;
    response.setItem(tlv::kTLVType_State, {M2});
    response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Authentication});

    // TODO: Check if already paired and return kTLVError_Unavailable

    // TODO: Check max tries and return kTLVError_MaxTries

    // TODO: Check if performing another pairing and return kTLVError_Busy

    // Check for request flags
    const std::vector<uint8_t>* v_flags = tlv_data.getItem(tlv::kTLVType_Flags);
    _currentPairingFlags = 0;
    if(v_flags != nullptr)
    {
        _currentPairingFlags = *(uint32_t*)(v_flags->data());

        // Persist flags in response
        response.setItem(tlv::kTLVType_Flags, *v_flags);
    }

    // Without flags or with transient&split flags set, generate/load setup code
    if((_currentPairingFlags & (kPairingFlag_Split | kPairingFlag_Transient)) 
        || !_currentPairingFlags)
    {
        std::string random_setup_code = _generateSetupCode();
        if(random_setup_code.empty())
        {
            // TODO: log error
            return response;
        }

        _setupCode = random_setup_code;
    }
    // With split flag set, load saved SRP verifier for the setup code
    else if(_currentPairingFlags & kPairingFlag_Split)
    {
        // TODO: check for stored SRP verifier

        if(true/* TODO: SRP verifier not found */)
        {
            // TODO: log error
            return response;
        }
    }

    // Initialize new SRP context
    if(_srpContext != nullptr)
    {
        // TODO: log warning

        crypto::SRP::ctxFree(_srpContext);
        _srpContext = crypto::SRP::ctxNew("3072");
    }

            
    // Generate SRP public key and salt for controller
    std::vector<uint8_t> salt;
    std::vector<uint8_t> pkey = crypto::SRP::generateKey(
        _srpContext, salt, "Pair-Setup", _setupCode.c_str());
    if(pkey.empty())
    {
        // TODO: log error
        return response;
    }
            
    // Compile successful M2 response
    response.setItem(tlv::kTLVType_PublicKey, pkey);
    response.setItem(tlv::kTLVType_Salt, salt);

    response.removeItem(tlv::kTLVType_Error);
    return response;
}

tlv::TLVData PairingHandler::_verifyResponse(const tlv::TLVData& tlv_data)
{
    tlv::TLVData response;
    response.setItem(tlv::kTLVType_State, {M4});
    response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Authentication});

    // Retrieve public key and proof received from controller
    const std::vector<uint8_t>* c_pkey = tlv_data.getItem(tlv::kTLVType_PublicKey);
    const std::vector<uint8_t>* c_proof = tlv_data.getItem(tlv::kTLVType_Proof);
    if(c_pkey == nullptr || c_proof == nullptr || _srpContext == nullptr)
    {
        // TODO: log error
        return response;
    }

    _sharedSecret = crypto::SRP::computeSecret(_srpContext, *c_pkey);
    if(_sharedSecret.empty())
    {
        // TODO: log error
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        return response;
    }

    int client_proof_verified = 
        crypto::SRP::verifyProof(_srpContext, _sharedSecret, *c_proof);

    // 0 means client proof mismatch
    if(client_proof_verified == 0)
    {
        // TODO: log error
        return response;
    }
    // < 0 means an error occurred during proof verification
    else if(client_proof_verified < 0)
    {
        // TODO: log error
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        return response;
    }

    // Compute accessory proof
    std::vector<uint8_t> proof = crypto::SRP::computeProof(*c_pkey, *c_proof, _sharedSecret);
    if(proof.empty())
    {
        // TODO: log error
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        return response;
    }

    // Compute final session key
    std::vector<uint8_t> session_key = 
        crypto::HKDF::derive(HAP_SERVER_CRYPTO_CHACHA20_KEY_LENGTH, 
            HAP_SERVER_HKDF_TRANSIENT_SALT, sizeof(HAP_SERVER_HKDF_TRANSIENT_SALT), 
            _sharedSecret.data(), _sharedSecret.size(), 
            HAP_SERVER_HKDF_TRANSIENT_INFO, sizeof(HAP_SERVER_HKDF_TRANSIENT_INFO));
    if(session_key.empty())
    {
        // TODO: log error
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        return response;
    }

    // Store succesfully computed shared key for transient pair setup
    _sessionKey.assign(session_key.begin(), session_key.end());

    // If performing transient pair setup enable security, setup completed
    if(_currentPairingFlags & kPairingFlag_Transient)
    {
        _clientVerified = true;
    }

    // Send accessory proof back to the controller
    response.setItem(tlv::kTLVType_Proof, proof);

    crypto::SRP::ctxFree(_srpContext); _srpContext = nullptr;

    response.removeItem(tlv::kTLVType_Error);
    return response;
}

tlv::TLVData PairingHandler::_exchangeResponse(const tlv::TLVData& tlv_data)
{
    tlv::TLVData response;
    response.setItem(tlv::kTLVType_State, {M6});
    response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Authentication});

    // Retrieve encrypted sub-TLVData
    const std::vector<uint8_t>* v_encrypted_tlvdata = 
        tlv_data.getItem(tlv::kTLVType_EncryptedData);
    if(v_encrypted_tlvdata == nullptr)
    {
        // TODO: log error
        return response;
    }

    // Attempt sub-TLVData decryption
    std::vector<uint8_t> v_tlvdata = _decrypt(v_encrypted_tlvdata->data(), 
        v_encrypted_tlvdata->size(), (uint8_t*)"PS-Msg05", true);
    if(v_tlvdata.empty())
    {
        // TODO: log error
        return response;
    }

    // Parse sub-TLVData buffer
    tlv::TLVData sub_tlv(v_tlvdata);
    const std::vector<uint8_t>* iOSDevicePairingID = sub_tlv.getItem(tlv::kTLVType_Identifier);
    const std::vector<uint8_t>* iOSDeviceLTPK = sub_tlv.getItem(tlv::kTLVType_PublicKey);
    const std::vector<uint8_t>* iOSDeviceSignature = sub_tlv.getItem(tlv::kTLVType_Signature);

    // Compute iOSDeviceX value from previously shared SRP secret
    std::vector<uint8_t> iOSDeviceX = 
        crypto::HKDF::derive(HAP_SERVER_CRYPTO_CHACHA20_KEY_LENGTH, 
            HAP_SERVER_HKDF_CONTROLLER_SALT, sizeof(HAP_SERVER_HKDF_CONTROLLER_SALT),
            _sharedSecret.data(), _sharedSecret.size(),
            HAP_SERVER_HKDF_CONTROLLER_INFO, sizeof(HAP_SERVER_HKDF_CONTROLLER_INFO));
    if(iOSDeviceX.empty() || !iOSDevicePairingID || !iOSDeviceLTPK || !iOSDeviceSignature)
    {
        // TODO: log error
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        return response;
    }
            
    // Construct iOSDeviceInfo concatenating iOSDeviceX, iOSDevicePairingID and iOSDeviceLTPK
    std::vector<uint8_t>& iOSDeviceInfo = iOSDeviceX;
    iOSDeviceInfo.insert(iOSDeviceInfo.end(), 
        iOSDevicePairingID->begin(), iOSDevicePairingID->end());
    iOSDeviceInfo.insert(iOSDeviceInfo.end(), 
        iOSDeviceLTPK->begin(), iOSDeviceLTPK->end());

    // Verify iOSDeviceInfo against controller's signature
    if(!crypto::Ed25519::verify(iOSDeviceInfo.data(), iOSDeviceInfo.size(), 
        iOSDeviceLTPK->data(), iOSDeviceLTPK->size(),
        iOSDeviceSignature->data(), iOSDeviceSignature->size()))
    {
        // TODO: log error
        return response;
    }

    // Store pairing ID and public key on successful verification
    _eKeyStore->storeKey(*iOSDevicePairingID, *iOSDeviceLTPK);

    // Generate AccessoryLTPK and AccessoryLTSK public and secret keys
    std::pair<std::vector<uint8_t>,std::vector<uint8_t>> priv_pub = crypto::Ed25519::generatePair();
    std::vector<uint8_t>& AccessoryLTSK = priv_pub.first;
    std::vector<uint8_t>& AccessoryLTPK = priv_pub.second;

    // Generate AccessoryX from previously shared SRP secret
    std::vector<uint8_t> AccessoryX = 
        crypto::HKDF::derive(HAP_SERVER_CRYPTO_CHACHA20_KEY_LENGTH,
            HAP_SERVER_HKDF_ACCESSORY_SALT, sizeof(HAP_SERVER_HKDF_ACCESSORY_SALT),
            _sharedSecret.data(), _sharedSecret.size(),
            HAP_SERVER_HKDF_ACCESSORY_INFO, sizeof(HAP_SERVER_HKDF_CONTROLLER_INFO));
    if(AccessoryX.empty())
    {
        // TODO: log error
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        return response;
    }

    // Construct AccessoryInfo concatenating AccessoryX, AccessoryPairingID and AccessoryLTPK
    std::vector<uint8_t>& AccessoryInfo = AccessoryX;
    AccessoryInfo.insert(AccessoryInfo.end(), 
        _accessoryID.begin(), _accessoryID.end());
    AccessoryInfo.insert(AccessoryInfo.end(), 
        AccessoryLTPK.begin(), AccessoryLTPK.end());

    // Generate AccessoryInfo signature using AccessoryLTSK
    std::vector<uint8_t> AccessoryInfo_sign = crypto::Ed25519::sign(
        AccessoryInfo.data(), AccessoryInfo.size(), 
        AccessoryLTSK.data(), AccessoryLTSK.size());

    // Construct accessory sub-tlv buffer
    tlv::TLVData accessory_sub_tlv;
    accessory_sub_tlv.setItem(tlv::kTLVType_Identifier, 
        (const uint8_t*)_accessoryID.data(), _accessoryID.size());
    accessory_sub_tlv.setItem(tlv::kTLVType_PublicKey, AccessoryLTPK);
    accessory_sub_tlv.setItem(tlv::kTLVType_Signature, AccessoryInfo_sign);
    std::vector<uint8_t> v_accessory_sub_tlv = accessory_sub_tlv.serialize();

    // Encrypt accessory sub-tlv
    std::vector<uint8_t> v_encrypted_acc_sub_tlv = 
        _encrypt(v_accessory_sub_tlv.data(), v_accessory_sub_tlv.size(), 
            (const uint8_t*)"PS-Msg06", true);
    if(v_encrypted_acc_sub_tlv.empty())
    {
        // TODO: log error
        response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});
        return response;
    }

    // Set SRP client as verified 
    _clientVerified = true;

    // Send encrypted sub-tlv back to the controller
    response.setItem(tlv::kTLVType_EncryptedData, v_encrypted_acc_sub_tlv);
    
    response.removeItem(tlv::kTLVType_Error);
    return response;
}

/* Pair Setup procedure methods end */


/* Pair Verify procedure methods */

tlv::TLVData PairingHandler::_verifyStartResponse(const tlv::TLVData& tlv_data)
{
    tlv::TLVData response;
    response.setItem(tlv::kTLVType_State, {M2});
    response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Unknown});

    // Generate new Ed25519 key pair
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> priv_pub = 
        crypto::Ed25519::generatePair();

    std::vector<uint8_t>& AccessoryLTSK = priv_pub.first;
    std::vector<uint8_t>& AccessoryLTPK = priv_pub.second;
    if(AccessoryLTSK.empty() || AccessoryLTPK.empty())
    {
        // TODO: log error
        return response;
    }

    // Store AccessoryLTPK for later M3 iOSDeviceInfo construction
    _sharedSecret.assign(AccessoryLTPK.begin(), AccessoryLTPK.end());

    // Retrieve controller's public key
    const std::vector<uint8_t>* iOSDeviceLTPK = tlv_data.getItem(tlv::kTLVType_PublicKey);
    if(iOSDeviceLTPK == nullptr)
    {
        // TODO: log error
        return response;
    }

    // Derive shared secret from private key and controller public key
    std::vector<uint8_t> secret = crypto::Ed25519::derive(AccessoryLTSK.data(), 
        AccessoryLTSK.size(), iOSDeviceLTPK->data(), iOSDeviceLTPK->size());
    if(secret.empty())
    {
        // TODO: log error
        return response;
    }

    // Construct AccessoryInfo as AccessoryLTPK|accessoryID|iOSDeviceLTPK
    std::vector<uint8_t> AccessoryInfo(AccessoryLTPK.begin(), AccessoryLTPK.end());
    AccessoryInfo.insert(AccessoryInfo.end(), 
        _accessoryID.begin(), _accessoryID.end());
    AccessoryInfo.insert(AccessoryInfo.end(), 
        iOSDeviceLTPK->begin(), iOSDeviceLTPK->end());

    // Generate AccessoryInfo signature with AccessoryLTSK
    std::vector<uint8_t> AccessorySignature = 
        crypto::Ed25519::sign(AccessoryInfo.data(), AccessoryInfo.size(), 
            AccessoryLTSK.data(), AccessoryLTSK.size());
    if(AccessorySignature.empty())
    {
        // TODO: log error
        return response;
    }

    // Construct sub-TLV with accessoryID and AccessorySignature
    tlv::TLVData sub_tlv;
    sub_tlv.setItem(tlv::kTLVType_Identifier, 
        (const uint8_t*)_accessoryID.data(), _accessoryID.size());
    sub_tlv.setItem(tlv::kTLVType_Signature, AccessorySignature);

    // Derive session key from shared secret
    _sessionKey = crypto::HKDF::derive(HAP_SERVER_CRYPTO_CHACHA20_KEY_LENGTH, 
        HAP_SERVER_HKDF_VERIFY_SALT, sizeof(HAP_SERVER_HKDF_VERIFY_SALT),
        secret.data(), secret.size(),
        HAP_SERVER_HKDF_VERIFY_INFO, sizeof(HAP_SERVER_HKDF_VERIFY_INFO));
    if(_sessionKey.empty())
    {
        // TODO: log error
        return response;
    }

    // Encrypt sub-TLV
    std::vector<uint8_t> v_sub_tlv = sub_tlv.serialize();
    std::vector<uint8_t> encrypted_sub_tlv = _encrypt(v_sub_tlv.data(), 
        v_sub_tlv.size(), (const uint8_t*)"PV-Msg02", true);
    if(encrypted_sub_tlv.empty())
    {
        // TODO: log error
        return response;
    }

    // Construct M2 response
    response.setItem(tlv::kTLVType_PublicKey, AccessoryLTPK);
    response.setItem(tlv::kTLVType_EncryptedData, encrypted_sub_tlv);

    response.removeItem(tlv::kTLVType_Error);
    return response;
}

tlv::TLVData PairingHandler::_verifyFinishResponse(const tlv::TLVData& tlv_data)
{
    tlv::TLVData response;
    response.setItem(tlv::kTLVType_State, {M4});
    response.setItem(tlv::kTLVType_Error, {tlv::kTLVError_Authentication});

    // Retrieve encrypted sub-TLV data
    const std::vector<uint8_t>* encrypted_sub_tlv = 
        tlv_data.getItem(tlv::kTLVType_EncryptedData);
    if(encrypted_sub_tlv == nullptr)
    {
        // TODO: log error
        return response;
    }

    // Attempt sub-TLV data decryption
    std::vector<uint8_t> v_sub_tlv = _decrypt(encrypted_sub_tlv->data(), 
        encrypted_sub_tlv->size(), (const uint8_t*)"PV-Msg03", true);
    if(v_sub_tlv.empty())
    {
        // TODO: log error
        return response;
    }
    
    // Parse sub-TLV data
    tlv::TLVData sub_tlv(v_sub_tlv);
    
    // Retrieve controller's pairing ID and signature
    const std::vector<uint8_t>* iOSDevicePairingID = 
        sub_tlv.getItem(tlv::kTLVType_Identifier);
    const std::vector<uint8_t>* iOSDeviceSignature = 
        sub_tlv.getItem(tlv::kTLVType_Signature);
    if(iOSDevicePairingID == nullptr || iOSDeviceSignature == nullptr)
    {
        // TODO: log error
        return response;
    }

    // Look up iOSDeviceLTPK in list of paired controllers
    const std::vector<uint8_t>* iOSDeviceLTPK = 
        _eKeyStore->getKey(*iOSDevicePairingID);
    if(iOSDeviceLTPK == nullptr)
    {
        // TODO: log error
        return response;
    }

    // Here _sharedSecret will contain AccessoryLTPK stored from _verifyStartResponse
    std::vector<uint8_t>& AccessoryLTPK = _sharedSecret;

    // Construct iOSDeviceInfo as iOSDeviceLTPK|iOSDevicePairingID|AccessoryLTPK
    std::vector<uint8_t> iOSDeviceInfo(iOSDeviceLTPK->begin(), iOSDeviceLTPK->end());
    iOSDeviceInfo.insert(iOSDeviceInfo.end(), 
        iOSDevicePairingID->begin(), iOSDevicePairingID->end());
    iOSDeviceInfo.insert(iOSDeviceInfo.end(), 
        AccessoryLTPK.begin(), AccessoryLTPK.end());

    // Verify iOSDeviceSignature using iOSDeviceLTPK against iOSDeviceInfo
    if(!crypto::Ed25519::verify(iOSDeviceInfo.data(), iOSDeviceInfo.size(), 
        iOSDeviceLTPK->data(), iOSDeviceLTPK->size(), 
        iOSDeviceSignature->data(), iOSDeviceSignature->size()))
    {
        // TODO: log error
        return response;
    }

    // Set SRP client as verified 
    _clientVerified = true;

    // Successful M4 response will contain only state item

    response.removeItem(tlv::kTLVType_Error);
    return response;
}

/* Pair Verify procedure methods */



std::vector<uint8_t> PairingHandler::_encrypt(
    const uint8_t* buffer, size_t buffer_length, 
    const uint8_t nonce[8], bool has_size) const
{
    std::vector<uint8_t> out;

    // Encrypt buffer and get verification tag
    std::vector<uint8_t> vtag;
    std::vector<uint8_t> encrypted_buffer = crypto::ChaCha20Poly1305::encrypt(
        buffer, buffer_length, _sessionKey.data(), nonce, vtag);

    // If encryption was successful build output buffer as encrypted_data|vtag
    if(!encrypted_buffer.empty())
    {
        // Prepend encrypted_data+vtag size if required
        if(has_size)
        {
            uint16_t data_length = encrypted_buffer.size() + vtag.size();
            uint8_t* v_data_length = (uint8_t*)&data_length;
            out.insert(out.begin(), v_data_length, v_data_length + sizeof(data_length));
        }

        out.insert(out.end(), encrypted_buffer.begin(), encrypted_buffer.end());
        out.insert(out.end(), vtag.begin(), vtag.end());

        return out;
    }

    // TODO: log error

    return out;
}

std::vector<uint8_t> PairingHandler::_decrypt(
    const uint8_t* buffer, size_t buffer_length, 
    const uint8_t nonce[8], bool has_size) const
{
    // Setup data and vtag pointers according to buffer format
    size_t data_length = buffer_length - HAP_SERVER_CRYPTO_POLY1305_VTAG_LENGTH;
    const uint8_t *verification_tag = (buffer + data_length);

    // If data size is prepended to buffer, update decryption parameters
    if(has_size)
    {
        data_length = *(uint16_t*)(buffer);
        verification_tag = buffer + buffer_length - HAP_SERVER_CRYPTO_POLY1305_VTAG_LENGTH;
        buffer += 2;
    }
    
    // Decrypt data from buffer and verify against verification tag
    std::vector<uint8_t> out = crypto::ChaCha20Poly1305::decrypt(
        buffer, data_length, verification_tag, _sessionKey.data(), nonce);

    return out;
}

std::string PairingHandler::_generateSetupCode() const
{
    if(_setupCodeDisplay == nullptr)
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
            try {
                _setupCodeDisplay(random_code);
            }
            catch(std::exception& e)
            {
                // TODO: log error
                return std::string();
            }

            return random_code;
        }
    }
}