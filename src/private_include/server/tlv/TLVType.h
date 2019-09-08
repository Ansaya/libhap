#ifndef HAP_SERVER_TLVTYPE
#define HAP_SERVER_TLVTYPE

namespace hap {
namespace server {
namespace tlv {

    enum TLVType : unsigned char
    {
        kTLVType_Method                 = 0x00,
        kTLVType_Identifier             = 0x01,
        kTLVType_Salt                   = 0x02,
        kTLVType_PublicKey              = 0x03,
        kTLVType_Proof                  = 0x04,
        kTLVType_EncryptedData          = 0x05,
        kTLVType_State                  = 0x06,
        kTLVType_Error                  = 0x07,
        kTLVType_RetryDelay             = 0x08,
        kTLVType_Certificate            = 0x09,
        kTLVType_Signature              = 0x0A,
        kTLVType_Permissions            = 0x0B,
        kTLVType_FragmentD              = 0x0C,
        kTLVType_FragmentLast           = 0x0D,
        kTLVType_Flags                  = 0x13,
        kTLVType_Separator              = 0xFF
    };

}
}
}

#endif