#ifndef HAP_SERVER_TLVERROR
#define HAP_SERVER_TLVERROR

namespace hap {
namespace server {
namespace tlv {

    enum TLVError : unsigned char
    {
        kTLVError_Unknown               = 0x01,
        kTLVError_Authentication        = 0x02,
        kTLVError_Backoff               = 0x03,
        kTLVError_MaxPeers              = 0x04,
        kTLVError_MaxTries              = 0x05,
        kTLVError_Unavailable           = 0x06,
        kTLVError_Busy                  = 0x07
    };

}
}
}

#endif