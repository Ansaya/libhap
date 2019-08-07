#ifndef HAP_SERVER_TLVMETHOD
#define HAP_SERVER_TLVMETHOD

namespace hap {
namespace server {
namespace tlv {

    enum TLVMethod : unsigned char
    {
        kTLVMethod_PairSetup                = 0,
        kTLVMethod_PairSetupWithAuth        = 1,
        kTLVMethod_PairVerify               = 2,
        kTLVMethod_AddPairing               = 3,
        kTLVMethod_RemovePairing            = 4,
        kTLVMethod_ListPairings             = 5
    };

}
}
}

#endif