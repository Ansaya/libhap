#ifndef HAP_CHARACTERISTICPERMISSION
#define HAP_CHARACTERISTICPERMISSION

#include <string>

namespace hap {

    enum CharacteristicPermission
    {
        kPermission_PairedRead,
        kPermission_PairedWrite,
        kPermission_Events,
        kPermission_AdditionAuthorization,
        kPermission_TimedWrite,
        kPermission_Hidden,
        kPermission_WriteResponse,
        kPermission_Invalid
    };

    extern CharacteristicPermission to_permission(const std::string& permission);

    extern std::string to_permission_string(CharacteristicPermission permission);

}

#endif