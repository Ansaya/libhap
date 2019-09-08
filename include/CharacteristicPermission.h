#ifndef HAP_CHARACTERISTICPERMISSION
#define HAP_CHARACTERISTICPERMISSION

#include <hap_export.h>

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

    HAP_EXPORT extern CharacteristicPermission to_permission(const std::string& permission);

    HAP_EXPORT extern std::string to_permission_string(CharacteristicPermission permission);

}

#endif