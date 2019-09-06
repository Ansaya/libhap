#include <CharacteristicPermission.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <tuple>

using namespace hap;

static constexpr std::array<std::pair<const char*, CharacteristicPermission>, 7> strToPermission = {
    std::make_pair("pr", CharacteristicPermission::kPermission_PairedRead),
    std::make_pair("pw", CharacteristicPermission::kPermission_PairedWrite),
    std::make_pair("ev", CharacteristicPermission::kPermission_Events),
    std::make_pair("aa", CharacteristicPermission::kPermission_AdditionAuthorization),
    std::make_pair("tw", CharacteristicPermission::kPermission_TimedWrite),
    std::make_pair("hd", CharacteristicPermission::kPermission_Hidden),
    std::make_pair("wr", CharacteristicPermission::kPermission_WriteResponse),
};

CharacteristicPermission hap::to_permission(const std::string& permission)
{
    auto it = std::find_if(strToPermission.begin(), strToPermission.end(), 
        [&](const std::pair<const char*, CharacteristicPermission> stm)
        { return strcasecmp(permission.c_str(), stm.first); });

    if(it != strToPermission.end())
    {
        return it->second;
    }

    return CharacteristicPermission::kPermission_Invalid;
}

std::string hap::to_permission_string(CharacteristicPermission permission)
{
    auto it = std::find_if(strToPermission.begin(), strToPermission.end(), 
        [&](const std::pair<const char*, CharacteristicPermission> stm)
        { return permission == stm.second; });

    if(it != strToPermission.end())
    {
        return it->first;
    }

    return std::string("");
}