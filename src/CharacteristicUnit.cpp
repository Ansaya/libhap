#include <CharacteristicUnit.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <tuple>

using namespace hap;

static constexpr std::array<std::pair<const char*, CharacteristicUnit>, 5> strToUnit = {
    std::make_pair("celsius", CharacteristicUnit::kUnit_celsius),
    std::make_pair("percentage", CharacteristicUnit::kUnit_percentage),
    std::make_pair("arcdegrees", CharacteristicUnit::kUnit_arcdegrees),
    std::make_pair("lux", CharacteristicUnit::kUnit_lux),
    std::make_pair("seconds", CharacteristicUnit::kUnit_seconds)
};

CharacteristicUnit hap::to_unit(const std::string& unit)
{
    auto it = std::find_if(strToUnit.begin(), strToUnit.end(), 
        [&](const std::pair<const char*, CharacteristicUnit> stm)
        { return strcasecmp(unit.c_str(), stm.first); });

    if(it != strToUnit.end())
    {
        return it->second;
    }

    return CharacteristicUnit::kUnit_no_unit;
}

std::string hap::to_unit_string(CharacteristicUnit unit)
{
    auto it = std::find_if(strToUnit.begin(), strToUnit.end(), 
        [&](const std::pair<const char*, CharacteristicUnit> stm)
        { return unit == stm.second; });

    if(it != strToUnit.end())
    {
        return it->first;
    }

    return std::string("");
}