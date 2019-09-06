#include <CharacteristicFormat.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <tuple>

using namespace hap;

static constexpr std::array<std::pair<const char*, CharacteristicFormat>, 10> strToFormat = {
    std::make_pair("bool", CharacteristicFormat::kFormat_bool),
    std::make_pair("uint8", CharacteristicFormat::kFormat_uint8),
    std::make_pair("uint16", CharacteristicFormat::kFormat_uint16),
    std::make_pair("uint32", CharacteristicFormat::kFormat_uint32),
    std::make_pair("uint64", CharacteristicFormat::kFormat_uint64),
    std::make_pair("int", CharacteristicFormat::kFormat_int),
    std::make_pair("float", CharacteristicFormat::kFormat_float),
    std::make_pair("string", CharacteristicFormat::kFormat_string),
    std::make_pair("tlv8", CharacteristicFormat::kFormat_tlv8),
    std::make_pair("data", CharacteristicFormat::kFormat_data)
};

CharacteristicFormat hap::to_format(const std::string& format)
{
    auto it = std::find_if(strToFormat.begin(), strToFormat.end(), 
        [&](const std::pair<const char*, CharacteristicFormat> stm)
        { return strcasecmp(format.c_str(), stm.first); });

    if(it != strToFormat.end())
    {
        return it->second;
    }

    return CharacteristicFormat::kFormat_invalid;
}

std::string hap::to_format_string(CharacteristicFormat format)
{
    auto it = std::find_if(strToFormat.begin(), strToFormat.end(), 
        [&](const std::pair<const char*, CharacteristicFormat> stm)
        { return format == stm.second; });

    if(it != strToFormat.end())
    {
        return it->first;
    }

    return std::string("");
}