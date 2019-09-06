#include <Characteristic.h>

#include <CharacteristicAsInternal.h>

using namespace hap;

std::shared_ptr<Characteristic> Characteristic::make_shared(
    CharacteristicFormat format,
    CharacteristicType type,
    const std::vector<CharacteristicPermission>& perms,
    CharacteristicUnit unit)
{
    switch (format)
    {
    case kFormat_bool:
        return std::make_shared<CharacteristicAsInternal<kFormat_bool>>(type, perms, unit);

    case kFormat_uint8:
        return std::make_shared<CharacteristicAsInternal<kFormat_uint8>>(type, perms, unit);

    case kFormat_uint16:
        return std::make_shared<CharacteristicAsInternal<kFormat_uint16>>(type, perms, unit);

    case kFormat_uint32:
        return std::make_shared<CharacteristicAsInternal<kFormat_uint32>>(type, perms, unit);

    case kFormat_uint64:
        return std::make_shared<CharacteristicAsInternal<kFormat_uint64>>(type, perms, unit);

    case kFormat_int:
        return std::make_shared<CharacteristicAsInternal<kFormat_int>>(type, perms, unit);

    case kFormat_float:
        return std::make_shared<CharacteristicAsInternal<kFormat_float>>(type, perms, unit);

    case kFormat_string:
        return std::make_shared<CharacteristicAsInternal<kFormat_string>>(type, perms, unit);

    case kFormat_tlv8:
        return std::make_shared<CharacteristicAsInternal<kFormat_tlv8>>(type, perms, unit);

    case kFormat_data:
        return std::make_shared<CharacteristicAsInternal<kFormat_data>>(type, perms, unit);
    
    default:
        return nullptr;
    }
}

Characteristic::Characteristic(
    CharacteristicFormat format,
    CharacteristicType type,
    const std::vector<CharacteristicPermission>& perms,
    CharacteristicUnit unit)
    : _format(format), _type(type), _perms(perms), _unit(unit)
{
}

Characteristic::~Characteristic()
{
}

CharacteristicType Characteristic::getType() const
{
    return _type;
}

CharacteristicFormat Characteristic::getFormat() const
{
    return _format;
}

CharacteristicUnit Characteristic::getUnit() const
{
    return _unit;
}

const std::vector<CharacteristicPermission>& Characteristic::getPermissions() const
{
    return _perms;
}