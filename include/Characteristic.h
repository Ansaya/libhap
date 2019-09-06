#ifndef HAP_CHARACTERISTIC
#define HAP_CHARACTERISTIC

#include <hap_export.h>
#include <CharacteristcType.h>
#include <CharacteristicFormat.h>
#include <CharacteristicPermission.h>
#include <CharacteristicUnit.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hap {

    template<CharacteristicFormat F>
    class CharacteristicAs;

    class Characteristic
    {
    public:
        HAP_EXPORT static std::shared_ptr<Characteristic> make_shared(
            CharacteristicFormat format, 
            CharacteristicType type,
            const std::vector<CharacteristicPermission>& perms,
            CharacteristicUnit unit = kUnit_no_unit);

        template<CharacteristicFormat F>
        HAP_EXPORT static std::shared_ptr<CharacteristicAs<F>> make_shared(
            CharacteristicType type,
            const std::vector<CharacteristicPermission>& perms,
            CharacteristicUnit unit = kUnit_no_unit);

        Characteristic(const Characteristic&) = delete;
        Characteristic& operator=(const Characteristic&) = delete;

        HAP_EXPORT virtual ~Characteristic();

        HAP_EXPORT virtual uint64_t getID() const = 0;
        
        HAP_EXPORT CharacteristicType getType() const;

        HAP_EXPORT CharacteristicFormat getFormat() const;

        HAP_EXPORT CharacteristicUnit getUnit() const;

        HAP_EXPORT const std::vector<CharacteristicPermission>& getPermissions() const;

        HAP_EXPORT virtual std::string getStringValue() const = 0;

    protected:
        Characteristic(
            CharacteristicFormat format,
            CharacteristicType type,
            const std::vector<CharacteristicPermission>& perms,
            CharacteristicUnit unit = kUnit_no_unit);

    private:
        const CharacteristicFormat _format;
        const CharacteristicType _type;
        const std::vector<CharacteristicPermission> _perms;
        const CharacteristicUnit _unit;

    };

    template<CharacteristicFormat F>
    std::shared_ptr<CharacteristicAs<F>> Characteristic::make_shared(
        CharacteristicType type,
        const std::vector<CharacteristicPermission>& perms,
        CharacteristicUnit unit)
    {
        return std::dynamic_pointer_cast<CharacteristicAs<F>>(make_shared(F, type, perms, unit));
    }

}

#endif