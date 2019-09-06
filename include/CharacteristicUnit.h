#ifndef HAP_CHARACTERISTICUNIT
#define HAP_CHARACTERISTICUNIT

#include <string>

namespace hap {

    enum CharacteristicUnit {
        kUnit_celsius ,
        kUnit_percentage ,
        kUnit_arcdegrees ,
        kUnit_lux ,
        kUnit_seconds,
        kUnit_no_unit
    };

    extern CharacteristicUnit to_unit(const std::string& unit);

    extern std::string to_unit_string(CharacteristicUnit unit);

}

#endif