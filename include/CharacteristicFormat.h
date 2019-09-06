#ifndef HAP_CHARACTERISTICFORMAT
#define HAP_CHARACTERISTICFORMAT

#include <string>

namespace hap {

    enum CharacteristicFormat {
        kFormat_bool,
        kFormat_uint8,
        kFormat_uint16,
        kFormat_uint32,
        kFormat_uint64,
        kFormat_int,
        kFormat_float,
        kFormat_string,
        kFormat_tlv8,
        kFormat_data,
        kFormat_invalid
    };

    extern CharacteristicFormat to_format(const std::string& format);

    extern std::string to_format_string(CharacteristicFormat format);

}

#endif