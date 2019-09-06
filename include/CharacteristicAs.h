#ifndef HAP_CHARACTERISTICAS
#define HAP_CHARACTERISTICAS

#include <hap_export.h>
#include <Characteristic.h>
#include <CharacteristicFormat.h>

#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>
#include <vector>

namespace hap {

    struct CharacteristicAsBase { };
    struct CharacteristicAsData { size_t _maxDataLen = 2097152; };
    struct CharacteristicAsString { uint8_t _maxLen = 64; };
    
    template<typename T>
    struct CharacteristicAsStep { 
        T _minValue; T _maxValue; T _minStep;
    };

    template<CharacteristicFormat F>
    class CharacteristicAs 
        : virtual public Characteristic, 
        private std::conditional_t<kFormat_data == F, CharacteristicAsData, 
            std::conditional_t<kFormat_string == F, CharacteristicAsString, 
            std::conditional_t<kFormat_int == F, CharacteristicAsStep<int>, 
            std::conditional_t<kFormat_float == F, CharacteristicAsStep<float>,
            CharacteristicAsBase>>>>
    {
    public:
        using FormatType = std::conditional_t<kFormat_bool == F, bool, 
            std::conditional_t<kFormat_uint8 == F, uint8_t, 
            std::conditional_t<kFormat_uint16 == F, uint16_t,
            std::conditional_t<kFormat_uint32 == F, uint32_t,
            std::conditional_t<kFormat_uint64 == F, uint64_t,
            std::conditional_t<kFormat_int == F, int, 
            std::conditional_t<kFormat_float == F, float, 
            std::conditional_t<kFormat_string == F, std::string, 
                std::vector<uint8_t>>>>>>>>>;

        CharacteristicAs(const CharacteristicAs&) = delete;
        CharacteristicAs& operator=(const CharacteristicAs&) = delete;

        HAP_EXPORT virtual ~CharacteristicAs();

        HAP_EXPORT std::string getStringValue() const override;

        HAP_EXPORT virtual FormatType getValue() const = 0;
        
        HAP_EXPORT virtual void setValue(FormatType value) = 0;

        template<typename D = void>
        HAP_EXPORT std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
        setMaxValue(FormatType maxValue);

        template<typename D = FormatType>
        HAP_EXPORT std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
        getMaxValue() const;

        template<typename D = void>
        HAP_EXPORT std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
        setMinValue(FormatType minValue);

        template<typename D = FormatType>
        HAP_EXPORT std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
        getMinValue() const;

        template<typename D = void>
        HAP_EXPORT std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
        setMinStep(FormatType minStep);

        template<typename D = FormatType>
        HAP_EXPORT std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
        getMinStep() const;

        template<typename D = void>
        HAP_EXPORT std::enable_if_t<kFormat_string == F, D> setMaxLen(uint8_t len);

        template<typename D = uint8_t>
        HAP_EXPORT std::enable_if_t<kFormat_string == F, D> getMaxLen() const;

        template<typename D = void>
        HAP_EXPORT std::enable_if_t<kFormat_data == F, D> setMaxDataLen(size_t len);

        template<typename D = size_t>
        HAP_EXPORT std::enable_if_t<kFormat_data == F, D> getMaxDataLen() const;

    protected:
        CharacteristicAs(
            CharacteristicType type,
            const std::vector<CharacteristicPermission>& perms,
            CharacteristicUnit unit = kUnit_no_unit);

    };

    template<CharacteristicFormat F>
    CharacteristicAs<F>::~CharacteristicAs()
    {
    }

    template<CharacteristicFormat F>
    std::string CharacteristicAs<F>::getStringValue() const
    {
        return std::to_string(getValue());
    }

    template<>
    std::string CharacteristicAs<kFormat_string>::getStringValue() const
    {
        return getValue();
    }

    template<>
    std::string CharacteristicAs<kFormat_tlv8>::getStringValue() const
    {
        std::vector<uint8_t> tlv8 = getValue();

        return std::string((char*)tlv8.data(), tlv8.size());
    }

    template<>
    std::string CharacteristicAs<kFormat_data>::getStringValue() const
    {
        std::vector<uint8_t> tlv8 = getValue();

        return std::string((char*)tlv8.data(), tlv8.size());
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
    CharacteristicAs<F>::setMaxValue(FormatType maxValue)
    {
        CharacteristicAsStep<FormatType>::_maxValue = maxValue;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
    CharacteristicAs<F>::getMaxValue() const
    {
        return CharacteristicAsStep<FormatType>::_maxValue;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
    CharacteristicAs<F>::setMinValue(FormatType minValue)
    {
        CharacteristicAsStep<FormatType>::_minValue = minValue;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
    CharacteristicAs<F>::getMinValue() const
    {
        return CharacteristicAsStep<FormatType>::_minValue;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
    CharacteristicAs<F>::setMinStep(FormatType minStep)
    {
        CharacteristicAsStep<FormatType>::_minStep = minStep;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_int == F || kFormat_float == F, D> 
    CharacteristicAs<F>::getMinStep() const
    {
        return CharacteristicAsStep<FormatType>::_minStep;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_string == F, D> 
    CharacteristicAs<F>::setMaxLen(uint8_t len)
    {
        CharacteristicAsString::_maxLen = len;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_string == F, D> 
    CharacteristicAs<F>::getMaxLen() const
    {
        return CharacteristicAsString::_maxLen;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_data == F, D> 
    CharacteristicAs<F>::setMaxDataLen(size_t len)
    {
        CharacteristicAsData::_maxDataLen = len;
    }

    template<CharacteristicFormat F>
    template<typename D>
    std::enable_if_t<kFormat_data == F, D> 
    CharacteristicAs<F>::getMaxDataLen() const
    {
        return CharacteristicAsData::_maxDataLen;
    }

    template<CharacteristicFormat F>
    CharacteristicAs<F>::CharacteristicAs(
        CharacteristicType type,
        const std::vector<CharacteristicPermission>& perms,
        CharacteristicUnit unit)
        : Characteristic(F, type, perms, unit)
    {
    }

}

#endif