#ifndef HAP_CHARACTERISTICASINTERNAL
#define HAP_CHARACTERISTICASINTERNAL

#include <CharacteristicInternal.h>
#include <CharacteristicAs.h>

#include <algorithm>
#include <cmath>
#include <mutex>
#include <sstream>
#include <string>

namespace hap {

    template<CharacteristicFormat F>
    class CharacteristicAsInternal : public CharacteristicAs<F>, public CharacteristicInternal
    {
    public:
        CharacteristicAsInternal(
            CharacteristicType type,
            const std::vector<CharacteristicPermission>& perms, 
            CharacteristicUnit unit = kUnit_no_unit);

        CharacteristicAsInternal(const CharacteristicAsInternal&) = delete;
        CharacteristicAsInternal& operator=(const CharacteristicAsInternal&) = delete;

        ~CharacteristicAsInternal();

        uint64_t getID() const override;

        std::string getStringValue() const override;

        typename CharacteristicAs<F>::FormatType getValue() const override;
        
        server::HAPStatus setStringValue(const std::string& value) override;

        int setValue(typename CharacteristicAs<F>::FormatType value) override;

        rapidjson::Document to_json(rapidjson::Document::AllocatorType* allocator = nullptr) const override;

    private:
        mutable std::mutex _mValue;
        typename CharacteristicAs<F>::FormatType _value;
    
    };

    template<CharacteristicFormat F>
    CharacteristicAsInternal<F>::CharacteristicAsInternal(
        CharacteristicType type,
        const std::vector<CharacteristicPermission>& perms, 
        CharacteristicUnit unit)
        : Characteristic(F, type, perms, unit),
        CharacteristicAs<F>(type, perms, unit), 
        CharacteristicInternal(F, type, perms, unit),
        _value(0)
    {
    }

    template<>
    CharacteristicAsInternal<kFormat_string>::CharacteristicAsInternal(
        CharacteristicType type,
        const std::vector<CharacteristicPermission>& perms,
        CharacteristicUnit unit)
        : Characteristic(kFormat_string, type, perms, unit),
        CharacteristicAs<kFormat_string>(type, perms, unit), 
        CharacteristicInternal(kFormat_string, type, perms, unit),
        _value("")
    {
    }

    template<>
    CharacteristicAsInternal<kFormat_tlv8>::CharacteristicAsInternal(
        CharacteristicType type,
        const std::vector<CharacteristicPermission>& perms,
        CharacteristicUnit unit)
        : Characteristic(kFormat_tlv8, type, perms, unit),
        CharacteristicAs<kFormat_tlv8>(type, perms, unit), 
        CharacteristicInternal(kFormat_tlv8, type, perms, unit),
        _value()
    {
    }

    template<>
    CharacteristicAsInternal<kFormat_data>::CharacteristicAsInternal(
        CharacteristicType type,
        const std::vector<CharacteristicPermission>& perms,
        CharacteristicUnit unit)
        : Characteristic(kFormat_data, type, perms, unit),
        CharacteristicAs<kFormat_data>(type, perms, unit), 
        CharacteristicInternal(kFormat_data, type, perms, unit),
        _value()
    {
    }

    template<CharacteristicFormat F>
    CharacteristicAsInternal<F>::~CharacteristicAsInternal()
    {
    }

    template<CharacteristicFormat F>
    uint64_t CharacteristicAsInternal<F>::getID() const
    {
        return CharacteristicInternal::getID();
    }

    template<CharacteristicFormat F>
    typename CharacteristicAs<F>::FormatType CharacteristicAsInternal<F>::getValue() const
    {
        std::lock_guard lock(_mValue);

        return _value;
    }

    template<CharacteristicFormat F>
    std::string CharacteristicAsInternal<F>::getStringValue() const
    {
        if(!hasPermission(kPermission_PairedRead))
        {
            return "";
        }

        return std::to_string(getValue());
    }

    template<>
    std::string CharacteristicAsInternal<kFormat_string>::getStringValue() const
    {
        if(!hasPermission(kPermission_PairedRead))
        {
            return "";
        }

        return getValue();
    }

    template<>
    std::string CharacteristicAsInternal<kFormat_tlv8>::getStringValue() const
    {
        if(!hasPermission(kPermission_PairedRead))
        {
            return "";
        }

        std::vector<uint8_t> tlv8 = getValue();

        return std::string((char*)tlv8.data(), tlv8.size());
    }

    template<>
    std::string CharacteristicAsInternal<kFormat_data>::getStringValue() const
    {
        if(!hasPermission(kPermission_PairedRead))
        {
            return "";
        }

        std::vector<uint8_t> data = getValue();

        return std::string((char*)data.data(), data.size());
    }
    
    template<CharacteristicFormat F>
    int CharacteristicAsInternal<F>::setValue(typename CharacteristicAs<F>::FormatType value)
    {
        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged(rapidjson::Value(value));

        return server::HAPStatus::SUCCESS;
    }

    template<>
    int CharacteristicAsInternal<kFormat_uint8>::setValue(typename CharacteristicAs<kFormat_uint8>::FormatType value)
    {
        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged(rapidjson::Value((uint16_t)value));

        return server::HAPStatus::SUCCESS;
    }

    template<>
    int CharacteristicAsInternal<kFormat_int>::setValue(typename CharacteristicAs<kFormat_int>::FormatType value)
    {
        if(value < getMinValue() || value > getMaxValue() || (value % getMinStep()) != 0)
        {
            return server::HAPStatus::INVALID_VALUE;
        }

        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged(rapidjson::Value(value));

        return server::HAPStatus::SUCCESS;
    }

    template<>
    int CharacteristicAsInternal<kFormat_float>::setValue(typename CharacteristicAs<kFormat_float>::FormatType value)
    {
        if(value < getMinValue() || value > getMaxValue() || modf(value / getMinStep(), nullptr) != 0)
        {
            return server::HAPStatus::INVALID_VALUE;
        }

        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged(rapidjson::Value(value));

        return server::HAPStatus::SUCCESS;
    }

    template<>
    int CharacteristicAsInternal<kFormat_string>::setValue(typename CharacteristicAs<kFormat_string>::FormatType value)
    {
        if(value.size() > getMaxLen())
        {
            return server::HAPStatus::INVALID_VALUE;
        }

        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged(rapidjson::Value(value.c_str(), value.size()));

        return server::HAPStatus::SUCCESS;
    }

    template<>
    int CharacteristicAsInternal<kFormat_tlv8>::setValue(typename CharacteristicAs<kFormat_tlv8>::FormatType value)
    {
        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged(rapidjson::Value((char*)value.data(), value.size()));

        return server::HAPStatus::SUCCESS;
    }

    template<>
    int CharacteristicAsInternal<kFormat_data>::setValue(typename CharacteristicAs<kFormat_data>::FormatType value)
    {
        if(value.size() > getMaxDataLen())
        {
            return server::HAPStatus::INVALID_VALUE;
        }

        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged(rapidjson::Value((char*)value.data(), value.size()));

        return server::HAPStatus::SUCCESS;
    }

    template<CharacteristicFormat F>
    server::HAPStatus CharacteristicAsInternal<F>::setStringValue(const std::string& value)
    {
        if(!hasPermission(kPermission_PairedWrite))
        {
            return server::HAPStatus::READ_ONLY_CHARACTERISTIC;
        }

        std::istringstream iss(value);
        typename CharacteristicAs<F>::FormatType v;
        iss >> v;
        if(iss.fail())
        {
            return server::HAPStatus::INVALID_VALUE;
        }

        return (server::HAPStatus)setValue(v);
    }

    template<>
    server::HAPStatus CharacteristicAsInternal<kFormat_bool>::setStringValue(const std::string& value)
    {
        if(!hasPermission(kPermission_PairedWrite))
        {
            return server::HAPStatus::READ_ONLY_CHARACTERISTIC;
        }
        
        if(!strcasecmp(value.data(), "false") || !strcasecmp(value.data(), "0"))
        {
            return (server::HAPStatus)setValue(false);
        }
        else if(!strcasecmp(value.data(), "true") || !strcasecmp(value.data(), "1"))
        {
            return (server::HAPStatus)setValue(true);
        }
        else
        {
            return server::HAPStatus::INVALID_VALUE;
        }
    }

    template<>
    server::HAPStatus CharacteristicAsInternal<kFormat_uint8>::setStringValue(const std::string& value)
    {
        if(!hasPermission(kPermission_PairedWrite))
        {
            return server::HAPStatus::READ_ONLY_CHARACTERISTIC;
        }

        std::istringstream iss(value);
        uint16_t v;
        iss >> v;
        if(iss.fail() || v > std::numeric_limits<uint8_t>::max())
        {
            return server::HAPStatus::INVALID_VALUE;
        }

        return (server::HAPStatus)setValue((uint8_t)v);
    }

    template<>
    server::HAPStatus CharacteristicAsInternal<kFormat_string>::setStringValue(const std::string& value)
    {
        if(!hasPermission(kPermission_PairedWrite))
        {
            return server::HAPStatus::READ_ONLY_CHARACTERISTIC;
        }

        return (server::HAPStatus)setValue(value);
    }

    template<>
    server::HAPStatus CharacteristicAsInternal<kFormat_tlv8>::setStringValue(const std::string& value)
    {
        if(!hasPermission(kPermission_PairedWrite))
        {
            return server::HAPStatus::READ_ONLY_CHARACTERISTIC;
        }

        std::vector<uint8_t> vvalue(value.begin(), value.end());

        return (server::HAPStatus)setValue(vvalue);
    }

    template<>
    server::HAPStatus CharacteristicAsInternal<kFormat_data>::setStringValue(const std::string& value)
    {
        if(!hasPermission(kPermission_PairedWrite))
        {
            return server::HAPStatus::READ_ONLY_CHARACTERISTIC;
        }

        std::vector<uint8_t> vvalue(value.begin(), value.end());

        return (server::HAPStatus)setValue(vvalue);
    }

    template<CharacteristicFormat F>
    rapidjson::Document CharacteristicAsInternal<F>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

        if(hasPermission(kPermission_PairedRead))
        {
            json.AddMember("value", getValue(), json.GetAllocator());
        }

        return json;
    }

    template<>
    rapidjson::Document CharacteristicAsInternal<kFormat_int>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

        if(hasPermission(kPermission_PairedRead))
        {
            json.AddMember("value", getValue(), json.GetAllocator());
        }

        json.AddMember("minValue", getMinValue(), json.GetAllocator());

        json.AddMember("maxValue", getMaxValue(), json.GetAllocator());

        json.AddMember("minStep", getMinStep(), json.GetAllocator());

        return json;
    }

    template<>
    rapidjson::Document CharacteristicAsInternal<kFormat_float>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

        if(hasPermission(kPermission_PairedRead))
        {
            json.AddMember("value", getValue(), json.GetAllocator());
        }

        json.AddMember("minValue", getMinValue(), json.GetAllocator());

        json.AddMember("maxValue", getMaxValue(), json.GetAllocator());

        json.AddMember("minStep", getMinStep(), json.GetAllocator());

        return json;
    }

    template<>
    rapidjson::Document CharacteristicAsInternal<kFormat_string>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

        if(hasPermission(kPermission_PairedRead))
        {
            std::string value = getValue();

            json.AddMember(
                "value", 
                rapidjson::Value(value.c_str(), value.size(), json.GetAllocator()), 
                json.GetAllocator());
        }

        json.AddMember("maxLen", getMaxLen(), json.GetAllocator());

        return json;
    }

    template<>
    rapidjson::Document CharacteristicAsInternal<kFormat_tlv8>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

        if(hasPermission(kPermission_PairedRead))
        {
            std::vector<uint8_t> value = getValue();

            json.AddMember(
                "value", 
                rapidjson::Value((char*)value.data(), value.size(), json.GetAllocator()), 
                json.GetAllocator());
        }

        return json;
    }

    template<>
    rapidjson::Document CharacteristicAsInternal<kFormat_data>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

        if(hasPermission(kPermission_PairedRead))
        {
            std::vector<uint8_t> value = getValue();

            json.AddMember(
                "value", 
                rapidjson::Value((char*)value.data(), value.size(), json.GetAllocator()), 
                json.GetAllocator());
        }

        json.AddMember("maxDataLen", getMaxDataLen(), json.GetAllocator());

        return json;
    }

}

#endif