#ifndef HAP_CHARACTERISTICASINTERNAL
#define HAP_CHARACTERISTICASINTERNAL

#include <CharacteristicInternal.h>
#include <CharacteristicAs.h>

#include <mutex>

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
        
        void setValue(typename CharacteristicAs<F>::FormatType value) override;

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
    std::string CharacteristicAsInternal<F>::getStringValue() const
    {
        return CharacteristicAs<F>::getStringValue();
    }

    template<CharacteristicFormat F>
    typename CharacteristicAs<F>::FormatType CharacteristicAsInternal<F>::getValue() const
    {
        std::lock_guard lock(_mValue);

        return _value;
    }
    
    template<CharacteristicFormat F>
    void CharacteristicAsInternal<F>::setValue(typename CharacteristicAs<F>::FormatType value)
    {
        std::lock_guard lock(_mValue);

        _value = value;

        valueChanged();
    }

    template<CharacteristicFormat F>
    rapidjson::Document CharacteristicAsInternal<F>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        return CharacteristicInternal::to_json(allocator);
    }

    template<>
    rapidjson::Document CharacteristicAsInternal<kFormat_int>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

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

        json.AddMember("maxLen", getMaxLen(), json.GetAllocator());

        return json;
    }

    template<>
    rapidjson::Document CharacteristicAsInternal<kFormat_data>::to_json(
        rapidjson::Document::AllocatorType* allocator) const
    {
        rapidjson::Document json = CharacteristicInternal::to_json(allocator);

        json.AddMember("maxDataLen", getMaxDataLen(), json.GetAllocator());

        return json;
    }

}

#endif