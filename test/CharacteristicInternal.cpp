#include <catch2/catch.hpp>

#include <CharacteristicInternal.h>

#include <CharacteristicAsInternal.h>
#include <iostream>

using namespace hap;

TEST_CASE("Characteristic internal constructor", "[Characteristic]")
{
    CharacteristicAsInternal<kFormat_string> cint(kCharacteristic_Name, {kPermission_PairedRead});

    REQUIRE(cint.getValue() == "");
    REQUIRE(cint.getMaxLen() == 64);
}

TEST_CASE("Characteristic internal value getter/setter", "[Characteristic]")
{
    CharacteristicAsInternal<kFormat_string> cint(kCharacteristic_Name, {kPermission_PairedRead, kPermission_PairedWrite});

    std::string newVal("hello");
    server::HAPStatus status = (server::HAPStatus)cint.setValue(newVal);

    REQUIRE(status == server::HAPStatus::SUCCESS);
    REQUIRE(cint.getValue() == newVal);
    REQUIRE(cint.getStringValue() == newVal);

    CharacteristicAsInternal<kFormat_bool> cint_b(kCharacteristic_On, {kPermission_PairedRead});

    status = (server::HAPStatus)cint_b.setStringValue("true");
    REQUIRE(status == server::HAPStatus::READ_ONLY_CHARACTERISTIC);
    
    REQUIRE(cint_b.getStringValue().size());

    CharacteristicAsInternal<kFormat_bool> cint_c(kCharacteristic_On, {kPermission_PairedWrite});

    status = (server::HAPStatus)cint_c.setStringValue("true");
    REQUIRE(status == server::HAPStatus::SUCCESS);
    
    REQUIRE(cint_c.getStringValue().empty());
}

TEST_CASE("Characteristic internal json serialization", "[Characteristic]")
{
    CharacteristicAsInternal<kFormat_float> cint(kCharacteristic_Name, {kPermission_PairedRead});
    cint.setMaxValue(12.5f);
    cint.setMinValue(0.0f);
    cint.setMinStep(0.5f);

    rapidjson::Document cint_json = cint.to_json();

    REQUIRE(cint_json.HasMember("type"));
    REQUIRE(cint_json.HasMember("iid"));
    REQUIRE(cint_json.HasMember("value"));
    REQUIRE(cint_json.HasMember("perms"));
    REQUIRE(cint_json.HasMember("format"));
    REQUIRE(cint_json.HasMember("maxValue"));
    REQUIRE(cint_json.HasMember("minValue"));
    REQUIRE(cint_json.HasMember("minStep"));

    REQUIRE(cint_json["format"].GetString() == to_format_string(kFormat_float));
    REQUIRE(cint_json["value"].GetFloat() == 0.0f);
    REQUIRE(cint_json["perms"].GetArray()[0].GetString() == to_permission_string(kPermission_PairedRead));
    REQUIRE(cint_json["maxValue"].GetFloat() == 12.5f);
    REQUIRE(cint_json["minValue"].GetFloat() == 0.0f);
    REQUIRE(cint_json["minStep"].GetFloat() == 0.5f);
}