#include <catch2/catch.hpp>

#include <CharacteristicInternal.h>

#include <CharacteristicAsInternal.h>
#include <iostream>

using namespace hap;

TEST_CASE("Characteristic internal", "[Characteristic]")
{
    CharacteristicAsInternal<kFormat_string> cint(kCharacteristic_Name, {kPermission_PairedRead});

    REQUIRE(cint.getValue() == "");
    REQUIRE(cint.getMaxLen() == 64);

    std::string newVal("hello");
    cint.setValue(newVal);

    REQUIRE(cint.getValue() == newVal);

    rapidjson::Document cint_json = cint.to_json();

    REQUIRE(cint_json.HasMember("type"));
    REQUIRE(cint_json.HasMember("iid"));
    REQUIRE(cint_json.HasMember("value"));
    REQUIRE(cint_json.HasMember("perms"));
    REQUIRE(cint_json.HasMember("format"));
    REQUIRE(cint_json.HasMember("maxLen"));

    REQUIRE(cint_json["format"].GetString() == to_format_string(kFormat_string));
    REQUIRE(cint_json["value"].GetString() == newVal);
    REQUIRE(cint_json["perms"].GetArray()[0].GetString() == to_permission_string(kPermission_PairedRead));
    REQUIRE(cint_json["maxLen"].GetUint() == 64);
}