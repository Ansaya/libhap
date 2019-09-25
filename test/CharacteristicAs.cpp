#include <catch2/catch.hpp>

#include <CharacteristicAs.h>

using namespace hap;

TEST_CASE("Characteristic value getter/setter", "[Characteristic]")
{
    std::shared_ptr<CharacteristicAs<kFormat_string>> cint = 
        Characteristic::make_shared<kFormat_string>(kCharacteristic_Name, {kPermission_PairedRead, kPermission_PairedWrite});

    std::string newVal("hello");
    int status = cint->setValue(newVal);

    REQUIRE(status == 0);
    REQUIRE(cint->getValue() == newVal);

    std::string long_val("Hello, I'm a very very very very very long string that will exceed max length");

    status = cint->setValue(long_val);

    REQUIRE(status == -70410);
    REQUIRE(cint->getValue() == newVal);

    std::shared_ptr<CharacteristicAs<kFormat_int>> cint_b = 
        Characteristic::make_shared<kFormat_int>(kCharacteristic_Volume, {kPermission_PairedRead, kPermission_PairedWrite});

    cint_b->setMinStep(2);

    status = cint_b->setValue(2);
    REQUIRE(status == 0);
    REQUIRE(cint_b->getValue() == 2);

    status = cint_b->setValue(3);
    REQUIRE(status == -70410);
    REQUIRE(cint_b->getValue() == 2);

    status = cint_b->setValue(-2);
    REQUIRE(status == -70410);
    REQUIRE(cint_b->getValue() == 2);

    std::shared_ptr<CharacteristicAs<kFormat_data>> cint_c = 
        Characteristic::make_shared<kFormat_data>(kCharacteristic_Version, {kPermission_PairedRead, kPermission_PairedWrite});

    cint_c->setMaxDataLen(10);

    status = cint_c->setValue({'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'});
    REQUIRE(status == 0);
    REQUIRE(cint_c->getValue().size() == 10);

    status = cint_c->setValue({'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k'});
    REQUIRE(status == -70410);
    REQUIRE(cint_c->getValue().size() == 10);
}