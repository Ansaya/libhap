#include <catch2/catch.hpp>

#include <Characteristic.h>

#include <CharacteristicAs.h>

using namespace hap;

TEST_CASE("Characteristic factory", "[Characteristic]")
{
    std::shared_ptr<Characteristic> cptr = Characteristic::make_shared(
        kFormat_bool, kCharacteristic_On, {kPermission_PairedRead, kPermission_Events});

    REQUIRE(cptr->getFormat() == kFormat_bool);
    REQUIRE(cptr->getID() == 0);
    REQUIRE(cptr->getType() == kCharacteristic_On);
    REQUIRE(cptr->getPermissions()[0] == kPermission_PairedRead);
    REQUIRE(cptr->getPermissions()[1] == kPermission_Events);
    REQUIRE(cptr->getUnit() == kUnit_no_unit);
    REQUIRE(cptr->hasPermission(kPermission_PairedRead));
    REQUIRE_FALSE(cptr->hasPermission(kPermission_PairedWrite));

    cptr = Characteristic::make_shared(
        kFormat_uint8, 
        kCharacteristic_Brightness, 
        {kPermission_PairedRead, kPermission_PairedWrite}, 
        kUnit_percentage);

    REQUIRE(cptr->getFormat() == kFormat_uint8);
    REQUIRE(cptr->getID() == 0);
    REQUIRE(cptr->getType() == kCharacteristic_Brightness);
    REQUIRE(cptr->getPermissions()[0] == kPermission_PairedRead);
    REQUIRE(cptr->getPermissions()[1] == kPermission_PairedWrite);
    REQUIRE(cptr->getUnit() == kUnit_percentage);
    REQUIRE(cptr->hasPermission(kPermission_PairedRead));
    REQUIRE(cptr->hasPermission(kPermission_PairedWrite));
    REQUIRE_FALSE(cptr->hasPermission(kPermission_Events));

    cptr = Characteristic::make_shared(kFormat_string, kCharacteristic_Name, {kPermission_PairedRead});

    REQUIRE(cptr->getFormat() == kFormat_string);
    REQUIRE(cptr->getID() == 0);
    REQUIRE(cptr->getType() == kCharacteristic_Name);
    REQUIRE(cptr->getPermissions()[0] == kPermission_PairedRead);
    REQUIRE(cptr->getUnit() == kUnit_no_unit);
    REQUIRE(cptr->hasPermission(kPermission_PairedRead));
    REQUIRE_FALSE(cptr->hasPermission(kPermission_Events));
}