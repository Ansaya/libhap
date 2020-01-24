#include <catch2/catch.hpp>

#include <AccessoryBridge.h>

#include <CharacteristicAs.h>

#include <thread>

using namespace hap;

TEST_CASE("Accessory bridge constructor", "[AccessoryBridge]")
{
    std::shared_ptr<AccessoryBridge> abptr = 
        AccessoryBridge::make_shared("Test Bridge", "software-bridge", 1, "123-45-678");

    auto c_on = Characteristic::make_shared<kFormat_bool>(kCharacteristic_On, {kPermission_PairedRead, kPermission_PairedWrite, kPermission_Events});

    auto s_lightBulb = Service::make_shared(kServiceType_LightBulb);

    auto a_lightBulb = Accessory::make_shared();
    
    s_lightBulb->addCharacteristic(std::static_pointer_cast<Characteristic>(c_on));
    a_lightBulb->addService(s_lightBulb);

    abptr->addAccessory(a_lightBulb);

    REQUIRE_NOTHROW(abptr->networkStart());

    std::this_thread::sleep_for(std::chrono::seconds(5));
    
    REQUIRE_NOTHROW(abptr->networkStop());
}