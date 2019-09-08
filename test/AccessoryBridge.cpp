#include <catch2/catch.hpp>

#include <AccessoryBridge.h>

#include <thread>

using namespace hap;

TEST_CASE("Accessory bridge constructor", "[AccessoryBridge]")
{
    std::shared_ptr<AccessoryBridge> abptr = 
        AccessoryBridge::make_shared("Test Bridge", "Software bridge", 1, "123-45-678");

    REQUIRE_NOTHROW(abptr->networkStart());

    std::this_thread::sleep_for(std::chrono::seconds(5));
    
    REQUIRE_NOTHROW(abptr->networkStop());
}