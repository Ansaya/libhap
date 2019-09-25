#include <catch2/catch.hpp>

#include <Service.h>

using namespace hap;

TEST_CASE("Service constructor", "[Service]")
{
    std::shared_ptr<Service> sptr = Service::make_shared(kServiceType_LightBulb);

    REQUIRE(sptr->getID() == 0);
    REQUIRE(sptr->getType() == kServiceType_LightBulb);
}

TEST_CASE("Service characteristics getter/setter", "[Service]")
{
    std::shared_ptr<Service> sptr = Service::make_shared(kServiceType_LightBulb);

    std::shared_ptr<Characteristic> cptr = 
        Characteristic::make_shared(kFormat_bool, kCharacteristic_On, {kPermission_PairedWrite, kPermission_PairedRead});

    uint64_t c_iid = cptr->getID();

    REQUIRE(sptr->getCharacteristic(c_iid) == nullptr);

    sptr->addCharacteristic(cptr);

    c_iid = cptr->getID();

    REQUIRE(sptr->getCharacteristic(c_iid) == cptr);
    REQUIRE(sptr->getCharacteristic(132454765) == nullptr);

    sptr->removeCharacteristic(c_iid);

    REQUIRE(sptr->getCharacteristic(c_iid) == nullptr);
}