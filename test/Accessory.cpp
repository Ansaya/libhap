#include <catch2/catch.hpp>

#include <Accessory.h>

using namespace hap;

TEST_CASE("Accessory constructor", "[Accessory]")
{
    std::shared_ptr<Accessory> aptr = Accessory::make_shared();

    REQUIRE(aptr->getID() == 1);
}

TEST_CASE("Accessory service getter/setter", "[Accessory]")
{
    std::shared_ptr<Accessory> aptr = Accessory::make_shared();
    
    std::shared_ptr<Service> sptr = Service::make_shared(kServiceType_LightBulb);

    std::shared_ptr<Characteristic> cptr = 
        Characteristic::make_shared(kFormat_bool, kCharacteristic_On, {kPermission_PairedWrite, kPermission_PairedRead});

    sptr->addCharacteristic(cptr);

    uint64_t s_iid = sptr->getID();
    uint64_t c_iid = cptr->getID();

    aptr->addService(sptr);

    REQUIRE(sptr->getID() != s_iid);
    REQUIRE(cptr->getID() != c_iid);

    s_iid = sptr->getID();
    c_iid = cptr->getID();

    REQUIRE(aptr->getService(s_iid) == sptr);
    REQUIRE(aptr->getCharacteristic(c_iid) == cptr);

    aptr->removeService(s_iid);

    REQUIRE(aptr->getService(s_iid) == nullptr);
    REQUIRE(aptr->getCharacteristic(c_iid) == nullptr);
}