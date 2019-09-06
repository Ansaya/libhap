#include <Accessory.h>

#include <AccessoryInternal.h>

using namespace hap;

std::shared_ptr<Accessory> Accessory::make_shared()
{
    return std::make_shared<AccessoryInternal>();
}

Accessory::Accessory()
{
}

Accessory::~Accessory()
{
}