#include <PrimaryAccessory.h>

#include <PrimaryAccessoryInternal.h>

using namespace hap;

std::shared_ptr<PrimaryAccessory> PrimaryAccessory::make_shared(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number,
    AccessoryCategory category,
    const std::string& setup_code,
    const std::string& device_mac)
{
    return std::make_shared<PrimaryAccessoryInternal>(accessory_name, model_name, 
        config_number, category, setup_code, device_mac);
}

std::shared_ptr<PrimaryAccessory> PrimaryAccessory::make_shared(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number,
    AccessoryCategory category,
    std::function<bool(std::string)> display_setup_code,
    const std::string& device_mac)
{
    return std::make_shared<PrimaryAccessoryInternal>(accessory_name, model_name, 
        config_number, category, display_setup_code, device_mac);
}

PrimaryAccessory::PrimaryAccessory()
{
}

PrimaryAccessory::~PrimaryAccessory()
{
}