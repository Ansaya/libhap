#include <AccessoryBridge.h>

#include <PrimaryAccessoryInternal.h>

using namespace hap;

std::shared_ptr<AccessoryBridge> AccessoryBridge::make_shared(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number,
    const std::string& setup_code,
    const std::string& device_mac)
{
    return std::make_shared<PrimaryAccessoryInternal>(accessory_name, model_name, 
        config_number, kAccessory_Bridges, setup_code, device_mac);
}

std::shared_ptr<AccessoryBridge> AccessoryBridge::make_shared(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number,
    std::function<bool(std::string)> display_setup_code,
    const std::string& device_mac)
{
    return std::make_shared<PrimaryAccessoryInternal>(accessory_name, model_name, 
        config_number, kAccessory_Bridges, display_setup_code, device_mac);
}

AccessoryBridge::AccessoryBridge()
{
}

AccessoryBridge::~AccessoryBridge()
{
}