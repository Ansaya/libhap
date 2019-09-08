#include <PrimaryAccessoryInternal.h>

using namespace hap;

PrimaryAccessoryInternal::PrimaryAccessoryInternal(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number,
    AccessoryCategory category,
    const std::string& setup_code,
    const std::string& device_mac)
    : server::HAPServer(accessory_name, model_name, config_number, 
        category, setup_code, device_mac)
{
}

PrimaryAccessoryInternal::PrimaryAccessoryInternal(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number,
    AccessoryCategory category,
    std::function<bool(std::string)> display_setup_code,
    const std::string& device_mac)
    : server::HAPServer(accessory_name, model_name, config_number, 
        category, display_setup_code, device_mac)
{
}

PrimaryAccessoryInternal::~PrimaryAccessoryInternal()
{
}

void PrimaryAccessoryInternal::networkStart()
{
    return server::HAPServer::networkStart();
}

void PrimaryAccessoryInternal::networkStop()
{
    return server::HAPServer::networkStop();
}

std::vector<std::exception> PrimaryAccessoryInternal::networkCheck()
{
    return server::HAPServer::networkCheck();
}

std::shared_ptr<Accessory> PrimaryAccessoryInternal::getAccessory(uint64_t aid) const
{
    return server::HAPServer::getAccessory(aid);
}
        
void PrimaryAccessoryInternal::addAccessory(const std::shared_ptr<Accessory>& accessory)
{
    return server::HAPServer::addAccessory(std::dynamic_pointer_cast<AccessoryInternal>(accessory));
}

void PrimaryAccessoryInternal::removeAccessory(uint64_t aid)
{
    return server::HAPServer::removeAccessory(aid);
}