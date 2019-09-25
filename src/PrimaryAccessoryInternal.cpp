#include <PrimaryAccessoryInternal.h>

#include <CharacteristicAs.h>

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
    _init();
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
    _init();
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

static void _fake_destructor(PrimaryAccessoryInternal* pai)
{
}

void PrimaryAccessoryInternal::_init()
{
    // Add HAP protocol information service to primary accessory
    std::shared_ptr<Service> hap_information = 
        Service::make_shared(kServiceType_ProtocolInformation);

    std::shared_ptr<CharacteristicAs<kFormat_string>> version = 
        Characteristic::make_shared<kFormat_string>(kCharacteristic_Version, {kPermission_PairedRead});

    version->setValue("1.1.0");

    hap_information->addCharacteristic(version);
    addService(hap_information);

    // Add self-reference for HAPServer service to work correctly
    // NOTE: because it is a self-reference, a null deleter function
    //       is set to avoid double delete when destructors are called.
    //       This "undeletable" reference won't be shared because HAPServer
    //       interface isn't visible from PrimaryAccessory
    addAccessory(std::shared_ptr<PrimaryAccessoryInternal>(this, _fake_destructor));
}