#include <server/ControllerDevice.h>

using namespace hap::server;

ControllerDevice::ControllerDevice(
    int socket, 
    const std::string& device_name,
    std::shared_ptr<crypto::EncryptionKeyStore> e_key_store,
    std::function<http::Response(ControllerDevice*,const http::Request&)> accessory_http)
    : EncryptedHTTPSocket(socket, e_key_store, std::bind(accessory_http, this, std::placeholders::_1)), 
    _deviceName(device_name)
{
}
    
ControllerDevice::~ControllerDevice()
{
}

const std::string& ControllerDevice::getName() const
{
    return _deviceName;
}