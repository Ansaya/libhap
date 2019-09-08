#include <server/ControllerDevice.h>

using namespace hap::server;

ControllerDevice::ControllerDevice(
    int socket, 
    const std::string& device_name,
    std::shared_ptr<crypto::EncryptionKeyStore> e_key_store,
    std::function<http::Response(ControllerDevice*,const http::Request&)> accessory_http,
    std::function<void(const ControllerDevice*)> connection_lost)
    : EncryptedHTTPSocket(socket, e_key_store, std::bind(accessory_http, this, std::placeholders::_1)), 
    _deviceName(device_name), _connectionLost(connection_lost)
{
}
    
ControllerDevice::~ControllerDevice()
{
}

const std::string& ControllerDevice::getName() const
{
    return _deviceName;
}

void ControllerDevice::connectionLost() const noexcept
{
    if(_connectionLost)
    {
        try {
            _connectionLost(this);
        }
        catch(std::exception& e)
        {
            // TODO: log exception
        }
    }
}