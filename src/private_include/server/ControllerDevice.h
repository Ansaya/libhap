#ifndef HAP_SERVER_CONTROLLERDEVICE
#define HAP_SERVER_CONTROLLERDEVICE

#include "EncryptedHTTPSocket.h"
#include "http/EventResponse.h"

#include <functional>
#include <memory>

namespace hap {
namespace server {

    class ControllerDevice : public EncryptedHTTPSocket
    {
    public:
        ControllerDevice(
            int socket, 
            const std::string& device_name,
            std::shared_ptr<crypto::EncryptionKeyStore> e_key_store,
            std::function<http::Response(ControllerDevice*,const http::Request&)> accessory_http,
            std::function<void(const ControllerDevice*)> connection_lost = nullptr);
        
        ControllerDevice(const ControllerDevice&) = delete;

        ControllerDevice& operator=(const ControllerDevice&) = delete;

        virtual ~ControllerDevice();

        const std::string& getName() const;

    private:
        const std::string _deviceName;
        const std::function<void(const ControllerDevice*)> _connectionLost;

        void connectionLost() const noexcept override;
    };
    

}
}

#endif