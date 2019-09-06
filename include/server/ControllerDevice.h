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
            std::function<http::Response(ControllerDevice*,const http::Request&)> accessory_http);
        
        ControllerDevice(const ControllerDevice&) = delete;

        ControllerDevice& operator=(const ControllerDevice&) = delete;

        virtual ~ControllerDevice();

        const std::string& getName() const;

    private:
        const std::string _deviceName;
        std::map<uint64_t, uint64_t> _characteristicsNotification;
    };
    

}
}

#endif