#ifndef HAP_SERVER_CONTROLLERDEVICE
#define HAP_SERVER_CONTROLLERDEVICE

namespace hap {
namespace server {

    class ControllerDevice
    {
    public:
        ControllerDevice();
        
        ControllerDevice(const ControllerDevice&) = delete;

        ControllerDevice& operator=(const ControllerDevice&) = delete;

        virtual ~ControllerDevice();

    private:
        
    };
    

}
}

#endif