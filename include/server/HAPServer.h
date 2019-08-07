#ifndef HAP_SERVER_HAPSERVER
#define HAP_SERVER_HAPSERVER

#include "ControllerDevice.h"

#include <list>
#include <thread>

namespace hap {
namespace server {

    class HAPServer
    {
    public:
        HAPServer(const HAPServer&) = delete;

        HAPServer& operator=(const HAPServer&) = delete;

        virtual ~HAPServer();

    protected:
        HAPServer();

    private:
        int _tcpSocket;
        int _tcpShutdownPipe;
        std::thread* _tcpListener;
        std::list<ControllerDevice*> _connectedControllers;

        void _tcpListenerLoop(int shutdown_pipe);

    };

}
}

#endif