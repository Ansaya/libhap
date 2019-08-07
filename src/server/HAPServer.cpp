#include <server/HAPServer.h>


#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>

#define HAP_SERVER_HAP_SERVER_MAX_CONNECTIONS   8
#define HAP_SERVER_HAP_SERVER_POLL_TIMEOUT      30000

using namespace hap::server;

HAPServer::HAPServer()
{
    // TCP socket setup
    _tcpSocket = socket(PF_INET, SOCK_STREAM, 0);
    if(_tcpSocket < 0)
    {
        // Check errno

        throw std::runtime_error("Could not allocate socket");
    }

    struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_family = PF_INET;
	addr.sin_port = htons(0);

	int optval = 1;
	socklen_t optlen = sizeof(optval);
	int retval = setsockopt(_tcpSocket, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
	retval |= bind(_tcpSocket, (const struct sockaddr *)&addr, sizeof(addr));
	retval |= listen(_tcpSocket, HAP_SERVER_HAP_SERVER_MAX_CONNECTIONS);
	if (retval < 0) {
        // Check errno

		throw std::runtime_error("Could not initialize socket");
	}

    // Allocate shutdown pipe for tcp listener thread
    int shutdown_pipe[2];
    retval = pipe(shutdown_pipe);
    if(retval < 0)
    {
        // Check errno
        throw std::runtime_error("Could not allocate pipe");
    }
    _tcpShutdownPipe = shutdown_pipe[1];
    
    // Start tcp listener thread
    _tcpListener = new std::thread(&HAPServer::_tcpListenerLoop, this, shutdown_pipe[0]);
}

HAPServer::~HAPServer()
{
    // Join TCP listener thread and dispose TCP socket
    write(_tcpShutdownPipe, (const char*)'a', 0);
    _tcpListener->join();
    delete _tcpListener;
    close(_tcpShutdownPipe);
    close(_tcpSocket);
}

void HAPServer::_tcpListenerLoop(int shutdown_pipe)
{
    // File descriptors setup
    struct pollfd fds[2];
    fds[0] = { fd: _tcpSocket, events: POLLIN };
    fds[1] = { fd: shutdown_pipe, events: POLLIN };

    int poll_retval = 0;
    char c_name_buffer[128];
    while (true)
    {
        poll_retval = poll(fds, 2, HAP_SERVER_HAP_SERVER_POLL_TIMEOUT);

        if(poll_retval < 0)             // poll notified an error
        {
            // Check errno for poll error
            break;
        }
        else if(poll_retval == 0)       // poll timed out
        {
            continue;
        }

        // poll returned on a file descriptor event

        // When shutdown file descriptor notifies an event its time to go
        if(fds[1].revents) { break; }

        // If an error on tcp socket is detected dispose all
        if(fds[0].revents & (POLLHUP | POLLERR))
        {
            // Check errno for _tcpSocket error
            break;
        }

        // Accept new connection socket
        struct sockaddr_in client_addr;
        socklen_t clen;
        int controller_socket = 
            accept(_tcpSocket, (struct sockaddr*)&client_addr, &clen);

        // Get controller hostname from connection socket
        std::string controller_name("no_name");
        if(clen == sizeof(struct sockaddr_in))
        {
            // Retrieve client hostname or its numeric form
            int retval = getnameinfo((struct sockaddr*)&client_addr, clen, 
                c_name_buffer, sizeof(c_name_buffer), NULL, 0, NI_NOFQDN);

            // If buffer size was too small for hostname require numeric form
            if(retval == EAI_OVERFLOW)
            {
                retval = getnameinfo((struct sockaddr*)&client_addr, clen, 
                    c_name_buffer, sizeof(c_name_buffer), NULL, 0, NI_NUMERICHOST);
            }

            if(retval)
            {
                if(retval == EAI_SYSTEM)
                {
                    // Check errno, use gai_strerror to get error string
                }
            }
            else
            {
                controller_name.assign(c_name_buffer);
            }
        }

        // Initialize new controller device
        ControllerDevice* new_controller = new ControllerDevice();   // TODO: properly initialize ControllerDevice object

        // Add new controller device to local pool
        _connectedControllers.push_back(new_controller);
    }
    
    // Close shutdown_pipe fd when finished
    close(shutdown_pipe);
}