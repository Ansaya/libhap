#include <server/EncryptedHTTPSocket.h>

#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define HAP_SERVER_EHTTPSOCKET_BUFFER_SIZE  4096
#define HAP_SERVER_EHTTPSOCKET_TIMEOUT      30000

using namespace hap::server;

EncryptedHTTPSocket::EncryptedHTTPSocket(
    int socket, 
    std::shared_ptr<EncryptionKeyStore> e_key_store,
    std::function<http::Response(const http::Request&)> cb)
    : _socket(socket), _socketSecured(false), _eKeyStore(e_key_store), _cb(cb)
{
    if(!socket)
    {
        throw std::invalid_argument("Given socket should be initialized to a valid file descriptor");
    }

    if(e_key_store == nullptr)
    {
        throw std::invalid_argument("Given key store should be a valid pointer");
    }

    int shutdown_pipe[2];
    int retval = pipe(shutdown_pipe);
    if(retval)
    {
        // Check errno

        throw std::runtime_error("Could not allocate pipe");
    }
    _shutdownPipe = shutdown_pipe[1];

    _httpListener = new std::thread(&EncryptedHTTPSocket::_httpListenerLoop, this, shutdown_pipe[0]);
}

EncryptedHTTPSocket::~EncryptedHTTPSocket()
{
    write(_shutdownPipe, (const char*)'a', 1);
    _httpListener->join();
    delete _httpListener;
    close(_shutdownPipe);
    close(_socket);
}

void EncryptedHTTPSocket::_httpListenerLoop(int shutdown_pipe)
{
    struct pollfd fds[2];
    memset(&fds, 0, sizeof(fds));
    fds[0].fd = _socket;
    fds[0].events = POLLIN;
    fds[1].fd = shutdown_pipe;
    fds[1].events = POLLIN;

    char read_buffer[HAP_SERVER_EHTTPSOCKET_BUFFER_SIZE];
    int retval = 0;
    while (true)
    {
        retval = poll(fds, 2, HAP_SERVER_EHTTPSOCKET_TIMEOUT);
        if(retval < 0)
        {
            // Check errno

            break;
        }

        // If two descritors have events, then shutdown_pipe has an event,
        // so it is time to join
        if(retval > 1 || fds[1].revents) { break; }

        // Check for socket exceptions
        if(fds[0].revents & POLLHUP)
        {
            // Client closed connection
            break;
        }
        else if(fds[0].revents & POLLERR)
        {
            // Connection error
            break;
        }

        // Receive available data from socket
        ssize_t length = recv(_socket, read_buffer, sizeof(read_buffer),0);
        if(length < 0)
        {
            // Check errno
            break;
        }
        else if(length == 0)
        {
            // Client closed connection
            break;
        }

        if(_socketSecured.load())
        {
            // Decrypt request from buffer
            decrypt(read_buffer, length);
        }

        http::Request request(read_buffer, length);

        http::Response response;

        // Handle request

        std::string response_buffer = response.getText();

        if(_socketSecured.load())
        {
            encrypt(response_buffer.data(), response_buffer.size());
        }
            
        length = ::send(_socket, response_buffer.data(), response_buffer.size(), 0);
        if(length < 0)
        {
            // Check errno
            break;
        }
        else if((size_t)length < response_buffer.size())
        {
            // Maybe while loop or something
        }
    }
    
    close(shutdown_pipe);
}

http::Response EncryptedHTTPSocket::_secureSetup(const http::Request& controller_request)
{

}

void EncryptedHTTPSocket::encrypt(char* buffer, size_t buffer_length)
{

}

void EncryptedHTTPSocket::decrypt(char* buffer, size_t buffer_length)
{

}