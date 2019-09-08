#include <server/EncryptedHTTPSocket.h>

#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

static constexpr uint16_t socket_buffer_size = 8192;

static constexpr int socket_read_timeout = 30000;

static constexpr const char* mime_tlv8 = "application/pairing+tlv8";

using namespace hap::server;

EncryptedHTTPSocket::EncryptedHTTPSocket(
    int socket, 
    std::shared_ptr<crypto::EncryptionKeyStore> e_key_store,
    std::function<http::Response(const http::Request&)> accessory_http)
    : _socket(socket), _pairingHandler(e_key_store), 
    _accessoryHTTPHandler(accessory_http)
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
    // Initialize pollfd array to contemporarly listen to socket and shutdown_pipe
    struct pollfd fds[2];
    memset(&fds, 0, sizeof(fds));
    fds[0].fd = _socket;
    fds[0].events = POLLIN;
    fds[1].fd = shutdown_pipe;
    fds[1].events = POLLIN;

    // Setup a read buffer for the data from the socket
    char read_buffer[socket_buffer_size];

    // Received messages counter
    uint64_t in_nonce = 0;

    int retval = 0;
    while (true)
    {
        // Wait for some data to come from the socket
        retval = poll(fds, 2, socket_read_timeout);
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

        std::vector<uint8_t> v_request, v_response;
        bool verified_transaction = _pairingHandler.clientVerified();

        // If client is successfully paired decrypt message and increment in_nonce
        if(verified_transaction)
        {
            v_request = _pairingHandler.decrypt((const uint8_t*)read_buffer, 
                length, (const uint8_t*)&in_nonce);

            in_nonce++;

            if(v_request.empty())
            {
                // TODO: log error
            }
        }

        // Parse HTTP request
        http::Request request(v_request.data(), v_request.size());

        // Call HTTP requests handler to get a response
        http::Response response = _requestHandler(request, verified_transaction);

        // Serialize response
        std::string s_response = response.getText();

        // Get lock on socket before writing
        std::unique_lock lock(_mSocket);

        // If client is successfully verified at the beginning of transaction,
        // encrypt response message and increment _outNonce
        if(verified_transaction)
        {
            v_response = _pairingHandler.encrypt((const uint8_t*)s_response.data(), 
                s_response.size(), (const uint8_t*)&_outNonce);

            if(v_response.empty())
            {
                // TODO: log error
            }
            else
            {
               _outNonce++;
            }
        }
        else    // Else populate response buffer with plain HTTP response
        {
            v_response.assign(s_response.begin(), s_response.end());
        }
        
        // Send response to client
        length = ::send(_socket, v_response.data(), v_response.size(), 0);

        if(length < 0)
        {
            // Check errno
            break;
        }
        else if((size_t)length < v_response.size())
        {
            // Maybe while loop or something
        }
    }
    
    close(shutdown_pipe);

    connectionLost();
}

bool EncryptedHTTPSocket::send(const http::Response& response) noexcept
{
    // Discard response if client is not yet paired successfully
    std::unique_lock lock(_mSocket);
    if(!_pairingHandler.clientVerified())
    {
        return false;
    }
    
    // Get response text
    std::string response_text = response.getText();

    // Encrypt response text
    std::vector<uint8_t> encrypted_v_response = _pairingHandler.encrypt(
        (const uint8_t*)response_text.data(), response_text.size(), (const uint8_t*)&_outNonce);
    if(encrypted_v_response.empty())
    {
        // TODO: log error
        return false;
    }
    else
    {
        _outNonce++;
    }
    
    // Send response to client
    ssize_t length = ::send(_socket, 
        encrypted_v_response.data(), encrypted_v_response.size(), 0);

    
    if(length < 0)
    {
        // Check errno

        return false;
    }
    else if((size_t)length < encrypted_v_response.size())
    {
        // Maybe while loop or something
    }

    return true;
}

http::Response EncryptedHTTPSocket::_requestHandler(
    const http::Request& request, 
    bool secure_session)
{
    static const std::map<std::string, 
        std::function<http::Response(EncryptedHTTPSocket* ehs, const http::Request&)>> 
    pairing_path = 
    {
        { "/pair-setup", 
        [](EncryptedHTTPSocket* ehs, const http::Request& req)
        {
            tlv::TLVData tlv_data((const uint8_t*)req.getContent().data(), 
                req.getContent().size());

            tlv::TLVData resp_tlv = ehs->_pairingHandler.pairSetup(tlv_data);
            std::vector<uint8_t> v_resp_tlv = resp_tlv.serialize();

            return http::Response(http::HTTPStatus::SUCCESS, mime_tlv8, 
                std::string((const char*)v_resp_tlv.data(), v_resp_tlv.size()));
        }},
        { "/pair-verify", 
        [](EncryptedHTTPSocket* ehs, const http::Request& req)
        {
            tlv::TLVData tlv_data((const uint8_t*)req.getContent().data(), 
                req.getContent().size());

            tlv::TLVData resp_tlv = ehs->_pairingHandler.pairVerify(tlv_data);
            std::vector<uint8_t> v_resp_tlv = resp_tlv.serialize();

            return http::Response(http::HTTPStatus::SUCCESS, mime_tlv8, 
                std::string((const char*)v_resp_tlv.data(), v_resp_tlv.size()));
        }},
        { "/pairings", 
        [](EncryptedHTTPSocket* ehs, const http::Request& req)
        {
            tlv::TLVData tlv_data((const uint8_t*)req.getContent().data(), 
                req.getContent().size());

            tlv::TLVData resp_tlv = ehs->_pairingHandler.pairings(tlv_data);
            std::vector<uint8_t> v_resp_tlv = resp_tlv.serialize();

            return http::Response(http::HTTPStatus::SUCCESS, mime_tlv8, 
                std::string((const char*)v_resp_tlv.data(), v_resp_tlv.size()));
        }},
        { "/secure-message", 
        [](EncryptedHTTPSocket* ehs, const http::Request& req)
        {
            return http::Response(http::BAD_REQUEST);
        }}
    };

    if(auto it = pairing_path.find(request.getUri()); it != pairing_path.end())
    {
        // Pairing URLs are all bound to HTTP POST method
        if(request.getMethod() != http::POST)
        {
            return http::Response(http::METHOD_NOT_ALLOWED);
        }

        return it->second(this, request);
    }

    // If session is already secured pass request to accessory handler
    if(secure_session)
    {
        return _accessoryHTTPHandler(request);
    }
    else    // Else notify authentication should be performed
    {
        return http::Response(http::CONNECTION_AUTHENTICATION_REQUIRED);
    }
    
}