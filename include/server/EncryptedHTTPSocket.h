#ifndef HAP_SERVER_ENCRYPTEDHTTPSOCKET
#define HAP_SERVER_ENCRYPTEDHTTPSOCKET

#include "EncryptionKeyStore.h"
#include "http/Request.h"
#include "http/Response.h"

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

namespace hap {
namespace server {

    class EncryptedHTTPSocket
    {
    public:
        EncryptedHTTPSocket(
            int socket, 
            std::shared_ptr<EncryptionKeyStore> e_key_store,
            std::function<http::Response(const http::Request&)> cb);

        EncryptedHTTPSocket(const EncryptedHTTPSocket&) = delete;

        EncryptedHTTPSocket& operator=(const EncryptedHTTPSocket&) = delete;

        virtual ~EncryptedHTTPSocket();

        void send(const http::Response& response);

    private:
        const int _socket;
        std::atomic_bool _socketSecured;
        const std::shared_ptr<EncryptionKeyStore> _eKeyStore;
        const std::function<http::Response(const http::Request&)> _cb;

        int _shutdownPipe;
        std::thread* _httpListener;

        void _httpListenerLoop(int shutdown_pipe);

        http::Response _secureSetup(const http::Request& controller_request);

        void encrypt(char* buffer, size_t buffer_length);

        void decrypt(char* buffer, size_t buffer_length);

    };

}
}

#endif