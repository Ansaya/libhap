#ifndef HAP_SERVER_ENCRYPTEDHTTPSOCKET
#define HAP_SERVER_ENCRYPTEDHTTPSOCKET

#include "crypto/EncryptionKeyStore.h"
#include "PairingHandler.h"
#include "http/Request.h"
#include "http/Response.h"

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace hap {
namespace server {

    class EncryptedHTTPSocket
    {
    public:
        /**
         * @brief Construct a new Encrypted HTTP Socket handler
         * 
         * @param socket HTTP socket file descriptor
         * @param e_key_store Encryption key store associated with this connection
         * @param cb Accessory request handler associated with this connection
         */
        EncryptedHTTPSocket(
            int socket, 
            std::shared_ptr<crypto::EncryptionKeyStore> e_key_store,
            std::function<http::Response(const http::Request&)> cb);

        EncryptedHTTPSocket(const EncryptedHTTPSocket&) = delete;
        EncryptedHTTPSocket& operator=(const EncryptedHTTPSocket&) = delete;

        virtual ~EncryptedHTTPSocket();

        /**
         * @brief Send HTTP response to client
         * 
         * @detail Given HTTP response is sent to the client only after a successful
         *         pairing procedure has been completed
         * 
         * @param response HTTP response to send to the client
         * @return true When HTTP response has been sent succesfully
         * @return false When some error occurred during send procedure or if client was not yet paired
         */
        bool send(const http::Response& response);

    private:
        const int _socket;
        uint64_t _outNonce;
        std::mutex _mSocket;
        std::condition_variable _cvSocket;
        PairingHandler _pairingHandler;
        const std::function<http::Response(const http::Request&)> _accessoryRequestHandler;

        int _shutdownPipe;
        std::thread* _httpListener;

        void _httpListenerLoop(int shutdown_pipe);

        http::Response _requestHandler(const http::Request& request, bool secure_session);

    };

}
}

#endif