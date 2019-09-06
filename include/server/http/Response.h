#ifndef HAP_SERVER_HTTP_RESPONSE
#define HAP_SERVER_HTTP_RESPONSE

#include "HTTPStatus.h"

#include <map>
#include <string>

namespace hap {
namespace server {
namespace http {

    class Response
    {
    public:
        /**
         * @brief Construct an empty response object
         * 
         */
        Response();

        /**
         * @brief Construct a new Response object with given status code
         * 
         * @param status HTTP status code
         */
        Response(HTTPStatus status);

        /**
         * @brief Construct a new Response object with status code and content
         * 
         * @param status HTTP status code
         * @param content_type Content-Type header value
         * @param content Response content
         */
        Response(
            HTTPStatus status, 
            const std::string& content_type, 
            const std::string& content);
        
        virtual ~Response();

        /**
         * @brief Set response HTTP status code
         * 
         * @param code HTTP status code
         */
        void setStatus(HTTPStatus code);

        /**
         * @brief Get response HTTP status code
         * 
         * @return HTTPStatus HTTP status code
         */
        HTTPStatus getStatus() const;

        /**
         * @brief Get response header for key
         * 
         * @param key Header name
         * @return std::string Header value
         */
        std::string getHeader(const std::string& key) const;
        
        /**
         * @brief Set response header
         * 
         * @param key Header name
         * @param value Header value
         */
        void setHeader(const std::string& key, const std::string& value);

        /**
         * @brief Set response content
         * 
         * @param content Response content
         */
        void setContent(const std::string& content);

        /**
         * @brief Get response content
         * 
         * @return const std::string& Response content
         */
        const std::string& getContent() const;

        /**
         * @brief Get full response text
         * 
         * @return std::string HTTP response text
         */
        virtual std::string getText() const;
    
    protected:
        /**
         * @brief Construct a new Response object with given protocol signature
         * 
         * @note Default signature is "HTTP/1.1"
         * 
         * @param protocol Protocol signature
         */
        Response(const std::string& protocol);

    private:
        const std::string _protocol;
        HTTPStatus _status;
        std::map<std::string, std::string> _headers;
        std::string _content;
    };

}
}
}

#endif