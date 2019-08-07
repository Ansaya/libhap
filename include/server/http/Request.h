#ifndef HAP_SERVER_HTTP_REQUEST
#define HAP_SERVER_HTTP_REQUEST

#include "HTTPMethod.h"

#include <string>
#include <map>
#include <vector>

namespace hap {
namespace server {
namespace http {

    class Request
    {
    public:
        /**
         * @brief Construct a new Request object decoding given buffer as an HTTP request
         * 
         * @param buffer Buffer containing HTTP request to be decoded
         * @param buffer_size Buffer size
         */
        Request(const void* buffer, size_t buffer_size);

        virtual ~Request();
        
        /**
         * @brief Get HTTP request method
         * 
         * @return HTTPMethod HTTP request method
         */
        HTTPMethod getMethod() const;

        /**
         * @brief Get HTTP request URI
         * 
         * @return const std::string& HTTP request URI
         */
        const std::string& getUri() const;

        /**
         * @brief Get the HTTP request headers
         * 
         * @return const std::map<std::string, std::string>& Map of header name and value
         */
        const std::map<std::string, std::string>& getHeaders() const;

        /**
         * @brief Get HTTP request content
         * 
         * @return const std::vector<char>& HTTP request content
         */
        const std::vector<char>& getContent() const;


    private:
        HTTPMethod _method;
        std::string _uri;
        std::map<std::string, std::string> _headers;
        std::vector<char> _content;

    };

}
}
}

#endif