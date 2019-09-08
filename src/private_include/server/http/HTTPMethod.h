#ifndef HAP_SERVER_HTTP_HTTPMETHOD
#define HAP_SERVER_HTTP_HTTPMETHOD

#include <string>

namespace hap {
namespace server {
namespace http {

    enum HTTPMethod
    {
        GET,
        POST,
        PUT,
        DELETE,
        INVALID
    };

    extern HTTPMethod to_method(const std::string& http_method);

    extern std::string to_method_string(HTTPMethod http_method);

}
}
}

#endif