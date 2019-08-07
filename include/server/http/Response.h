#ifndef HAP_SERVER_HTTP_RESPONSE
#define HAP_SERVER_HTTP_RESPONSE

#include "HTTPStatus.h"

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

        Response(
            HTTPStatus status_code, 
            const std::string& content_type, 
            const char* content, 
            size_t content_length);
        
        virtual ~Response();

        const std::string& getText() const;

    private:
        std::string _text;
    };

}
}
}

#endif