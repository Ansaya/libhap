#ifndef HAP_SERVER_HTTP_EVENTRESPONSE
#define HAP_SERVER_HTTP_EVENTRESPONSE

#include "Response.h"

namespace hap {
namespace server {
namespace http {

    class EventResponse : public Response
    {
    public:
        /**
         * @brief Construct a new empty Event Response object
         * 
         */
        EventResponse();

    };

}
}
}

#endif