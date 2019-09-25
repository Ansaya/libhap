#ifndef HAP_SERVER_HTTP_HTTPSTATUS
#define HAP_SERVER_HTTP_HTTPSTATUS

namespace hap {
namespace server {
namespace http {

    enum HTTPStatus
    {
        SUCCESS                                 = 200,
        NO_CONTENT                              = 204,
        MULTI_STATUS                            = 207,
        BAD_REQUEST                             = 400,
        NOT_FOUND                               = 404,
        METHOD_NOT_ALLOWED                      = 405,
        UNPROCESSABLE_ENTITY                    = 422,
        TOO_MANY_REQUESTS                       = 429,
        CONNECTION_AUTHENTICATION_REQUIRED      = 470,
        INTERNAL_SERVER_ERROR                   = 500,
        SERVICE_UNAVAILABLE                     = 503
    };

}
}
}

#endif