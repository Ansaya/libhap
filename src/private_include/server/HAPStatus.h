#ifndef HAP_SERVER_HAPSTATUS
#define HAP_SERVER_HAPSTATUS


namespace hap {
namespace server {

    enum HAPStatus
    {
        SUCCESS                     = 0,
        REQUEST_DENIED              = -70401,
        UNABLE                      = -70402,
        RESOURCE_BUSY               = -70403,
        READ_ONLY_CHARACTERISTIC    = -70404,
        WRITE_ONLY_CHARACTERISTIC   = -70405,
        NOTIFICATION_NOT_SUPPORTED  = -70406,
        OUT_OF_RESOURCES            = -70407,
        OPERATION_TIMED_OUT         = -70408,
        RESOURCE_INEXISTENT         = -70409,
        INVALID_VALUE               = -70410,
        INSUFFICIENT_AUTHORIZATION  = -70411
    };

}
}

#endif