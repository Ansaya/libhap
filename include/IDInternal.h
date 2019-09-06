#ifndef HAP_IDINTERNAL
#define HAP_IDINTERNAL

#include <cstdint>

namespace hap {

    class IDInternal 
    {
    public:

        virtual void setID(uint64_t id) = 0;
    };

}

#endif