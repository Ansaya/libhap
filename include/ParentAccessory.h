#ifndef HAP_PARENTACCESSORY
#define HAP_PARENTACCESSORY

#include <cstdint>

namespace hap
{
    class ParentAccessory
    {
    public:

        virtual uint64_t getID() const = 0;

        virtual uint64_t getNewIID() = 0;

    };
}

#endif