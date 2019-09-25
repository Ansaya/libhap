#ifndef HAP_IPRIMARYACCESSORY
#define HAP_IPRIMARYACCESSORY

#include <hap_export.h>

#include <exception>
#include <vector>

namespace hap 
{
    class IPrimaryAccessory
    {
    public:
        /**
         * @brief Start HAP network service
         * 
         */
        HAP_EXPORT virtual void networkStart() = 0;

        /**
         * @brief Stop HAP network service
         * 
         */
        HAP_EXPORT virtual void networkStop() = 0;

        /**
         * @brief Check for network service exceptions
         * 
         * @details Get internal exceptions from underlaying network routine
         * 
         * @return std::vector<std::exception> Network service occurred exceptions since last call
         */
        HAP_EXPORT virtual std::vector<std::exception> networkCheck() = 0;
    };
}

#endif