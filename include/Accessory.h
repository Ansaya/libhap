#ifndef HAP_ACCESSORY
#define HAP_ACCESSORY

#include <hap_export.h>
#include "AccessoryCategory.h"
#include "Service.h"

#include <cstdint>
#include <memory>

namespace hap {

    class Accessory
    {
    public:

        /**
         * @brief Initialize a generic accessory object
         * 
         * @return std::shared_ptr<Accessory> Accessory object
         */
        HAP_EXPORT static std::shared_ptr<Accessory> make_shared();

        Accessory(const Accessory&) = delete;
        Accessory& operator=(const Accessory&) = delete;
        
        HAP_EXPORT virtual ~Accessory();

        HAP_EXPORT virtual uint64_t getID() const = 0;

        HAP_EXPORT virtual std::shared_ptr<Service> getService(uint64_t id) const = 0;

        HAP_EXPORT virtual void addService(const std::shared_ptr<Service>& service) = 0;

        HAP_EXPORT virtual void removeService(uint64_t iid) = 0;

    protected:
        Accessory();
    };

}

#endif