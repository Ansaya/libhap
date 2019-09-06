#ifndef HAP_ACCESSORY
#define HAP_ACCESSORY

#include <hap_export.h>
#include "Service.h"

#include <cstdint>
#include <memory>

namespace hap {

    class Accessory
    {
    public:

        HAP_EXPORT static std::shared_ptr<Accessory> make_shared();
        
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