#ifndef HAP_SERVICE
#define HAP_SERVICE

#include <hap_export.h>
#include "Characteristic.h"
#include "ServiceType.h"

#include <cstdint>
#include <memory>

namespace hap {

    class Service
    {
    public:

        HAP_EXPORT static std::shared_ptr<Service> make_shared(ServiceType type);

        Service(const Service&) = delete;
        Service& operator=(const Service&) = delete;

        HAP_EXPORT virtual ~Service();

        HAP_EXPORT virtual uint64_t getID() const = 0;

        HAP_EXPORT ServiceType getType() const;

        HAP_EXPORT virtual std::shared_ptr<Characteristic> getCharacteristic(uint64_t iid) const = 0;

        HAP_EXPORT virtual void setCharacteristic(const std::shared_ptr<Characteristic>& characteristic) = 0;

        HAP_EXPORT virtual void removeCharacteristic(uint64_t iid) = 0;

    protected:
        Service(ServiceType type);

    private:
        const ServiceType _type;

    };

}

#endif