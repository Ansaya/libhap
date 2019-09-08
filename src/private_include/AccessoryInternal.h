#ifndef HAP_ACCESSORYINTERNAL
#define HAP_ACCESSORYINTERNAL

#include <Accessory.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>

namespace hap {

    class ServiceInternal;

    class AccessoryInternal : public Accessory
    {
    public:
        AccessoryInternal();

        AccessoryInternal(const AccessoryInternal&) = delete;
        AccessoryInternal& operator=(const AccessoryInternal&) = delete;

        ~AccessoryInternal();

        uint64_t getID() const override;

        std::shared_ptr<Service> getService(uint64_t id) const override;

        void addService(const std::shared_ptr<Service>& service) override;

        void removeService(uint64_t iid) override;
        
        uint64_t getNewIID();

        void setID(uint64_t id);

    private:
        mutable std::mutex _mID;
        uint64_t _id;

        mutable std::mutex _mServices;
        uint64_t _iid;
        std::map<uint64_t, std::shared_ptr<ServiceInternal>> _services;
    };

}

#endif