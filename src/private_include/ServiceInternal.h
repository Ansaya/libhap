#ifndef HAP_SERVICEINTERNAL
#define HAP_SERVICEINTERNAL

#include <Service.h>
#include <AccessoryInternal.h>
#include <CharacteristicInternal.h>
#include <HasJSON.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace hap {

    class ServiceInternal : public Service, public HasJSON
    {
    public:
        ServiceInternal(ServiceType type);

        ServiceInternal(const ServiceInternal&) = delete;
        ServiceInternal& operator=(const ServiceInternal&) = delete;

        ~ServiceInternal();

        uint64_t getID() const override;

        std::shared_ptr<Characteristic> getCharacteristic(uint64_t iid) const override;

        void addCharacteristic(const std::shared_ptr<Characteristic>& characteristic) override;

        void removeCharacteristic(uint64_t iid) override;

        void setParent(AccessoryInternal* parent) noexcept;

        rapidjson::Document to_json(rapidjson::Document::AllocatorType* allocator = nullptr) const override;

    private:
        mutable std::mutex _mID;
        uint64_t _id;
        AccessoryInternal* _parentAccessory;

        mutable std::mutex _mCharacteristics;
        std::vector<std::shared_ptr<CharacteristicInternal>> _characteristics;
    };

}

#endif