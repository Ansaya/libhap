#ifndef HAP_CHARACTERISTICINTERNAL
#define HAP_CHARACTERISTICINTERNAL

#include <server/ControllerDevice.h>
#include <Characteristic.h>
#include <AccessoryInternal.h>
#include <HasJSON.h>

#include <memory>
#include <mutex>
#include <list>

namespace hap {
    
    class CharacteristicInternal : virtual public Characteristic, public HasJSON
    {
    public:
        CharacteristicInternal(
            CharacteristicFormat format, 
            CharacteristicType type,
            const std::vector<CharacteristicPermission>& perms,
            CharacteristicUnit unit = kUnit_no_unit);

        CharacteristicInternal(const CharacteristicInternal&) = delete;
        CharacteristicInternal& operator=(const CharacteristicInternal&) = delete;

        virtual ~CharacteristicInternal();

        uint64_t getID() const override;

        void setParent(AccessoryInternal* parent) noexcept;

        void registerNotification(std::shared_ptr<server::ControllerDevice> controller);

        void deregisterNotification(std::shared_ptr<server::ControllerDevice> controller);

        virtual rapidjson::Document to_json(rapidjson::Document::AllocatorType* allocator = nullptr) const override;

    protected:
        void valueChanged() noexcept;

    private:
        mutable std::mutex _mID;
        uint64_t _id;
        AccessoryInternal* _parentAccessory;

        std::mutex _mToNotify;
        std::list<std::shared_ptr<server::ControllerDevice>> _toNotify;        
    };

}

#endif