#ifndef HAP_CHARACTERISTICINTERNAL
#define HAP_CHARACTERISTICINTERNAL

#include "server/ControllerDevice.h"
#include "server/HAPStatus.h"
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

        /**
         * @brief Get characteristic value
         * 
         * @return std::string Characteristic value or empty if read permission isn't present
         */
        virtual std::string getStringValue() const = 0;

        /**
         * @brief Set characteristic value
         * 
         * @param value New characteristic value
         * @return server::HAPStatus Value setting request status
         */
        virtual server::HAPStatus setStringValue(const std::string& value) = 0;

        server::HAPStatus registerNotification(std::shared_ptr<server::ControllerDevice> controller);

        server::HAPStatus deregisterNotification(std::shared_ptr<server::ControllerDevice> controller);

        virtual rapidjson::Document to_json(rapidjson::Document::AllocatorType* allocator = nullptr) const override;

    protected:
        void valueChanged(rapidjson::Value value) noexcept;

    private:
        mutable std::mutex _mID;
        uint64_t _id;
        AccessoryInternal* _parentAccessory;

        std::mutex _mToNotify;
        std::list<std::shared_ptr<server::ControllerDevice>> _toNotify;        
    };

}

#endif