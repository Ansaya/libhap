#ifndef HAP_PRIMARYACCESSORYINTERNAL
#define HAP_PRIMARYACCESSORYINTERNAL

#include <AccessoryBridge.h>
#include <AccessoryInternal.h>
#include <server/HAPServer.h>

namespace hap {

    class PrimaryAccessoryInternal : private server::HAPServer, public AccessoryInternal, public AccessoryBridge
    {
    public: 
        PrimaryAccessoryInternal(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number,
            AccessoryCategory category,
            const std::string& setup_code,
            const std::string& device_mac = "");

        PrimaryAccessoryInternal(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number,
            AccessoryCategory category,
            std::function<bool(std::string)> display_setup_code,
            const std::string& device_mac = "");

        PrimaryAccessoryInternal(const PrimaryAccessoryInternal&) = delete;
        PrimaryAccessoryInternal& operator=(const PrimaryAccessoryInternal&) = delete;

        virtual ~PrimaryAccessoryInternal();

        void networkStart() override;

        void networkStop() override;

        std::vector<std::exception> networkCheck() override;

        std::shared_ptr<Accessory> getAccessory(uint64_t aid) const override;
        
        void addAccessory(const std::shared_ptr<Accessory>& accessory) override;

        void removeAccessory(uint64_t aid) override;

    };

}

#endif