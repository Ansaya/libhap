#ifndef HAP_ACCESSORYBRIDGE
#define HAP_ACCESSORYBRIDGE

#include <hap_export.h>
#include <Accessory.h>
#include <IPrimaryAccessory.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace hap {

    class AccessoryBridge : virtual public IPrimaryAccessory
    {
    public:
        /**
         * @brief Initialize an accessory bridge to expose multiple accessories
         * 
         * @details Initialized accessory bridge will expose added accessories 
         *          from its HTTP HAP server advertised using dnssd
         * 
         * @param accessory_name 
         * @param model_name 
         * @param config_number 
         * @param setup_code 
         * @param device_mac 
         * @return std::shared_ptr<AccessoryBridge> Accessory bridge object
         */
        HAP_EXPORT static std::shared_ptr<AccessoryBridge> make_shared(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number,
            const std::string& setup_code,
            const std::string& device_mac = "");

        /**
         * @brief Initialize an accessory bridge to expose multiple accessories
         * 
         * @details Initialized accessory bridge will expose added accessories 
         *          from its HTTP HAP server advertised using dnssd
         * 
         * @param accessory_name 
         * @param model_name 
         * @param config_number 
         * @param display_setup_code 
         * @param device_mac 
         * @return std::shared_ptr<AccessoryBridge> Accessory bridge object
         */
        HAP_EXPORT static std::shared_ptr<AccessoryBridge> make_shared(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number, 
            std::function<bool(std::string)> display_setup_code,
            const std::string& device_mac = "");

        AccessoryBridge(const AccessoryBridge&) = delete;
        AccessoryBridge& operator=(const AccessoryBridge&) = delete;

        HAP_EXPORT virtual ~AccessoryBridge();

        /**
         * @brief Get the Accessory object with given id
         * 
         * @param aid Accessory ID
         * @return std::shared_ptr<Accessory> Required accessory or nullptr if not found
         */
        HAP_EXPORT virtual std::shared_ptr<Accessory> getAccessory(uint64_t aid) const = 0;
        
        /**
         * @brief Add accessory to HAP server
         * 
         * @param accessory Accessory to add
         */
        HAP_EXPORT virtual void addAccessory(const std::shared_ptr<Accessory>& accessory) = 0;

        /**
         * @brief Remove accessory from HAP server
         * 
         * @param aid Accessory ID to remove
         */
        HAP_EXPORT virtual void removeAccessory(uint64_t aid) = 0;

    protected:
        AccessoryBridge();

    };

}

#endif