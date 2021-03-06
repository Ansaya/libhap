#ifndef HAP_PRIMARYACCESSORY
#define HAP_PRIMARYACCESSORY

#include <hap_export.h>
#include <Accessory.h>
#include <AccessoryCategory.h>
#include <IPrimaryAccessory.h>

#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace hap {

    class PrimaryAccessory : virtual public IPrimaryAccessory, virtual public Accessory
    {
    public:
        /**
         * @brief Initialize a primary accessory object exposed on local network
         * 
         * @details Initialize a primary accessory which will automatically launch
         *          an HTTP HAP server advertised using dnssd
         * 
         * @param accessory_name 
         * @param model_name 
         * @param config_number 
         * @param category 
         * @param setup_code 
         * @param device_mac 
         * @return std::shared_ptr<PrimaryAccessory> Primary accessory object
         */
        HAP_EXPORT static std::shared_ptr<PrimaryAccessory> make_shared(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number,
            AccessoryCategory category,
            const std::string& setup_code,
            const std::string& device_mac = "");

        /**
         * @brief Initialize a primary accessory object exposed on local network
         * 
         * @details Initialize a primary accessory which will automatically launch
         *          an HTTP HAP server advertised using dnssd
         * 
         * @param accessory_name 
         * @param model_name 
         * @param config_number 
         * @param category 
         * @param display_setup_code 
         * @param device_mac 
         * @return std::shared_ptr<PrimaryAccessory> Primary accessory object
         */
        HAP_EXPORT static std::shared_ptr<PrimaryAccessory> make_shared(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number, 
            AccessoryCategory category,
            std::function<bool(std::string)> display_setup_code,
            const std::string& device_mac = "");

        PrimaryAccessory(const PrimaryAccessory&) = delete;
        PrimaryAccessory& operator=(const PrimaryAccessory&) = delete;

        HAP_EXPORT virtual ~PrimaryAccessory();

    protected:
        PrimaryAccessory();

    };

}

#endif