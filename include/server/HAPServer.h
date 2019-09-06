#ifndef HAP_SERVER_HAPSERVER
#define HAP_SERVER_HAPSERVER

#include "ControllerDevice.h"
#include "crypto/EncryptionKeyStore.h"
#include "dns_sd/TXTRecord.h"
#include <hap_export.h>

#include <list>
#include <memory>
#include <mutex>
#include <thread>

namespace hap {

    class Accessory;

namespace server {

    class HAPServer
    {
    public:
        HAPServer(const HAPServer&) = delete;

        HAPServer& operator=(const HAPServer&) = delete;

        HAP_EXPORT virtual ~HAPServer();

    protected:
        HAPServer(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number, 
            uint16_t cat_id, 
            const std::string& setup_code,
            const std::string& device_mac = "");

        HAPServer(
            const std::string& accessory_name,
            const std::string& model_name, 
            uint16_t config_number, 
            uint16_t cat_id, 
            std::function<bool(std::string setupCode)> display_setup_code,
            const std::string& device_mac = "");

        /**
         * @brief Get the Accessory object with given id
         * 
         * @param aid Accessory ID
         * @return std::shared_ptr<Accessory> Required accessory or nullptr if not found
         */
        std::shared_ptr<Accessory> getAccessory(uint64_t aid) const;
        
        /**
         * @brief Add accessory to HAP server
         * 
         * @param accessory Accessory to add
         */
        void addAccessory(const std::shared_ptr<Accessory>& accessory);

        /**
         * @brief Remove accessory from HAP server
         * 
         * @param aid Accessory ID to remove
         */
        void removeAccessory(uint64_t aid);

        /**
         * @brief Increment configuration number updating all related entries
         * 
         * @return uint16_t Updated configuration number
         */
        uint16_t updateConfiguration();

    private:
        int _tcpSocket;
        int _tcpShutdownPipe;
        dns_sd::TXTRecord* _dnssdRecord;

        const std::string _modelName;
        uint16_t _configNumber;
        std::mutex _mConfigNumber;
        const uint16_t _categoryID;
        std::string _deviceMAC;

        std::shared_ptr<crypto::EncryptionKeyStore> _eKeyStore;

        std::thread* _tcpListener;

        std::mutex _mConnectedControllers;
        std::list<std::shared_ptr<ControllerDevice>> _connectedControllers;

        mutable std::mutex _mAccessorySet;
        std::map<uint64_t, std::shared_ptr<Accessory>> _accessorySet;

        void _init(
            const std::string& accessory_name,
            const std::string& setup_code,
            std::function<bool(std::string setupCode)> display_setup_code);

        void _tcpListenerLoop(int shutdown_pipe);

        http::Response _accessoryProxy(ControllerDevice* sender, const http::Request& request);

        http::Response _accessoryHTTPHandler(
            std::shared_ptr<ControllerDevice> sender, 
            const http::Request& request);

    };

}
}

#endif