#ifndef HAP_SERVER_HAPSERVER
#define HAP_SERVER_HAPSERVER

#include <AccessoryInternal.h>
#include "ControllerDevice.h"
#include "crypto/EncryptionKeyStore.h"
#include "dns_sd/TXTRecord.h"

#include <exception>
#include <list>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace hap {

namespace server {

    class HAPServer
    {
    public:
        HAPServer(const HAPServer&) = delete;

        HAPServer& operator=(const HAPServer&) = delete;

        virtual ~HAPServer();

        /**
         * @brief Start HAP network service
         * 
         */
        void networkStart();

        /**
         * @brief Stop HAP network service
         * 
         */
        void networkStop();

        /**
         * @brief Check for network service exceptions
         * 
         * @details Get internal exceptions from underlaying network routine
         * 
         * @return std::vector<std::exception> Network service occurred exceptions since last call
         */
        std::vector<std::exception> networkCheck();

        /**
         * @brief Get the Accessory object with given id
         * 
         * @param aid Accessory ID
         * @return std::shared_ptr<hap::AccessoryInternal> Required accessory or nullptr if not found
         */
        std::shared_ptr<hap::AccessoryInternal> getAccessory(uint64_t aid) const;
        
        /**
         * @brief Add accessory to HAP server
         * 
         * @param accessory Accessory to add
         */
        void addAccessory(const std::shared_ptr<hap::AccessoryInternal>& accessory);

        /**
         * @brief Remove accessory from HAP server
         * 
         * @param aid Accessory ID to remove
         */
        void removeAccessory(uint64_t aid);

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
            std::function<bool(std::string)> display_setup_code,
            const std::string& device_mac = "");

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

        const std::string _accessoryName;
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
        uint64_t _aid;
        std::map<uint64_t, std::shared_ptr<hap::AccessoryInternal>> _accessorySet;

        void _init(
            const std::string& setup_code,
            std::function<bool(std::string setupCode)> display_setup_code);

        std::string _getLocalMAC() const;

        void _clientDisconnect(const ControllerDevice*);

        void _tcpListenerLoop(int shutdown_pipe);

        http::Response _accessoryProxy(ControllerDevice* sender, const http::Request& request);

        http::Response _accessoryHTTPHandler(
            std::shared_ptr<ControllerDevice> sender, 
            const http::Request& request);

    };

}
}

#endif