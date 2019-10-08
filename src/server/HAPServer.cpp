#include <server/HAPServer.h>

#include <Accessory.h>
#include <CharacteristicInternal.h>
#include <log.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>

#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static constexpr const char* hap_service_type = "_hap._tcp";

static constexpr const char* hap_content_type = "application/hap+json";

static constexpr int poll_timeout = 30000;

using namespace hap::server;

HAPServer::~HAPServer()
{
    networkStop();
}

void HAPServer::networkStart()
{
    if(_tcpSocket != 0) { return; }

    // TCP socket allocation
    _tcpSocket = socket(PF_INET, SOCK_STREAM, 0);
    if(_tcpSocket < 0)
    {
        int errc = errno;
        char* errstr = strerror_r(errc, NULL, 0);

        logger->error("HAPServer could not allocate a socket: {} (errno = {})", errstr, errc);

        throw std::runtime_error("Could not allocate socket");
    }

    // Require IPv4 address and random port
    struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_family = PF_INET;
	addr.sin_port = htons(0);

    // Bind listener socket
	int optval = 1;
	socklen_t optlen = sizeof(optval);
	int retval = setsockopt(_tcpSocket, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
	retval |= bind(_tcpSocket, (const struct sockaddr *)&addr, sizeof(addr));
	retval |= listen(_tcpSocket, 0);
	if (retval < 0) {
        int errc = errno;
        char* errstr = strerror_r(errc, NULL, 0);

        logger->error("HAPServer could not bind socket: {} (errno = {})", errstr, errc);

		throw std::runtime_error("Could not initialize socket");
	}

    // Get listening port
	sockaddr_in address;
	socklen_t len = sizeof(address);
	getsockname(_tcpSocket, (struct sockaddr *)&address, &len);

	uint16_t service_port = htons(ntohs(address.sin_port));

    // Register DNSSD entry
    _dnssd_entry_refresh = [&, service_port](){ return _dnssdRecord->updateEntry(0, service_port); };
    retval = _dnssd_entry_refresh();
    if(retval != 0)
    {
        logger->error("HAPServer could not register dnssd entry");

        throw std::runtime_error("Could not register dns service discovery record");
    }

    // Allocate shutdown pipe for tcp listener thread
    int shutdown_pipe[2];
    retval = pipe(shutdown_pipe);
    if(retval < 0)
    {
        int errc = errno;
        char* errstr = strerror_r(errc, NULL, 0);

        logger->error("HAPServer could not allocate pipe: {} (errno = {})", errstr, errc);

        throw std::runtime_error("Could not allocate pipe");
    }
    _tcpShutdownPipe = shutdown_pipe[1];
    
    // Start tcp listener thread
    _tcpListener = std::thread(&HAPServer::_tcpListenerLoop, this, shutdown_pipe[0]);

    logger->info("HAPServer for accessory \"{}\" ({} {}) initialized on port {}", 
        _accessoryName, _modelName, _deviceMAC, service_port);
}

void HAPServer::networkStop()
{
    if(_tcpShutdownPipe != 0)
    {
        // Join TCP listener thread and dispose TCP socket
        const char a = 'a';
        write(_tcpShutdownPipe, &a, 1);
        if(_tcpListener.joinable())
        {
            _tcpListener.join();
        }

        close(_tcpShutdownPipe);
        _tcpShutdownPipe = 0;
        
        close(_tcpSocket);
        _tcpSocket = 0;

        std::lock_guard lock(_mConnectedControllers);
        _connectedControllers.clear();

        _dnssd_entry_refresh = [](){ return 0; };

        logger->info("HAPSever for accessory \"{}\" ({} {}) stopped",
            _accessoryName, _modelName, _deviceMAC);
    }
}

std::vector<std::exception> HAPServer::networkCheck()
{
    // TODO: implement something to detect network loop failure and report it here

    return std::vector<std::exception>();
}

std::shared_ptr<hap::AccessoryInternal> HAPServer::getAccessory(uint64_t aid) const
{
    std::lock_guard lock(_mAccessorySet);
    if(const auto& it = _accessorySet.find(aid); it != _accessorySet.end())
    {
        return it->second;
    }

    return nullptr;
}
        
void HAPServer::addAccessory(const std::shared_ptr<hap::AccessoryInternal>& accessory)
{
    if(accessory != nullptr)
    {
        std::lock_guard lock(_mAccessorySet);

        accessory->setID(_aid++);

        _accessorySet.emplace(accessory->getID(), accessory);

        logger->info("New accessory added to HAPServer {} ({}).", 
            _accessoryName, _deviceMAC);

        updateConfiguration();
    }
}

void HAPServer::removeAccessory(uint64_t aid)
{
    std::lock_guard lock(_mAccessorySet);

    _accessorySet.erase(aid);

    logger->info("Accessory {} removed from HAPServer {} ({}).", 
        aid, _accessoryName, _deviceMAC);
}

rapidjson::Document HAPServer::to_json(rapidjson::Document::AllocatorType* allocator) const
{
    rapidjson::Document json(rapidjson::kObjectType, allocator);

    rapidjson::Value accessories(rapidjson::kArrayType);

    std::lock_guard lock(_mAccessorySet);
    for(const auto& [aid, a] : _accessorySet)
    {
        accessories.PushBack(a->to_json(&json.GetAllocator()), json.GetAllocator());
    }
    json.AddMember("accessories", accessories, json.GetAllocator());

    return json;
}

HAPServer::HAPServer(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number, 
    uint16_t cat_id, 
    const std::string& setup_code,
    const std::string& device_mac)
    : _tcpSocket(0), _tcpShutdownPipe(0), _dnssdRecord(nullptr), 
    _accessoryName(accessory_name), _modelName(model_name), 
    _configNumber(config_number), _categoryID(cat_id), 
    _deviceMAC(device_mac), _aid(1), _accessorySet()
{
    _init(setup_code, nullptr);
}

HAPServer::HAPServer(
    const std::string& accessory_name,
    const std::string& model_name, 
    uint16_t config_number, 
    uint16_t cat_id, 
    std::function<bool(std::string setupCode)> display_setup_code,
    const std::string& device_mac)
    : _tcpSocket(0), _tcpShutdownPipe(0), _dnssdRecord(nullptr), 
    _accessoryName(accessory_name), _modelName(model_name), 
    _configNumber(config_number), _categoryID(cat_id), 
    _deviceMAC(device_mac), _aid(1), _accessorySet()
{
    _init("", display_setup_code);
}

uint16_t HAPServer::updateConfiguration()
{
    std::lock_guard lock(_mConfigNumber);

    // Increment configuration number in range 1-65535
    if(_configNumber == UINT16_MAX)
    {
        _configNumber = 1;
    }
    else
    {
        _configNumber++;
    }

    // Update dns service discovery enrty
    _dnssdRecord->setValue("c#", std::to_string(_configNumber));
    _dnssd_entry_refresh();

    logger->info("HAPServer {} ({}) updated configuration number to {}", 
        _accessoryName, _deviceMAC, _configNumber);
    
    return _configNumber;
}

void HAPServer::_init(
    const std::string& setup_code,
    std::function<bool(std::string setupCode)> display_setup_code)
{
    // Get interface MAC address if not provided from user
    if(_deviceMAC.empty())
    {
        _deviceMAC = _getLocalMAC();
    }

    // Setup DNS SD TXT record
    _dnssdRecord = 
        new dns_sd::TXTRecord(_accessoryName.c_str(), hap_service_type);
    int retval = _dnssdRecord->setValue("c#", 
        std::to_string(_configNumber));                 // Configuration number
    retval |= _dnssdRecord->setValue("ff", "0");        // Pairing feature
    retval |= _dnssdRecord->setValue("id", _deviceMAC); // Device MAC address
    retval |= _dnssdRecord->setValue("md", _modelName); // Accessory model name
    retval |= _dnssdRecord->setValue("pv", "1.1");      // IP Protocol version
    retval |= _dnssdRecord->setValue("s#", "4");        
    retval |= _dnssdRecord->setValue("sf", "1");        // Current state
    retval |= _dnssdRecord->setValue("ci", 
        std::to_string(_categoryID));                   // Accessory category ID
    
    _dnssd_entry_refresh = [](){ return 0; };

    // Initialize encryption key store
    if(setup_code.empty())
    {
        if(display_setup_code != nullptr)
        {
            _eKeyStore = std::make_shared<crypto::EncryptionKeyStore>(
                _deviceMAC, display_setup_code);
        }
        else
        {
            throw std::invalid_argument("Setup code or code display function must be set to a valid value");
        }
    }
    else
    {
        _eKeyStore = std::make_shared<crypto::EncryptionKeyStore>(
            _deviceMAC, setup_code);
    }
}

std::string HAPServer::_getLocalMAC() const
{
    std::string mac_address("00:00:00:00:00:00");

    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
    { 
        logger->warn("Unable to create new socket to read device MAC address.");
        return mac_address;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
    { 
        logger->warn("Unable to set ifconf on socket to read device MAC address.");
        return mac_address;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) 
    {
        strcpy(ifr.ifr_name, it->ifr_name);

        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) 
        if (! (ifr.ifr_flags & IFF_LOOPBACK)) // don't count loopback
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) 
        {
            const unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
            sprintf(mac_address.data(), "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            break;
        }
    }

    return mac_address;
}

void HAPServer::_tcpListenerLoop(int shutdown_pipe)
{
    // File descriptors setup
    struct pollfd fds[2];
    fds[0] = { fd: _tcpSocket, events: POLLIN };
    fds[1] = { fd: shutdown_pipe, events: POLLIN };

    int poll_retval = 0;
    char c_name_buffer[128];
    while (true)
    {
        logger->info("HAPServer {} ({}) listenining for connections...", 
            _accessoryName, _deviceMAC);

        poll_retval = poll(fds, 2, poll_timeout);

        if(poll_retval < 0)             // poll notified an error
        {
            int errc = errno;
            char* errstr = strerror_r(errc, NULL, 0);

            logger->error("HAPServer {} ({}) listener poll failed: {} (errno = {})", 
                _accessoryName, _deviceMAC, errstr, errc);
            break;
        }
        else if(poll_retval == 0)       // poll timed out
        {
            continue;
        }

        // poll returned on a file descriptor event

        // When shutdown file descriptor notifies an event its time to go
        if(fds[1].revents)
        { 
            break; 
        }

        // If an error on tcp socket is detected dispose all
        if(fds[0].revents & (POLLHUP | POLLERR))
        {
            int errc = errno;
            char* errstr = strerror_r(errc, NULL, 0);

            logger->error("HAPServer {} ({}) listener socket failed: {} (errno = {})", 
                _accessoryName, _deviceMAC, errstr, errc);
            break;
        }

        // Accept new connection socket
        struct sockaddr_in client_addr;
        socklen_t clen;
        int controller_socket = 
            accept(_tcpSocket, (struct sockaddr*)&client_addr, &clen);

        // Get controller hostname from connection socket
        std::string controller_name("no_name");
        if(clen == sizeof(struct sockaddr_in))
        {
            // Retrieve client hostname or its numeric form
            int retval = getnameinfo((struct sockaddr*)&client_addr, clen, 
                c_name_buffer, sizeof(c_name_buffer), NULL, 0, NI_NOFQDN);

            // If buffer size was too small for hostname require numeric form
            if(retval == EAI_OVERFLOW)
            {
                retval = getnameinfo((struct sockaddr*)&client_addr, clen, 
                    c_name_buffer, sizeof(c_name_buffer), NULL, 0, NI_NUMERICHOST);
            }

            if(retval)
            {
                int errc = retval;
                const char* errstr;

                if(retval == EAI_SYSTEM)
                {
                    errc = errno;
                    errstr = strerror(errc);
                }
                else
                {
                    errstr = gai_strerror(errc);
                }
                
                logger->warn("HAPServer {} ({}) listener failed to get connected "
                        "controller name: {} (errno = {})", 
                        _accessoryName, _deviceMAC, errstr, errc);
            }
            else
            {
                controller_name.assign(c_name_buffer);
            }
        }

        logger->info("New controller \"{}\" connected to HAPServer {} ({})", 
            controller_name, _accessoryName, _deviceMAC);

        // Initialize new controller device
        std::shared_ptr<ControllerDevice> new_controller = std::make_shared<ControllerDevice>(
            controller_socket, controller_name, _eKeyStore, 
            std::bind(&HAPServer::_accessoryProxy, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&HAPServer::_clientDisconnect, this, std::placeholders::_1));

        // Add new controller device to local pool
        std::lock_guard lock(_mConnectedControllers);
        _connectedControllers.push_back(new_controller);
    }
    
    // Close shutdown_pipe fd when finished
    close(shutdown_pipe);
}

void HAPServer::_clientDisconnect(const ControllerDevice* controller_device)
{
    std::unique_lock lock(_mConnectedControllers);
    std::remove_if(_connectedControllers.begin(), _connectedControllers.end(), 
        [&](const std::shared_ptr<ControllerDevice>& cd) 
        { return cd.get() == controller_device; });
}

http::Response HAPServer::_accessoryProxy(ControllerDevice* sender, const http::Request& request)
{
    if(sender != nullptr)
    {
        logger->info("Accessory {} ({}) received request from controller {}", 
            _accessoryName, _deviceMAC, sender->getName());

        std::unique_lock lock(_mConnectedControllers);
        for(const auto& cd : _connectedControllers)
        {
            if(cd.get() == sender)
            {
                lock.unlock();
                return _accessoryHTTPHandler(cd, request);
            }
        }
    }
    else
    {
        logger->warn("Accessory {} ({}) received request from unknown", 
            _accessoryName, _deviceMAC);
        logger->trace("Request from unknown: \n{}", request.getText());
    }
    
    return hapError(http::CONNECTION_AUTHENTICATION_REQUIRED, HAPStatus::INSUFFICIENT_AUTHORIZATION);
}

http::Response HAPServer::_accessoryHTTPHandler(
    std::shared_ptr<ControllerDevice> sender, 
    const http::Request& request)
{
    std::string path = request.getPath();

    logger->trace("Controller \"\" requested url: ", 
        sender->getName(), request.getUri());

    static const std::map<std::string, 
        std::function<http::Response(std::shared_ptr<ControllerDevice>&, const http::Request&)>> 
        requests = 
    {
        {
            "/accessories", [&](std::shared_ptr<ControllerDevice>& s, const http::Request& req)
            {
                // Get accessories list
                rapidjson::Document accessories = to_json();

                return http::Response(http::SUCCESS, hap_content_type, to_json_string(accessories));
            }
        },
        {  
            "/characteristics", [&](std::shared_ptr<ControllerDevice>& s, const http::Request& req)
            {
                http::HTTPMethod method = req.getMethod();
                if(method == http::GET)
                {
                    return _characteristicsRead(s, req);
                }
                else if(method == http::PUT)
                {
                    return _characteristicsWrite(s, req);
                }
                else
                {
                    return hapError(http::METHOD_NOT_ALLOWED, HAPStatus::UNABLE);
                }
            }
        },
        {
            "/identify", [&](std::shared_ptr<ControllerDevice>& s, const http::Request& req)
            {
                std::lock_guard lock(_mConnectedControllers);
                if(_connectedControllers.empty())
                {
                    // TODO: run identification routine of primary accessory

                    return http::Response(http::NO_CONTENT);
                }

                return hapError(http::BAD_REQUEST, HAPStatus::REQUEST_DENIED);
            }
        }
    };

    // Search available reuqest handlers for required path
    if(const auto it = requests.find(path); it != requests.end())
    {
        try {
            return it->second(sender, request);
        }catch(std::exception& e)
        {
            logger->error("Request handler exception happened for request {} from \"{}\": {}", 
                request.getUri(), sender->getName(), e.what());

            return hapError(http::INTERNAL_SERVER_ERROR, HAPStatus::OUT_OF_RESOURCES);
        }
    }

    // If no valid handler is found, return bad request
    return hapError(http::HTTPStatus::BAD_REQUEST, RESOURCE_INEXISTENT);
}

http::Response HAPServer::_characteristicsWrite(
    std::shared_ptr<ControllerDevice> sender, 
    const http::Request& request)
{
    rapidjson::Document json_content;
    json_content.Parse(request.getContent().data(), request.getContent().size());

    // Check request format
    if(json_content.HasMember("characteristics") && json_content["characteristics"].IsArray())
    {
        rapidjson::Document json(rapidjson::kObjectType);
        rapidjson::Value characteristics(rapidjson::kArrayType);
        bool multi_status = false;

        // Parse all characteristics requests
        for(auto& c : json_content["characteristics"].GetArray())
        {
            uint64_t aid = c["aid"].GetUint64(), iid = c["iid"].GetUint64();
            HAPStatus status = HAPStatus::RESOURCE_INEXISTENT;

            rapidjson::Document c_json(rapidjson::kObjectType, &json.GetAllocator());
            c_json.AddMember("aid", aid, c_json.GetAllocator());
            c_json.AddMember("iid", iid, c_json.GetAllocator());

            if(const auto ait = _accessorySet.find(aid); ait != _accessorySet.end())
            {
                if(auto cit = ait->second->getCharacteristic(iid); cit != nullptr)
                {
                    CharacteristicInternal& c_int = *std::dynamic_pointer_cast<CharacteristicInternal>(cit);
                    
                    // Required resource found
                    status = HAPStatus::SUCCESS;

                    // Check if event notifications are required
                    if(c.HasMember("ev"))
                    {
                        if(c["ev"].GetBool())
                        {
                            status = c_int.registerNotification(sender);
                        }
                        else
                        {
                            status = c_int.deregisterNotification(sender);
                        }
                    }

                    // Check if value write request is present
                    if(c.HasMember("value") && status == HAPStatus::SUCCESS)
                    {
                        std::string value = c["value"].GetString();

                        status = c_int.setStringValue(value);

                        // Check if value is expected in response
                        if(c.HasMember("r") && c["r"].GetBool())
                        {
                            std::string new_value = c_int.getStringValue();

                            if(new_value.size())
                            {
                                c_json.AddMember(
                                    "value", 
                                    rapidjson::Value(new_value.c_str(), new_value.size(), c_json.GetAllocator()), 
                                    c_json.GetAllocator());
                                multi_status = true;
                            }
                            else
                            {
                                status = HAPStatus::WRITE_ONLY_CHARACTERISTIC;
                            }
                        }
                    }
                }
            }

            // If current resource failed, report with multi-status response
            if(status != HAPStatus::SUCCESS)
            {
                multi_status = true;
            }
            
            c_json.AddMember("status", (int)status, c_json.GetAllocator());

            characteristics.PushBack(c_json, json.GetAllocator());
        }
        json.AddMember("characteristics", characteristics, json.GetAllocator());

        if(multi_status)
        {
            return http::Response(http::MULTI_STATUS, hap_content_type, to_json_string(json));
        }
        else
        {
            return http::Response(http::NO_CONTENT);
        }
    }

    return hapError(http::BAD_REQUEST, HAPStatus::UNABLE);
}

http::Response HAPServer::_characteristicsRead(
    std::shared_ptr<ControllerDevice> sender, 
    const http::Request& request)
{
    const auto& qs = request.getQueryString();

    if(auto it = qs.find("id"); it != qs.end())
    {
        std::string c_list = it->second;
        std::istringstream iss(c_list);

        uint64_t aid;
        uint64_t iid;

        bool multi_status = false;

        rapidjson::Document json(rapidjson::kObjectType);
        rapidjson::Value characteristics(rapidjson::kArrayType);

        while (iss.good())
        {
            iss >> aid;
            iss.get();
            iss >> iid;
            iss.get();

            rapidjson::Value c_json(rapidjson::kObjectType);
            c_json.AddMember("aid", aid, json.GetAllocator());
            c_json.AddMember("iid", iid, json.GetAllocator());

            HAPStatus status = HAPStatus::SUCCESS;
            if(const auto ait = _accessorySet.find(aid); ait != _accessorySet.end())
            {
                if(auto cit = ait->second->getCharacteristic(iid); cit != nullptr)
                {
                    CharacteristicInternal& c_int = *std::dynamic_pointer_cast<CharacteristicInternal>(cit);

                    std::string value = c_int.getStringValue();
                    if(value.size())
                    {
                        c_json.AddMember(
                            "value", 
                            rapidjson::Value(value.c_str(), value.size(), json.GetAllocator()), 
                            json.GetAllocator());
                    }
                    else
                    {
                        multi_status = true;
                        status = HAPStatus::WRITE_ONLY_CHARACTERISTIC;
                    }
                }
            }
            else
            {
                multi_status = true;
                status = HAPStatus::RESOURCE_INEXISTENT;
            }

            c_json.AddMember("status", (int)status, json.GetAllocator());

            characteristics.PushBack(c_json, json.GetAllocator());
        }
        json.AddMember("characteristics", characteristics, json.GetAllocator());

        http::HTTPStatus state = http::MULTI_STATUS;

        if(!multi_status)
        {
            state = http::SUCCESS;

            for(auto& c : characteristics.GetArray())
            {
                c.EraseMember("status");
            }
        }

        return http::Response(state, hap_content_type, to_json_string(json));
    }

    return hapError(http::BAD_REQUEST, HAPStatus::UNABLE);
}

http::Response HAPServer::hapError(http::HTTPStatus status, HAPStatus hap_status)
{
    rapidjson::Document json(rapidjson::kObjectType);
    json.AddMember("status", (int)hap_status, json.GetAllocator());

    return http::Response(status, hap_content_type, to_json_string(json));
}