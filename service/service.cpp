#include <iostream>

#include <AccessoryBridge.h>
#include <log.h>

static constexpr const char* hap_code = "123-45-678";

int main(int argc, char** argv)
{
    hap::logger->set_level(spdlog::level::level_enum::trace);

    std::shared_ptr<hap::AccessoryBridge> hap_bridge = 
        hap::AccessoryBridge::make_shared("HAP Bridge", "HAP_Service_Bridge", 1, hap_code);

    hap_bridge->networkStart();

    std::cout << "HAP bridge service started" << std::endl;
    std::cout << "Accessory code: " << hap_code << std::endl;

    std::cin.ignore();

    hap_bridge->networkStop();

    return 0;
}