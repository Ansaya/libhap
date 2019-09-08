#ifndef HAP_ACCESSORYCATEGORY
#define HAP_ACCESSORYCATEGORY

namespace hap {

    enum AccessoryCategory : unsigned short
    {
        kAccessory_Other                    = 1,
        kAccessory_Bridges,
        kAccessory_Fans,
        kAccessory_GarageDoorOpeners,
        kAccessory_Lighting,
        kAccessory_Locks,
        kAccessory_Outlets,
        kAccessory_Switches,
        kAccessory_Thermostats,
        kAccessory_Sensors,
        kAccessory_SecuritySystems,
        kAccessory_Doors,
        kAccessory_Windows,
        kAccessory_WindowCoverings,
        kAccessory_ProgrammableSwitches,

        // Reserved 16

        kAccessory_IPCameras                = 17,
        kAccessory_VideoDoorbells,
        kAccessory_AirPurifier,
        kAccessory_Heaters,
        kAccessory_AirConditioners,
        kAccessory_Humidifiers,
        kAccessory_Dehumidifiers,

        // Reserved 24-27

        kAccessory_Sprinklers               = 28,
        kAccessory_Faucets,
        kAccessory_ShowerSystems,

        // Reserved 31

        kAccessory_Remotes                  = 32
        
        // Reserved 32+
    };

}

#endif