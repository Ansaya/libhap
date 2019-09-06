#ifndef HAP_SERVICETYPE
#define HAP_SERVICETYPE

namespace hap {

    enum ServiceType {
        kServiceType_AccessoryInformation       = 0x3E,
        kServiceType_GarageDoorOpener           = 0x41,
        kServiceType_LightBulb                  = 0x43,
        kServiceType_LockMgmt                   = 0x44,
        kServiceType_LockMechanism              = 0x45,
        kServiceType_Outlet                     = 0x47,
        kServiceType_Switch                     = 0x49,
        kServiceType_Thermostat                 = 0x4A,
        kServiceType_SecuritySystem             = 0x7E,
        kServiceType_CarbonMonoxide             = 0x7F,
        kServiceType_SensorContact              = 0x80,
        kServiceType_Door                       = 0x81,
        kServiceType_SensorHumidity             = 0x82,
        kServiceType_SensorLeak                 = 0x83,
        kServiceType_SensorLight                = 0x84,
        kServiceType_SensorMotion               = 0x85,
        kServiceType_SensorOccupancy            = 0x86,
        kServiceType_SensorSmoke                = 0x87,
        kServiceType_StatelessProgSwitch        = 0x89,
        kServiceType_SensorTemperature          = 0x8A,
        kServiceType_Window                     = 0x8B,
        kServiceType_WindowCovering             = 0x8C,
        kServiceType_AirQuality                 = 0x8D,
        kServiceType_Battery                    = 0x96,
        kServiceType_CarbonDioxide              = 0x97,
        kServiceType_ProtocolInformation        = 0xA2,
        kServiceType_Fanv2                      = 0xB7,
        kServiceType_VerticalSlat               = 0xB9,
        kServiceType_FilterMaintenance          = 0xBA,
        kServiceType_HeaterCooler               = 0xBC,
        kServiceType_HumidifierDehumidifier     = 0xBD,
        kServiceType_AirPurifier                = 0xBB,
        kServiceType_ServiceLabel               = 0xCC,
        kServiceType_IrrigationSystem           = 0xCF,
        kServiceType_Valve                      = 0xD0,
        kServiceType_Faucet                     = 0xD7,
        kServiceType_CameraRTPStreamMgmt        = 0x110,
        kServiceType_Microphone                 = 0x112,
        kServiceType_Speaker                    = 0x113,
        kServiceType_Doorbell                   = 0x121,
        kServiceType_TargetControlMgmt          = 0x122,
        kServiceType_TargetControl              = 0x125,
        kServiceType_AudioStreamMgmt            = 0x127,
        kServiceType_DataStreamTransportMgmt    = 0x129,
        kServiceType_Siri                       = 0x133
    };

}

#endif