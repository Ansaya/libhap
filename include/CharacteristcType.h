#ifndef HAP_CHARACTERISTICTYPE
#define HAP_CHARACTERISTICTYPE

namespace hap {

    enum CharacteristicType {
        kCharacteristic_AccessoryProperties                     = 0xA6,
        kCharacteristic_Active                                  = 0xB0,
        kCharacteristic_ActiveIdentifier                        = 0xE7,
        kCharacteristic_AdminOnlyAccess                         = 0x1,
        kCharacteristic_AudioFeedback                           = 0x5,
        kCharacteristic_AirParticulateDensity                   = 0x64,
        kCharacteristic_AirParticulateSize                      = 0x65,
        kCharacteristic_AirQuality                              = 0x95,
        kCharacteristic_BatteryLevel                            = 0x68,
        kCharacteristic_Brightness                              = 0x8,
        kCharacteristic_ButtonEvent                             = 0x126,
        kCharacteristic_CarbonMonoxideLevel                     = 0x90,
        kCharacteristic_CarbonMonozidePeakLevel                 = 0x91,
        kCharacteristic_CarbonDioxideDetected                   = 0x92,
        kCharacteristic_CarbonDioxideLevel                      = 0x93,
        kCharacteristic_CarbonDioxidePeakLevel                  = 0x94,
        kCharacteristic_CarbonMonoxideDetected                  = 0x69,
        kCharacteristic_ChargingState                           = 0x8F,
        kCharacteristic_TemperatureCoolingThreshold             = 0x0D,
        kCharacteristic_ColorTemperature                        = 0xCE,
        kCharacteristic_ContactState                            = 0x6A,
        kCharacteristic_LightLevelCurrent                       = 0x6B,
        kCharacteristic_HorizontalTiltCurrent                   = 0x6C,
        kCharacteristic_AirPurifierStateCurrent                 = 0xA9,
        kCharacteristic_SlatStateCurrent                        = 0xAA,
        kCharacteristic_PositionCurrent                         = 0x6D,
        kCharacteristic_VerticalTiltCurrent                     = 0x6E,
        kCharacteristic_HumidifierDehumidifierStateCurrent      = 0xB3,
        kCharacteristic_DoorStateCurrent                        = 0xE,
        kCharacteristic_FanStateCurrent                         = 0xAF,
        kCharacteristic_HeatingCoolingCurrent                   = 0xF,
        kCharacteristic_HeaterCoolerStateCurrent                = 0xB1,
        kCharacteristic_RelativeHumidityCurrent                 = 0x10,
        kCharacteristic_TemperatureCurrent                      = 0x11,
        kCharacteristic_TiltCurrent                             = 0xC1,
        kCharacteristic_ZoomDigital                             = 0x11D,
        kCharacteristic_FilterLifeLevel                         = 0xAB,
        kCharacteristic_FilterChangeIndication                  = 0xAC,
        kCharacteristic_FirmwareRevision                        = 0x52,
        kCharacteristic_HardwareRevision                        = 0x53,
        kCharacteristic_TemperatureHeatingThreshold             = 0x12,
        kCharacteristic_PositionHold                            = 0x6F,
        kCharacteristic_Hue                                     = 0x13,
        kCharacteristic_Identify                                = 0x14,
        kCharacteristic_ImageRotation                           = 0x11E,
        kCharacteristic_ImageMirror                             = 0x11F,
        kCharacteristic_InUse                                   = 0xD2,
        kCharacteristic_IsConfigured                            = 0xD6,
        kCharacteristic_LeakDetected                            = 0x70,
        kCharacteristic_LockManagementControlPoint              = 0x19,
        kCharacteristic_LockMechanismCurrentState               = 0x1D,
        kCharacteristic_LokMechanismLastKnownAction             = 0x1C,
        kCharacteristic_LockMechanismAutoSecureTimeout          = 0x1A,
        kCharacteristic_LockPhysicalControls                    = 0xA7,
        kCharacteristic_LockMechanismTargetState                = 0x1E,
        kCharacteristic_Logs                                    = 0x1F,
        kCharacteristic_Manufacturer                            = 0x20,
        kCharacteristic_Model                                   = 0x21,
        kCharacteristic_MotionDetected                          = 0x22,
        kCharacteristic_Mute                                    = 0x11A,
        kCharacteristic_Name                                    = 0x23,
        kCharacteristic_NightVision                             = 0x11B,
        kCharacteristic_DensityNO2                              = 0xC4,
        kCharacteristic_ObstructionDetected                     = 0x24,
        kCharacteristic_DensityPM2_5                            = 0xC6,
        kCharacteristic_OccupancyDetected                       = 0x71,
        kCharacteristic_ZoomOptical                             = 0x11C,
        kCharacteristic_OutletInUse                             = 0x26,
        kCharacteristic_On                                      = 0x25,
        kCharacteristic_DensityOzone                            = 0xC3,
        kCharacteristic_DensityPM10                             = 0xC7,
        kCharacteristic_PositionState                           = 0x72,
        kCharacteristic_ProgramMode                             = 0xD1,
        kCharacteristic_InputEvent                              = 0x73,
        kCharacteristic_RelativeHumidityDehumidifierThreshold   = 0xC9,
        kCharacteristic_RelativeHumidityHumidifierThreshold     = 0xCA,
        kCharacteristic_RemainingDuration                       = 0xD4,
        kCharacteristic_ResetIndication                         = 0xAD,
        kCharacteristic_RotationDirection                       = 0x28,
        kCharacteristic_RotationSpeed                           = 0x29,
        kCharacteristic_Saturation                              = 0x2F,
        kCharacteristic_SecuritySystemAlarmType                 = 0x8E,
        kCharacteristic_SecuritySystemStateCurrent              = 0x66,
        kCharacteristic_SecuritySystemStateTarget               = 0x67,
        kCharacteristic_SelectedAudioStreamConfiguration        = 0x128,
        kCharacteristic_SerialNumber                            = 0x30,
        kCharacteristic_ServiceLabelIndex                       = 0xCB,
        kCharacteristic_ServiceLabelNamespace                   = 0xCD,
        kCharacteristic_SetupDataStreamTransport                = 0x131,
        kCharacteristic_SelectedRTPStreamConfiguration          = 0x117,
        kCharacteristic_SetupEndpoints                          = 0x118,
        kCharacteristic_SiriInputType                           = 0x132,
        kCharacteristic_TypeSlat                                = 0xC0,
        kCharacteristic_SmokeDetected                           = 0x76,
        kCharacteristic_StatusActive                            = 0x75,
        kCharacteristic_StatusFault                             = 0x77,
        kCharacteristic_StatusJammed                            = 0x78,
        kCharacteristic_StatusLowBattery                        = 0x79,
        kCharacteristic_StatusTampered                          = 0x7A,
        kCharacteristic_StreamingStatus                         = 0x120,
        kCharacteristic_SupportedAudioConfiguration             = 0x115,
        kCharacteristic_SupportedDataStreamTransportConfig      = 0x130,
        kCharacteristic_SupportedRTPConfiguration               = 0x116,
        kCharacteristic_SupportedVideoStreamConfiguration       = 0x114,
        kCharacteristic_DensitySO2                              = 0xC5,
        kCharacteristic_SwingMode                               = 0xB6,
        kCharacteristic_AirPurifierStateTarget                  = 0xA8,
        kCharacteristic_FanStateTarget                          = 0xBF,
        kCharacteristic_TiltTarget                              = 0xC2,
        kCharacteristic_HeaterCoolerStateTarget                 = 0xB2,
        kCharacteristic_SetDuration                             = 0xD3,
        kCharacteristic_SupportedTargetConfiguration            = 0x123,
        kCharacteristic_TargetList                              = 0x124,
        kCharacteristic_HorizontalTiltAngle                     = 0x7B,
        kCharacteristic_HumidifierDehumidifierStateTarget       = 0xB4,
        kCharacteristic_PositionTarget                          = 0x7C,
        kCharacteristic_DoorStateTarget                         = 0x32,
        kCharacteristic_HeatingCoolingTarget                    = 0x33,
        kCharacteristic_RelativeHumidityTarget                  = 0x34,
        kCharacteristic_TemperatureTarget                       = 0x35,
        kCharacteristic_TemperatureUnits                        = 0x36,
        kCharacteristic_VerticalTiltTarget                      = 0x7D,
        kCharacteristic_ValveType                               = 0xD5,
        kCharacteristic_Version                                 = 0x37,
        kCharacteristic_DensityVOC                              = 0xC8,
        kCharacteristic_Volume                                  = 0x119,
        kCharacteristic_WaterLevel                              = 0xB5
    };

}

#endif