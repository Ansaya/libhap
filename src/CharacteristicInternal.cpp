#include <CharacteristicInternal.h>

#include <log.h>

#include <algorithm>

using namespace hap;

CharacteristicInternal::CharacteristicInternal(
    CharacteristicFormat format, 
    CharacteristicType type,
    const std::vector<CharacteristicPermission>& perms,
    CharacteristicUnit unit)
    : Characteristic(format, type, perms, unit), _id(0), _parentAccessory(nullptr)
{
}

CharacteristicInternal::~CharacteristicInternal()
{
}

uint64_t CharacteristicInternal::getID() const
{
    std::lock_guard lock(_mID);

    return _id;
}

void CharacteristicInternal::setParent(AccessoryInternal* parent) noexcept
{
    std::lock_guard lock(_mID);
    
    if(parent != nullptr)
    {
        _id = parent->getNewIID();
    }
    
    _parentAccessory = parent;
}

void CharacteristicInternal::registerNotification(
    std::shared_ptr<server::ControllerDevice> controller)
{
    std::lock_guard lock(_mToNotify);
        
    _toNotify.push_back(controller);
}

void CharacteristicInternal::deregisterNotification(
    std::shared_ptr<server::ControllerDevice> controller)
{
    std::lock_guard lock(_mToNotify);

    std::remove_if(_toNotify.begin(), _toNotify.end(), 
        [&](const std::shared_ptr<server::ControllerDevice>& cdp) 
        { 
            return cdp.get() == controller.get(); 
        });
}

void CharacteristicInternal::valueChanged() noexcept
{
    server::http::EventResponse event;
    
    // TODO: add JSON to event response content

    std::lock_guard lock(_mToNotify);

    for(const auto& it : _toNotify)
    {
        bool eventSent = it->send(event);

        if(!eventSent)
        {
            logger->warn("Unable to send event to controller device \"{}\"\n", it->getName());
        }
    }
}