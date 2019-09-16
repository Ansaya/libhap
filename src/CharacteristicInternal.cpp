#include <CharacteristicInternal.h>

#include <log.h>

#include <algorithm>
#include <sstream>

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

rapidjson::Document CharacteristicInternal::to_json(rapidjson::Document::AllocatorType* allocator) const
{
    rapidjson::Document json(rapidjson::kObjectType, allocator);

    std::ostringstream sstr;
    sstr << std::hex << ((int)getType());
    std::string tstr = sstr.str();
    json.AddMember(
        "type", 
        rapidjson::Value(tstr.c_str(), tstr.size(), json.GetAllocator()), 
        json.GetAllocator());

    std::string value(getStringValue());
    json.AddMember(
        "value", 
        rapidjson::Value(value.c_str(), value.size(), json.GetAllocator()), 
        json.GetAllocator());
    
    rapidjson::Value perms(rapidjson::kArrayType);
    for(auto& p : getPermissions())
    {
        std::string pstr = to_permission_string(p);
        perms.PushBack(
            rapidjson::Value(pstr.c_str(), pstr.size(), json.GetAllocator()), 
            json.GetAllocator());
    }
    json.AddMember("perms", perms, json.GetAllocator());

    std::string format(to_format_string(getFormat()));
    json.AddMember(
        "format", 
        rapidjson::Value(format.c_str(), format.size(), json.GetAllocator()), 
        json.GetAllocator());

    if(CharacteristicUnit u = getUnit(); u != kUnit_no_unit)
    {
        std::string ustr = to_unit_string(u);
        json.AddMember(
            "unit", 
            rapidjson::Value(ustr.c_str(), ustr.size(), json.GetAllocator()), 
            json.GetAllocator());
    }

    std::lock_guard lock(_mID);

    json.AddMember("iid", _id, json.GetAllocator());

    return json;
}