#include <ServiceInternal.h>

#include <AccessoryInternal.h>
#include <CharacteristicInternal.h>

#include <algorithm>
#include <sstream>

using namespace hap;

ServiceInternal::ServiceInternal(ServiceType type)
    : Service(type), _id(0), _parentAccessory(nullptr)
{
}

ServiceInternal::~ServiceInternal()
{
}

uint64_t ServiceInternal::getID() const
{
    std::lock_guard lock(_mID);

    return _id;
}

std::shared_ptr<Characteristic> ServiceInternal::getCharacteristic(uint64_t iid) const
{
    std::lock_guard lock(_mCharacteristics);
    if(const auto& it = std::find_if(_characteristics.begin(), _characteristics.end(), 
        [&](const std::shared_ptr<CharacteristicInternal>& c) { return c->getID() == iid; }); 
        it != _characteristics.end())
    {
        return *it;
    }

    return nullptr;
}

void ServiceInternal::addCharacteristic(const std::shared_ptr<Characteristic>& characteristic)
{
    std::shared_ptr<CharacteristicInternal> characteristicInternal = 
        std::dynamic_pointer_cast<CharacteristicInternal>(characteristic);

    if(characteristicInternal != nullptr)
    {
        std::lock_guard lock(_mCharacteristics);

        _characteristics.push_back(characteristicInternal);

        characteristicInternal->setParent(_parentAccessory);
    }
}

void ServiceInternal::removeCharacteristic(uint64_t iid)
{
    std::lock_guard lock(_mCharacteristics);
    
    if(const auto& it = std::find_if(_characteristics.begin(), _characteristics.end(), 
        [&](const std::shared_ptr<CharacteristicInternal>& c) { return c->getID() == iid; }); 
        it != _characteristics.end())
    {
        (*it)->setParent(nullptr);

        _characteristics.erase(it);
    }
}

void ServiceInternal::setParent(AccessoryInternal* parent) noexcept
{
    // Update service iid
    std::scoped_lock lock(_mID, _mCharacteristics);
    
    if(parent != nullptr)
    {
        // Accessory information service always has iid 1
        if(getType() == kServiceType_AccessoryInformation)
        {
            _id = 1;
        }
        else
        {
            _id = parent->getNewIID();
        }
    }

    _parentAccessory = parent;
    

    // Update service's characteristics' iid
    for(const auto& c : _characteristics)
    {
        c->setParent(parent);
    }
}

rapidjson::Document ServiceInternal::to_json(rapidjson::Document::AllocatorType* allocator) const
{
    rapidjson::Document json(rapidjson::kObjectType, allocator);

    std::ostringstream sstr;
    sstr << std::hex << ((int)getType());
    std::string tstr(sstr.str());
    json.AddMember(
        "type", 
        rapidjson::Value(tstr.c_str(), tstr.size(), json.GetAllocator()), 
        json.GetAllocator());

    std::scoped_lock lock(_mID, _mCharacteristics);
    
    json.AddMember("iid", _id, json.GetAllocator());

    rapidjson::Value characteristics(rapidjson::kArrayType);
    for(auto& it : _characteristics)
    {
        characteristics.PushBack(it->to_json(&json.GetAllocator()), json.GetAllocator());
    }
    json.AddMember("characteristics", characteristics, json.GetAllocator());

    // TODO: deal with hidden, primary and linked

    return json;
}