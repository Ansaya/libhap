#include <AccessoryInternal.h>

#include <ServiceInternal.h>

using namespace hap;

AccessoryInternal::AccessoryInternal()
    : _id(1), _iid(2)
{

}
        
AccessoryInternal::~AccessoryInternal()
{
    for(auto& [iid, s] : _services)
    {
        s->setParent(nullptr);
    }
}

uint64_t AccessoryInternal::getID() const
{
    std::lock_guard lock(_mID);
    return _id;
}

uint64_t AccessoryInternal::getNewIID()
{
    return _iid++;
}

std::shared_ptr<Service> AccessoryInternal::getService(uint64_t id) const
{
    std::lock_guard lock(_mServices);
    if(const auto& it = _services.find(id); it != _services.end())
    {
        return it->second;
    }

    return nullptr;
}

void AccessoryInternal::addService(const std::shared_ptr<Service>& service)
{
    std::shared_ptr<ServiceInternal> serviceInternal = 
        std::dynamic_pointer_cast<ServiceInternal>(service);

    if(serviceInternal != nullptr)
    {
        std::lock_guard lock(_mServices);

        serviceInternal->setParent(this);

        _services.emplace(serviceInternal->getID(), serviceInternal);
    }
}

void AccessoryInternal::removeService(uint64_t iid)
{
    std::lock_guard lock(_mServices);
    if(const auto& it = _services.find(iid); it != _services.end())
    {
        it->second->setParent(nullptr);
        _services.erase(it);
    }
}

void AccessoryInternal::setID(uint64_t id)
{
    std::lock_guard lock(_mID);
    _id = id;
}