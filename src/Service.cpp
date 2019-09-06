#include <Service.h>

#include <ServiceInternal.h>

using namespace hap;

std::shared_ptr<Service> Service::make_shared(ServiceType type)
{
    return std::make_shared<ServiceInternal>(type);
}

Service::Service(ServiceType type)
    : _type(type)
{
}

Service::~Service()
{
}

ServiceType Service::getType() const
{
    return _type;
}