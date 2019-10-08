#include <server/dns_sd/TXTRecord.h>

#include <cstddef>
#include <dns_sd.h>

using namespace hap::server::dns_sd;

struct hap::server::dns_sd::sd_ctx_t {
    DNSServiceRef dnsService;
    TXTRecordRef txtRecord;
};

TXTRecord::TXTRecord(
    const std::string& name, 
    const std::string& type)
    : _name(name), _type(type),
     _context(new sd_ctx_t())
{
    TXTRecordCreate(&_context->txtRecord, 0, NULL);
}

TXTRecord::~TXTRecord()
{
    TXTRecordDeallocate(&_context->txtRecord);
    DNSServiceRefDeallocate(_context->dnsService);
}

int TXTRecord::updateEntry(uint32_t interface_index, uint16_t port)
{
    DNSServiceRefDeallocate(_context->dnsService);

    int retval = DNSServiceRegister(&_context->dnsService, 0, interface_index, 
        _name.c_str(), _type.c_str(), NULL, NULL, port, 
        TXTRecordGetLength(&_context->txtRecord), 
        TXTRecordGetBytesPtr(&_context->txtRecord), NULL, NULL);

    if(retval != kDNSServiceErr_NoError)
    {
        // TODO: log error
    }

    return retval;
}

void TXTRecord::removeEntry()
{
    DNSServiceRefDeallocate(_context->dnsService);
}

int TXTRecord::setValue(const std::string& key, const std::string& value)
{
    int retval = TXTRecordSetValue(&_context->txtRecord, 
        key.c_str(), value.size(), value.data());

    if(retval != kDNSServiceErr_NoError)
    {
        // TODO: log error
    }

    return retval;
}

int TXTRecord::removeValue(const std::string& key)
{
    DNSServiceErrorType retval = 
        TXTRecordRemoveValue(&_context->txtRecord, key.c_str());

    if(retval != kDNSServiceErr_NoError)
    {
        // TODO: log error
    }

    return retval;
}