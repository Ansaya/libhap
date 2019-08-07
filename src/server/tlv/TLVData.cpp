#include <server/tlv/TLVData.h>

using namespace hap::server::tlv;

TLVData::TLVData()
{
}

TLVData::TLVData(const uint8_t* buffer, size_t buffer_length)
{
    // Parse each item until buffer end
    const uint8_t* buffer_end = buffer + buffer_length;
    while (buffer < buffer_end)
    {
        uint8_t type = buffer[0];
        uint8_t size = buffer[1];
        buffer += 2;
        
        auto it = _items.find(type);
        if(it != _items.end())
        {
            it->second.insert(it->second.end(), buffer, buffer + size);
        }
        else
        {
            _items.emplace(type, std::vector<uint8_t>(buffer, buffer + size));
        }
        
        buffer += size;
    }
}

TLVData::TLVData(const std::vector<uint8_t>& buffer)
    : TLVData(buffer.data(), buffer.size())
{
}

TLVData::~TLVData()
{
}

const std::vector<uint8_t>* TLVData::getItem(const uint8_t item_type) const
{
    auto it = _items.find(item_type);
    if(it != _items.end())
    {
        return &(it->second);
    }
    else
    {
        return nullptr;
    }
    
}

void TLVData::setItem(const uint8_t item_type, const std::vector<uint8_t>& item_value)
{
    auto it = _items.find(item_type);
    if(it != _items.end())
    {
        _items[item_type] = item_value;
    }
    else
    {
        _items.emplace(item_type, item_value);
    }
}

void TLVData::setItem(const uint8_t item_type, const uint8_t* value, size_t value_length)
{
    auto it = _items.find(item_type);
    if(it != _items.end())
    {
        _items[item_type].assign(value, value + value_length);
        _items[item_type].resize(value_length);
    }
    else
    {
        _items.emplace(item_type, std::vector<uint8_t>(value, value + value_length));
    }
}

void TLVData::removeItem(const uint8_t item_type)
{
    _items.erase(item_type);
}

std::vector<uint8_t> TLVData::serialize() const
{
    std::vector<uint8_t> buffer;
    for(auto& it : _items)
    {
        auto v_it = it.second.begin();

        // Split TLV items into fragments when necessary
        while ((it.second.end() - v_it) > UINT8_MAX)
        {
            buffer.push_back(it.first);
            buffer.push_back(UINT8_MAX);
            buffer.insert(buffer.end(), v_it, v_it + UINT8_MAX);

            v_it += UINT8_MAX;
        }

        // Add last fragment to the buffer (unique fragment if item wasn't fragmented)
        uint8_t size = it.second.end() - v_it;
        if(size)
        {
            buffer.push_back(it.first);
            buffer.push_back(size);
            buffer.insert(buffer.end(), v_it, it.second.end());
        }
    }

    return buffer;
}