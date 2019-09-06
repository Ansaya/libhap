#include <server/http/HTTPMethod.h>

#include <algorithm>
#include <array>
#include <cstring>

using namespace hap::server::http;

static constexpr std::array<std::pair<const char*, HTTPMethod>, 4> strToMethod = {
    std::make_pair("GET", HTTPMethod::GET),
    std::make_pair("POST", HTTPMethod::POST),
    std::make_pair("PUT", HTTPMethod::PUT),
    std::make_pair("DELETE", HTTPMethod::DELETE)
};

HTTPMethod hap::server::http::to_method(const std::string& http_method)
{
    auto it = std::find_if(strToMethod.begin(), strToMethod.end(), 
        [&](const std::pair<const char*, HTTPMethod> stm)
        { return strcasecmp(http_method.c_str(), stm.first); });

    if(it != strToMethod.end())
    {
        return it->second;
    }

    return HTTPMethod::INVALID;
}

std::string hap::server::http::to_method_string(HTTPMethod http_method)
{
    auto it = std::find_if(strToMethod.begin(), strToMethod.end(), 
        [&](const std::pair<const char*, HTTPMethod> stm)
        { return http_method == stm.second; });

    if(it != strToMethod.end())
    {
        return it->first;
    }

    return std::string("");
}