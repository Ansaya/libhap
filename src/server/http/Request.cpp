#include <server/http/Request.h>

#include <cstring>

#define HTTP_REQUEST_NEWLINE                "\r\n"
#define HTTP_HEADER_CONTENT_LENGTH          "Content-Length"

using namespace hap::server::http;

Request::Request(const void* buffer, size_t buffer_length)
    : _method(HTTPMethod::INVALID)
{
    const char* c_buffer = (const char*)buffer;

    // Read HTTP request method
    size_t method_length = strchr(c_buffer, ' ') - c_buffer;
    if(method_length == 3)
    {
        if(!strncmp("GET", c_buffer, 3))
        {
            _method = HTTPMethod::GET;
        }
        else if(!strncmp("PUT", c_buffer, 3))
        {
            _method = HTTPMethod::PUT;
        }
    }
    else if(method_length == 4)
    {
        if(!strncmp("POST", c_buffer, 4))
        {
            _method = HTTPMethod::POST;
        }
    }
    else
    {
        // ERROR
        return;
    }
    
    c_buffer += method_length + 1;

    // Read HTTP request URI
    size_t uri_length = strchr(c_buffer, ' ') - c_buffer;
    if(uri_length != 0)
    {
        _uri = std::string(c_buffer, uri_length);
    }
    else
    {
        // ERROR
        return;
    }
    c_buffer = strstr(c_buffer, HTTP_REQUEST_NEWLINE) + sizeof(HTTP_REQUEST_NEWLINE);

    // Parse HTTP request headers
    const char* semiColon;
    const char* newLine;
    while ((semiColon = strchr(c_buffer, ':')))
    {
        // Store header name (string before ':')
        std::string headerName(c_buffer, semiColon - c_buffer);

        // Search for the end of the line
        c_buffer = semiColon + 2;
        newLine = strstr(c_buffer, HTTP_REQUEST_NEWLINE);

        // Store header value (string after ": " towards the end)
        std::string headerValue(c_buffer, newLine - c_buffer);

        // Store name/value pair
        _headers.emplace(headerName, headerValue);

        // Pass to next line
        c_buffer = newLine + sizeof(HTTP_REQUEST_NEWLINE);
    }

    // Skip empty line before HTTP request content
    c_buffer += sizeof(HTTP_REQUEST_NEWLINE);

    // Read HTTP request content length
    auto it = _headers.find(HTTP_HEADER_CONTENT_LENGTH);
    if(it != _headers.end())
    {
        size_t content_length = strtoull(it->second.data(), NULL, 10);

        // Store HTTP request content if any
        if(content_length != 0)
        {
            _content.insert(_content.begin(), c_buffer, c_buffer + content_length);
        }
    }
    else
    {
        // ERROR
        return;
    }
}

Request::~Request()
{
}

HTTPMethod Request::getMethod() const
{
    return _method;
}

const std::string& Request::getUri() const
{
    return _uri;
}

const std::map<std::string, std::string>& Request::getHeaders() const
{
    return _headers;
}

const std::vector<char>& Request::getContent() const
{
    return _content;
}