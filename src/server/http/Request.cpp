#include <server/http/Request.h>

#include <cstring>

static constexpr const char* http_request_newline = "\r\n";
static constexpr const char* http_header_content_length = "Content-Length";

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

        size_t path_length = uri_length;
        if(const char* p = strchr(c_buffer, '?'); p != NULL)
        {
            path_length = p - c_buffer;

            const char* query_string_end = c_buffer + uri_length + 1;
            
            const char* key = c_buffer + path_length + 1;
            const char* nextKey;
            const char* nextValue;
            do
            {
                nextKey = strchr(key, '&');
                nextValue = strchr(key, '=');

                if(nextKey != NULL)
                {
                    if(nextValue < nextKey)
                    {
                        _queryString.emplace(
                            std::string(key, nextValue - key), 
                            std::string(nextValue + 1, nextKey - nextValue - 1));
                    }
                    else
                    {
                        _queryString.emplace(
                            std::string(key, nextKey - key),
                            std::string(""));
                    }

                    key = nextKey + 1;
                }
                else
                {
                    if(nextValue != NULL)
                    {
                        _queryString.emplace(
                            std::string(key, nextValue - key), 
                            std::string(nextValue + 1, query_string_end - nextValue - 1));
                    }
                    else
                    {
                        _queryString.emplace(
                            std::string(key, query_string_end - key), 
                            std::string(""));
                    }
                    
                    key = query_string_end;
                }
                
            } while (nextKey < query_string_end);
        }

        _path = std::string(c_buffer, path_length);
    }
    else
    {
        // ERROR
        return;
    }
    c_buffer += uri_length + 1;

    // Read request protocol
    size_t protocol_length = strstr(c_buffer, http_request_newline) - c_buffer;
    _protocol = std::string(c_buffer, protocol_length);
    c_buffer += protocol_length + strlen(http_request_newline);

    // Parse HTTP request headers
    const char* semiColon;
    const char* newLine;
    while ((semiColon = strchr(c_buffer, ':')))
    {
        // Store header name (string before ':')
        std::string headerName(c_buffer, semiColon - c_buffer);

        // Search for the end of the line
        c_buffer = semiColon + 2;
        newLine = strstr(c_buffer, http_request_newline);

        // Store header value (string after ": " towards the end)
        std::string headerValue(c_buffer, newLine - c_buffer);

        // Store name/value pair
        _headers.emplace(headerName, headerValue);

        // Pass to next line
        c_buffer = newLine + strlen(http_request_newline);
    }

    // Skip empty line before HTTP request content
    c_buffer += strlen(http_request_newline);

    // Read HTTP request content length
    auto it = _headers.find(http_header_content_length);
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

const std::string& Request::getPath() const
{
    return _path;
}

const std::map<std::string,std::string>& Request::getQueryString() const
{
    return _queryString;
}

const std::map<std::string, std::string>& Request::getHeaders() const
{
    return _headers;
}

const std::vector<char>& Request::getContent() const
{
    return _content;
}

std::string Request::getText() const
{
    std::string text = to_method_string(_method);
    text += " " + _uri + " " + _protocol + http_request_newline;

    for(const auto& header : _headers)
    {
        text += header.first + ": " + header.second + http_request_newline;
    }
    text += http_request_newline;

    text.append(_content.begin(), _content.end());
    
    return text;
}