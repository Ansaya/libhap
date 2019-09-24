#include <server/http/Response.h>

using namespace hap::server::http;

static constexpr const char http_protocol[] = "HTTP/1.1";
static constexpr const char http_header_content_type[] = "Content-Type";
static constexpr const char http_header_content_length[] = "Content-Length";

Response::Response()
    : _protocol(http_protocol)
{
}

Response::Response(HTTPStatus status)
    : _protocol(http_protocol), _status(status)
{
}

Response::Response(
    HTTPStatus status, 
    const std::string& content_type, 
    const std::string& content)
    : _protocol(http_protocol), _status(status), _content(content)
{
    if(!content.empty() && !content_type.empty())
    {
        _headers.emplace(http_header_content_type, content_type);
        _headers.emplace(http_header_content_length, std::to_string(content.size()));
    }
}

Response::Response(const std::string& protocol)
    : _protocol(protocol)
{
}

Response::~Response()
{
}

void Response::setStatus(HTTPStatus code)
{
    _status = code;
}

HTTPStatus Response::getStatus() const
{
    return _status;
}

std::string Response::getHeader(const std::string& key) const
{
    if(const auto& it = _headers.find(key); it != _headers.end())
    {
        return it->second;
    }

    return std::string("");
}
        
void Response::setHeader(const std::string& key, const std::string& value)
{
    // Avoid empty headers
    if(key.empty())
    {
        return;
    }

    if(const auto& it = _headers.find(key); it != _headers.end())
    {
        it->second = value;
    }
    else
    {
        _headers.emplace(key, value);
    }
}

void Response::removeHeader(const std::string& key)
{
    _headers.erase(key);
}

void Response::setContent(const std::string& content)
{
    _content = content;

    size_t content_size = _content.size();

    // Update Content-Length header
    if(const auto& it = _headers.find(http_header_content_length); it != _headers.end())
    {
        if(content_size)
        {
            it->second = std::to_string(content_size);
        }
        else
        {
            _headers.erase(it);
        }
    }
    else if(content_size)
    {
        _headers.emplace(http_header_content_length, std::to_string(content_size));
    }
}

const std::string& Response::getContent() const
{
    return _content;
}

std::string Response::getText() const
{
    // First line with response code
    std::string text(_protocol);
    text += " " + std::to_string(_status);
    if(_status == HTTPStatus::SUCCESS) { text += " OK"; }
    text += "\r\n";
    
    // HTTP headers
    for(const auto& header : _headers)
    {
        text += header.first;
        
        if(!header.second.empty())
        {
            text += ": " + header.second;
        }
        text += "\r\n";
    }
    text += "\r\n";
    
    // Content length and content or empty line if no content
    if(!_content.empty())
    {
        text += _content;
    }
    
    return text;
}