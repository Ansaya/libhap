#include <server/http/Response.h>

using namespace hap::server::http;

static constexpr const char http_protocol[] = "HTTP/1.1";

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
        _headers.emplace("Contet-Type", content_type);
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
    auto it = _headers.find(key);
    if(it != _headers.end())
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

    auto it = _headers.find(key);
    if(it != _headers.end())
    {
        it->second = value;
    }
    else
    {
        _headers.emplace(key, value);
    }
}

void Response::setContent(const std::string& content)
{
    _content = content;
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
    
    // Content length and content or empty line if no content
    if(!_content.empty())
    {
        text += "Content-Length: " + std::to_string(_content.length()) + "\r\n";
        text += "\r\n";
        text += _content;
    }
    else
    {
        text += "\r\n";
    }
    
    return text;
}