#include <server/http/Response.h>

using namespace hap::server::http;

Response::Response()
{
}

Response::Response(HTTPStatus status_code, 
    const std::string& content_type, 
    const char* content, 
    size_t content_length)
{
    // Compose HTTP response text
    _text += "HTTP/1.1 " + std::to_string(status_code);
    if(status_code == HTTPStatus::SUCCESS) { _text += " OK"; }
    _text += "\r\nContent-Type: " + content_type;
    _text += "\r\nContent-Length: " + std::to_string(content_length);
    _text += "\r\n\r\n";
    _text.append(content, content_length);
}

Response::~Response()
{
}

const std::string& Response::getText() const
{
    return _text;
}