#include <catch2/catch.hpp>

#include <server/http/Request.h>

using namespace hap::server::http;

TEST_CASE("HTTP request constructor and parsing", "[Request]")
{
    std::string http_request = 
"PUT /characteristics?id=2.4&test=ciao HTTP/1.1\r\n\
Content-Length: 52\r\n\
Content-Type: application/hap+json\r\n\
Host: lights.local:12345\r\n\r\n\
{\"characteristics\":[{\"aid\":2,\"iid\":8,\"value\":true}]}";

    Request request(http_request.data(), http_request.size());

    REQUIRE(request.getProtocol() == "HTTP/1.1");
    REQUIRE(request.getMethod() == HTTPMethod::PUT);
    REQUIRE(request.getUri() == "/characteristics?id=2.4&test=ciao");
    REQUIRE(request.getPath() == "/characteristics");
    REQUIRE(request.getQueryString().find("id")->second == "2.4");
    REQUIRE(request.getQueryString().find("test")->second == "ciao");
    REQUIRE(request.getHeaders().find("Host")->second == "lights.local:12345");
    REQUIRE(request.getHeaders().find("Content-Type")->second == "application/hap+json");

    std::vector<char> content = request.getContent();

    REQUIRE(content.size() == 52);

    REQUIRE(request.getText() == http_request);
}