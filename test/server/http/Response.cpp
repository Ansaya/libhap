#include <catch2/catch.hpp>

#include <server/http/Response.h>

using namespace hap::server::http;

TEST_CASE("Response constructor", "[Response]")
{
    Response resp(HTTPStatus::NO_CONTENT);

    REQUIRE(resp.getContent().empty());
    REQUIRE(resp.getStatus() == HTTPStatus::NO_CONTENT);
    REQUIRE(resp.getText() == "HTTP/1.1 204\r\n\r\n");

    Response full_resp(HTTPStatus::SUCCESS, "application/hap+json", "{\"characteristics\":[{\"aid\":1,\"iid\":3,\"value\":5}]}");
    
    REQUIRE(full_resp.getStatus() == HTTPStatus::SUCCESS);
    REQUIRE(full_resp.getContent().size() == 49);
    REQUIRE(full_resp.getHeader("Content-Type") == "application/hap+json");
    REQUIRE(std::strtoull(full_resp.getHeader("Content-Length").c_str(), NULL, 10) == full_resp.getContent().size());

    REQUIRE(full_resp.getText() == "HTTP/1.1 200 OK\r\nContent-Length: 49\r\nContent-Type: application/hap+json\r\n\r\n{\"characteristics\":[{\"aid\":1,\"iid\":3,\"value\":5}]}");
}

TEST_CASE("Response getter/setters", "[Response]")
{
    Response resp(HTTPStatus::SUCCESS, "application/json", "{\"characteristics\":[{\"aid\":1,\"iid\":3,\"value\":5}]}");

    REQUIRE(resp.getHeader("Content-Type") == "application/json");
    REQUIRE(std::strtoull(resp.getHeader("Content-Length").c_str(), NULL, 10) == 49);
    REQUIRE(resp.getContent().size() == 49);

    resp.setHeader("Content-Type", "application/hap+json");

    REQUIRE(resp.getHeader("Content-Type") == "application/hap+json");

    resp.removeHeader("Content-Type");

    REQUIRE(resp.getHeader("Content-Type").empty());

    resp.setContent("");
    REQUIRE(resp.getHeader("Content-Length") == "");
    REQUIRE(resp.getContent().empty());
}