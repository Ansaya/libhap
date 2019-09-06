#include <server/http/EventResponse.h>

using namespace hap::server::http;

EventResponse::EventResponse()
    : Response("EVENT/1.0")
{
}