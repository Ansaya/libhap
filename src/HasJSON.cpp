#include <HasJSON.h>

#include <memory>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/writer.h>
#include <sstream>


std::string hap::to_json_string(rapidjson::Document& json_doc, bool prettyPrint)
{
    std::ostringstream json_str;
    rapidjson::OStreamWrapper osw(json_str);

    auto writer = prettyPrint ? 
        std::make_unique<rapidjson::Writer<rapidjson::OStreamWrapper>>(osw)
        : std::make_unique<rapidjson::PrettyWriter<rapidjson::OStreamWrapper>>(osw);

    json_doc.Accept(*writer);

    return json_str.str();
}