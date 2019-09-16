#ifndef HAP_HASJSON
#define HAP_HASJSON

#include <rapidjson/document.h>
#include <string>

namespace hap {

    class HasJSON
    {
    public:
        virtual rapidjson::Document to_json(rapidjson::Document::AllocatorType* allocator = nullptr) const = 0;
    };

    extern std::string to_json_string(rapidjson::Document& json_doc, bool prettyPrint = false);

}

#endif