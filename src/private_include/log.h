#ifndef HAP_INTERNAL_LOG
#define HAP_INTERNAL_LOG

#include <spdlog/spdlog.h>

namespace hap {

    extern std::shared_ptr<spdlog::logger> logger;

}

#endif