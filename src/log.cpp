#include <log.h>

#include <spdlog/sinks/stdout_color_sinks.h>

using namespace hap;

std::shared_ptr<spdlog::logger> hap::logger = spdlog::stdout_color_mt("hap");