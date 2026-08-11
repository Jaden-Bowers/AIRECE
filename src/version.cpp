#include <airece/version.hpp>
#include <airece/semantic/api_model.hpp>

#include "airece_build_config.hpp"

extern "C" {
#include <xair/xair.h>
#include <xair/xair_frontend.h>
}

#include <sstream>

namespace airece {

std::string version_text() {
    std::ostringstream output;
    output << "AIRECE " << AIRECE_VERSION << '\n'
           << "benchmark-freeze " << AIRECE_BENCHMARK_FREEZE << '\n'
           << "xair " << xair_ir_version_string() << " ("
           << AIRECE_XAIR_REVISION << ")\n"
           << "xair_cfg " << AIRECE_XAIR_CFG_VERSION << " ("
           << AIRECE_XAIR_CFG_REVISION << ")\n"
           << "xair_sym " << AIRECE_XAIR_SYM_VERSION << " ("
           << AIRECE_XAIR_SYM_REVISION << ")\n"
           << "api-models " << api_model_set_version << " (compiled-in)\n"
           << "directed-flow airece.flow.v1 (default-function-depth=3)\n"
           << "Zydis " << AIRECE_ZYDIS_VERSION << " (vendored)\n"
           << "Z3 " << AIRECE_Z3_VERSION << " ("
           << AIRECE_Z3_REVISION << ", lazy)\n"
           << "decoder " << xair_x86_decoder_name(xair_x86_default_decoder())
           << " (sole production path)\n"
           << "build " << AIRECE_BUILD_CONFIG
           << ", static-runtime=" << AIRECE_STATIC_RUNTIME << '\n';
    return output.str();
}

} // namespace airece
