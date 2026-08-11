#include <airece/version.hpp>

#include <cassert>
#include <string>

int main() {
    const std::string version = airece::version_text();
    assert(version.find("AIRECE 0.10.0") != std::string::npos);
    assert(version.find("benchmark-freeze v0.10.0-benchmark-rc1") !=
        std::string::npos);
    assert(version.find("xair 0.3.0") != std::string::npos);
    assert(version.find("xair_cfg 0.2.0") != std::string::npos);
    assert(version.find("xair_sym 0.6.0") != std::string::npos);
    assert(version.find("api-models 2.0.0 (compiled-in)") != std::string::npos);
    assert(version.find("directed-flow airece.flow.v1 (default-function-depth=3)") !=
        std::string::npos);
    assert(version.find("Zydis 5.0.0") != std::string::npos);
    assert(version.find("Z3 5.0.0") != std::string::npos);
    assert(version.find("decoder zydis (sole production path)") != std::string::npos);
    return 0;
}
