#include <airece/version.hpp>

#include <string>

int main() {
    const std::string version = airece::version_text();
    const std::string required[] = {
        "AIRECE 0.11.0",
        "benchmark-freeze v0.11.0-benchmark-rc2",
        "xair 0.3.0",
        "xair_cfg 0.2.0",
        "xair_sym 0.6.0",
        "api-models 2.0.0 (compiled-in)",
        "directed-flow airece.flow.v1 (default-function-depth=3)",
        "Zydis 5.0.0",
        "Z3 5.0.0",
        "decoder zydis (sole production path)",
    };
    for (const std::string& item : required) {
        if (version.find(item) == std::string::npos) return 1;
    }
    return 0;
}
