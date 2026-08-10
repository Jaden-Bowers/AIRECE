#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

extern "C" {
#include <xair/xair.h>
#include <xair_sym/xair_sym.h>
}

namespace airece {

inline constexpr std::string_view api_model_set_version = "2.0.0";

enum class ApiTaintRole {
    none,
    source,
    sink,
    source_and_sink
};

struct ApiArgumentModel {
    std::string_view name;
    std::string_view role;
    bool reads{};
    bool writes{};
};

struct ApiHandleRelationship {
    std::string_view produced;
    std::string_view consumes;
};

struct ApiModel {
    std::string_view module;
    std::string_view name;
    std::uint32_t ordinal{};
    std::span<const ApiArgumentModel> arguments;
    std::string_view return_role;
    std::uint32_t effects{};
    ApiTaintRole taint{ApiTaintRole::none};
    xair_sym_taint_category taint_category{XAIR_SYM_TAINT_CATEGORY_UNKNOWN};
    std::string_view constants;
    ApiHandleRelationship handles;
    xair_sym_model_info symbolic{};
    bool no_return{};
};

[[nodiscard]] const ApiModel* find_api_model(
    std::string_view module,
    std::string_view name,
    std::uint32_t ordinal = 0) noexcept;
[[nodiscard]] std::span<const ApiModel> api_models() noexcept;
[[nodiscard]] const char* api_taint_role_name(ApiTaintRole role) noexcept;
[[nodiscard]] std::string describe_api_effects(const ApiModel& model);

// Registers the presentation database through xair_sym's canonical identity
// registry. Unknown kinds deliberately retain xair_sym's ordinary-call fallback.
xair_sym_status register_api_models(xair_sym_environment* environment) noexcept;

} // namespace airece
