#pragma once

#include <airece/semantic/compact_view.hpp>
#include <airece/semantic/enrichment.hpp>

#include <string>

namespace airece {

inline constexpr const char* semantic_json_schema = "airece.semantic.v1";

[[nodiscard]] std::string render_semantic_json(
    const CompactFunctionView& view,
    const EnrichmentResult* enrichment = nullptr,
    std::size_t max_bytes = 0);
[[nodiscard]] std::string render_function_ir(
    const xair_cfg& cfg,
    const xair_module& module,
    xair_function_id function);

} // namespace airece
