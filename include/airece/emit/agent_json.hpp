#pragma once

#include <airece/semantic/compact_view.hpp>

#include <cstddef>
#include <string>

namespace airece {

class AnalysisSession;
struct FunctionInfo;

inline constexpr const char* agent_json_schema = "airece.agent-function.v1";

[[nodiscard]] std::string render_agent_json(
    const AnalysisSession& session,
    const FunctionInfo& function,
    const CompactFunctionView& semantic,
    std::size_t max_bytes = 4'096);

} // namespace airece
