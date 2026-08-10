#pragma once

#include <airece/session/analysis_session.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace airece {

enum class FlowMode {
    taint,
    taint_symbolic,
    symbolic
};

enum class FlowPointKind {
    register_value,
    buffer,
    memory,
    xair_value,
    function_argument,
    call_argument,
    call_result,
    reach,
    memory_write
};

enum class FlowWhen {
    before,
    after
};

struct FlowPointSelector {
    std::string raw;
    std::string name;
    FlowPointKind kind{FlowPointKind::xair_value};
    FlowWhen when{FlowWhen::before};
    std::string register_name;
    std::uint64_t address{};
    std::uint64_t memory_address{};
    std::size_t length{};
    std::size_t index{};
    xair_value_id value{XAIR_INVALID_ID};
};

struct FlowOptions {
    FlowMode mode{FlowMode::taint};
    std::size_t function_depth{3};
    std::size_t max_states{4096};
    std::size_t max_queries{128};
    std::size_t max_paths{16};
    std::size_t max_taint_bytes{4096};
    std::size_t max_symbolic_bytes{32};
    std::uint64_t max_time_ms{5000};
    const xair_cancel_token* cancellation{};
};

enum class FlowCompletion {
    complete,
    limited,
    timeout,
    canceled,
    unknown,
    failed
};

enum class FlowVerdict {
    may_flow,
    feasible_flow,
    infeasible,
    no_flow,
    unknown
};

struct ResolvedFlowPoint {
    FlowPointSelector selector;
    xair_function_id function{XAIR_CFG_INVALID_FUNCTION};
    xair_cfg_node_id node{XAIR_CFG_INVALID_ID};
    xair_op_id operation{XAIR_INVALID_ID};
    std::vector<xair_value_id> values;
    xair_confidence confidence{XAIR_CONFIDENCE_UNKNOWN};
    std::string message;
};

struct FlowInfluence {
    std::size_t source{};
    std::size_t target{};
    bool byte_range{};
    std::size_t offset_begin{};
    std::size_t offset_end{};
    std::size_t call_depth{};
    std::vector<std::string> transforms;
};

struct FlowPathStep {
    xair_cfg_node_id node{XAIR_CFG_INVALID_ID};
    std::uint64_t address{};
    std::string edge;
    std::string condition;
};

struct FlowWitness {
    std::size_t source{};
    bool byte_values{};
    std::uint64_t scalar{};
    std::size_t offset_begin{};
    std::vector<std::uint8_t> bytes;
};

struct DirectedFlowResult {
    xair_status status{XAIR_OK};
    FlowMode mode{FlowMode::taint};
    FlowCompletion completion{FlowCompletion::complete};
    FlowVerdict verdict{FlowVerdict::unknown};
    std::vector<ResolvedFlowPoint> sources;
    std::vector<ResolvedFlowPoint> targets;
    std::vector<FlowInfluence> influences;
    std::vector<FlowPathStep> path;
    std::vector<std::string> constraints;
    std::vector<FlowWitness> witnesses;
    std::size_t states{};
    std::size_t queries{};
    std::size_t paths{};
    std::size_t function_depth{3};
    std::size_t deepest_call{};
    bool solver_initialized{};
    bool source_constrained{};
    std::string diagnostic;
};

[[nodiscard]] bool parse_flow_point(
    std::string_view text,
    bool target,
    FlowPointSelector& selector,
    std::string& diagnostic);

[[nodiscard]] DirectedFlowResult directed_flow(
    AnalysisSession& session,
    const std::vector<FlowPointSelector>& sources,
    const std::vector<FlowPointSelector>& targets,
    const FlowOptions& options = {});

[[nodiscard]] std::string render_flow_text(const DirectedFlowResult& result);
[[nodiscard]] std::string render_flow_json(const DirectedFlowResult& result);

[[nodiscard]] const char* flow_mode_name(FlowMode mode) noexcept;
[[nodiscard]] const char* flow_point_kind_name(FlowPointKind kind) noexcept;
[[nodiscard]] const char* flow_completion_name(FlowCompletion completion) noexcept;
[[nodiscard]] const char* flow_verdict_name(FlowVerdict verdict) noexcept;

} // namespace airece
