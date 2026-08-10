#pragma once

#include <airece/semantic/control_view.hpp>
#include <airece/semantic/variable_view.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include <xair/xair_binary.h>
}

namespace airece {

enum class SemanticStatementKind {
    call,
    branch,
    return_value,
    memory_read,
    memory_write,
    global_reference,
    string_reference,
    constant,
    import_reference,
    indirect_target,
    effect,
    unresolved,
    trap,
    fault
};

struct SemanticEvidence {
    std::string stable_id;
    std::uint64_t begin{};
    std::uint64_t end{};
    xair_cfg_node_id node{XAIR_CFG_INVALID_ID};
    xair_block_id block{XAIR_INVALID_ID};
    std::vector<xair_op_id> operations;
    std::vector<xair_cfg_edge_id> edges;
    xair_confidence confidence{XAIR_CONFIDENCE_UNKNOWN};
    bool synthetic{};
};

struct SemanticStatement {
    std::string stable_id;
    SemanticStatementKind kind{SemanticStatementKind::unresolved};
    std::string text;
    std::string semantic_id;
    std::uint64_t address{};
    xair_cfg_node_id node{XAIR_CFG_INVALID_ID};
    xair_block_id block{XAIR_INVALID_ID};
    std::vector<xair_op_id> operations;
    std::vector<xair_value_id> values;
    std::string evidence_id;
    std::string api_model;
    std::vector<std::string> api_arguments;
    std::string return_role;
    std::string constant_summary;
    std::string handle_relationship;
    std::string effect_summary;
    std::string taint_role;
    bool no_return{};
    xair_confidence confidence{XAIR_CONFIDENCE_UNKNOWN};
    bool synthetic{};
};

struct SemanticCoverage {
    std::size_t exact_blocks{};
    std::size_t partial_blocks{};
    std::size_t opaque_blocks{};
    std::size_t exact_instructions{};
    std::size_t nonexact_instructions{};
    std::size_t total_instructions{};
    std::size_t unresolved_operations{};
    std::vector<std::pair<std::string, std::size_t>> nonexact_mnemonics;
    std::uint32_t exact_percent{};
    std::uint32_t exact_instruction_percent{};
};

struct OmittedSemanticItems {
    std::size_t calls{};
    std::size_t branches{};
    std::size_t statements{};
    std::size_t evidence{};
    std::size_t regions{};
    std::size_t transfers{};

    [[nodiscard]] bool any() const noexcept {
        return calls != 0 || branches != 0 || statements != 0 || evidence != 0 ||
            regions != 0 || transfers != 0;
    }
};

struct CompactOptions {
    std::size_t max_bytes{4'096};
    std::size_t max_statements{128};
    std::size_t max_expression_depth{6};
    std::size_t max_calls{32};
    std::size_t max_evidence{64};
    std::size_t call_offset{};
    std::size_t max_regions{128};
    std::size_t max_transfers{512};

    [[nodiscard]] bool operator==(const CompactOptions&) const = default;
};

struct CompactFunctionDescriptor {
    xair_function_id id{XAIR_CFG_INVALID_ID};
    std::string name;
    std::uint64_t entry{};
    std::uint64_t range_start{};
    std::uint64_t range_end{};
    xair_cfg_semantic_coverage coverage{XAIR_CFG_SEMANTICS_OPAQUE};
    bool session_complete{};
};

struct CompactFunctionView {
    xair_status status{XAIR_OK};
    CompactFunctionDescriptor function;
    std::vector<PresentationVariable> parameters;
    std::vector<PresentationVariable> returns;
    std::vector<SemanticStatement> statements;
    std::vector<SemanticEvidence> evidence;
    ControlView control;
    SemanticCoverage coverage;
    OmittedSemanticItems omitted;
    std::size_t total_calls{};
    std::size_t total_branches{};
    bool complete{};
    bool truncated{};
    std::string taint_status{"not-requested"};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == XAIR_OK;
    }
};

class CompactRecovery final {
public:
    CompactRecovery(
        const xair_cfg& cfg,
        const xair_module& module,
        const xair_binary_view& binary);
    ~CompactRecovery();
    CompactRecovery(const CompactRecovery&) = delete;
    CompactRecovery& operator=(const CompactRecovery&) = delete;
    CompactRecovery(CompactRecovery&&) noexcept;
    CompactRecovery& operator=(CompactRecovery&&) noexcept;

    [[nodiscard]] CompactFunctionView build(
        const CompactFunctionDescriptor& function,
        const VariableView& variables,
        const CompactOptions& options = {}) const;
    [[nodiscard]] ControlView control_view(
        xair_function_id function,
        const ControlOptions& options = {}) const;
    [[nodiscard]] std::size_t cache_size() const noexcept;
    [[nodiscard]] std::size_t control_cache_size() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] const char* semantic_statement_kind_name(
    SemanticStatementKind kind) noexcept;

} // namespace airece
