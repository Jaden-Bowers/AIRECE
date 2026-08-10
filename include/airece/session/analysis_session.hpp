#pragma once

#include <airece/semantic/compact_view.hpp>
#include <airece/semantic/expression_view.hpp>
#include <airece/semantic/variable_view.hpp>
#include <airece/session/decode_cache.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
#include <xair_cfg/xair_cfg.h>
#include <xair_sym/xair_sym.h>
}

namespace airece {

enum class AnalysisProfile {
    fast,
    balanced,
    exhaustive
};

struct AnalysisOptions {
    AnalysisProfile profile{AnalysisProfile::balanced};
    std::uint64_t max_input_bytes{};
    std::size_t max_segments{};
    std::size_t max_symbols{};
    std::size_t max_functions{};
    std::size_t max_blocks{};
    std::size_t max_edges{};
    std::size_t max_ir_values{};
    std::size_t max_memory_bytes{};
    std::uint64_t max_wall_time_ms{};
    std::uint32_t max_block_bytes{};
    std::uint32_t max_roots{};
    std::uint32_t max_indirect_candidates_per_edge{};
    std::uint32_t max_indirect_candidate_edges{};
    bool build_ir{true};
    bool expand_indirects{true};
    bool analyze_indirects{true};
    const xair_cancel_token* cancellation{};
    xair_progress_callback progress{};
    void* progress_user{};
};

struct SessionDiagnostic {
    xair_status status{XAIR_OK};
    xair_stage stage{XAIR_STAGE_NONE};
    std::uint64_t address{};
    std::string message;
};

struct FunctionInfo {
    xair_function_id id{XAIR_CFG_INVALID_ID};
    std::uint64_t entry{};
    std::uint64_t range_start{};
    std::uint64_t range_end{};
    std::string name;
    xair_cfg_semantic_coverage semantic_coverage{XAIR_CFG_SEMANTICS_OPAQUE};
    std::uint32_t flags{};
    std::size_t node_count{};
    std::size_t call_edge_count{};
};

struct CallSiteInfo {
    std::size_t index{};
    std::uint64_t address{};
    std::uint64_t target{};
    xair_function_id owner{XAIR_CFG_INVALID_ID};
    std::string import_module;
    std::string import_name;
    std::uint32_t import_ordinal{};
    std::uint32_t flags{};
};

struct SessionCompleteness {
    xair_analysis_state loader_state{XAIR_ANALYSIS_FAILED};
    xair_analysis_state cfg_state{XAIR_ANALYSIS_FAILED};
    xair_status reason{XAIR_ERR_INTERNAL};
    bool complete{};
    std::uint64_t nodes_total{};
    std::uint64_t nodes_partial{};
    std::uint64_t nodes_opaque{};
    std::uint64_t functions_total{};
    std::uint64_t functions_partial{};
    std::uint64_t unresolved_indirects{};
    std::uint64_t skipped_items{};
};

class AnalysisSession;
struct SessionOpenResult;

class AnalysisSession final {
public:
    static SessionOpenResult open(
        const std::filesystem::path& path,
        const AnalysisOptions& options = {});
    static SessionOpenResult open_bytes(
        std::span<const std::byte> bytes,
        std::string source_name,
        const AnalysisOptions& options = {});

    ~AnalysisSession();
    AnalysisSession(const AnalysisSession&) = delete;
    AnalysisSession& operator=(const AnalysisSession&) = delete;
    AnalysisSession(AnalysisSession&&) = delete;
    AnalysisSession& operator=(AnalysisSession&&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept;
    [[nodiscard]] const AnalysisOptions& options() const noexcept;
    [[nodiscard]] const xair_binary_view& binary() const noexcept;
    [[nodiscard]] const xair_cfg& cfg() const noexcept;
    [[nodiscard]] const xair_module* module() const noexcept;
    [[nodiscard]] const xair_cfg_stats& cfg_stats() const noexcept;
    [[nodiscard]] const SessionCompleteness& completeness() const noexcept;

    [[nodiscard]] const std::vector<FunctionInfo>& functions() const noexcept;
    [[nodiscard]] const std::vector<CallSiteInfo>& call_sites() const noexcept;
    [[nodiscard]] const FunctionInfo* function_by_address(std::uint64_t address) const;
    [[nodiscard]] const FunctionInfo* function_by_name(std::string_view name) const;
    [[nodiscard]] const FunctionInfo* function_by_call_site(std::uint64_t address) const;
    [[nodiscard]] const FunctionInfo* function_by_import(
        std::string_view module, std::string_view name) const;
    [[nodiscard]] const FunctionInfo* function_by_import(
        std::string_view module, std::uint32_t ordinal) const;
    [[nodiscard]] std::vector<const FunctionInfo*> functions_referencing_import(
        std::string_view module, std::string_view name) const;

    [[nodiscard]] DecodeCache& decode_cache() noexcept;
    [[nodiscard]] const DecodeCache& decode_cache() const noexcept;

    [[nodiscard]] SemanticExpression expression_view(
        xair_value_id value,
        const ExpressionOptions& options = {}) const;
    [[nodiscard]] std::size_t cached_expression_count() const noexcept;

    [[nodiscard]] VariableView variable_view(
        xair_function_id function,
        const VariableOptions& options = {}) const;
    [[nodiscard]] std::size_t cached_variable_view_count() const noexcept;

    [[nodiscard]] ControlView control_view(
        xair_function_id function,
        const ControlOptions& options = {}) const;
    [[nodiscard]] CompactFunctionView compact_view(
        xair_function_id function,
        const CompactOptions& options = {}) const;
    [[nodiscard]] std::size_t cached_control_view_count() const noexcept;
    [[nodiscard]] std::size_t cached_compact_view_count() const noexcept;

    [[nodiscard]] bool symbolic_context_initialized() const noexcept;
    [[nodiscard]] bool solver_initialized() const noexcept;
    xair_sym_context* symbolic_context(SessionDiagnostic* diagnostic = nullptr);

private:
    AnalysisSession(std::filesystem::path path, AnalysisOptions options);
    xair_status build_cfg(SessionDiagnostic& diagnostic);
    xair_status build_inventory(SessionDiagnostic& diagnostic);
    std::uint64_t recover_call_site_address(const xair_cfg_call_site& site);

    std::filesystem::path path_;
    AnalysisOptions options_;
    xair_binary_view binary_{};
    bool binary_loaded_{};
    xair_cfg* cfg_{};
    const xair_module* module_{};
    xair_cfg_stats cfg_stats_{};
    xair_analysis_result loader_result_{};
    xair_analysis_result cfg_result_{};
    SessionCompleteness completeness_{};
    std::unique_ptr<DecodeCache> decode_cache_;
    std::unique_ptr<ExpressionRecovery> expression_recovery_;
    std::unique_ptr<VariableRecovery> variable_recovery_;
    std::unique_ptr<CompactRecovery> compact_recovery_;
    std::vector<FunctionInfo> functions_;
    std::vector<CallSiteInfo> call_sites_;
    xair_sym_context* symbolic_context_{};
    xair_cancel_token* owned_cancellation_{};

    struct Indexes;
    std::unique_ptr<Indexes> indexes_;
};

struct SessionOpenResult {
    std::unique_ptr<AnalysisSession> session;
    std::unique_ptr<AnalysisSession> partial_session;
    SessionDiagnostic diagnostic;

    [[nodiscard]] explicit operator bool() const noexcept {
        return session != nullptr;
    }
};

[[nodiscard]] const char* semantic_coverage_name(
    xair_cfg_semantic_coverage coverage) noexcept;

} // namespace airece
