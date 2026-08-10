#pragma once

#include <airece/semantic/compact_view.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include <xair_sym/xair_sym.h>
}

namespace airece {

struct EnrichmentOptions {
    bool symbolic{};
    bool taint{};
    std::size_t max_queries{16};
    std::size_t max_states{256};
    std::uint64_t max_time_ms{1'000};
    const xair_cancel_token* cancellation{};
};

enum class EnrichmentCompletion {
    complete,
    limited,
    timeout,
    canceled,
    unknown,
    failed
};

struct SymbolicFinding {
    std::string question;
    std::string answer;
    std::string evidence_id;
    xair_value_id value{XAIR_INVALID_ID};
    xair_sym_status status{XAIR_SYM_OK};
    bool inferred{};
};

struct TaintFinding {
    std::string kind;
    std::string source;
    std::string sink;
    std::string transform;
    std::string guard;
    std::string evidence_id;
    xair_sym_taint_id taint{XAIR_SYM_TAINT_NONE};
};

struct EnrichmentResult {
    EnrichmentCompletion completion{EnrichmentCompletion::complete};
    std::vector<SymbolicFinding> symbolic;
    std::vector<TaintFinding> taint;
    std::size_t queries{};
    std::size_t states{};
    bool solver_initialized{};
};

[[nodiscard]] EnrichmentResult enrich_function(
    const xair_cfg& cfg,
    const xair_module& module,
    const xair_binary_view& binary,
    xair_function_id function,
    xair_sym_context& context,
    const CompactFunctionView& base,
    const EnrichmentOptions& options);
void append_enrichment(CompactFunctionView& base, const EnrichmentResult& enrichment);
[[nodiscard]] const char* enrichment_completion_name(EnrichmentCompletion value) noexcept;

} // namespace airece
