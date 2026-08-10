#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

extern "C" {
#include <xair/xair.h>
}

namespace airece {

struct SourceSpan {
    std::uint64_t begin{};
    std::uint64_t end{};
    xair_confidence confidence{XAIR_CONFIDENCE_UNKNOWN};
    std::size_t record_count{};
    bool synthetic{};

    [[nodiscard]] bool has_machine_address() const noexcept {
        return begin != 0 || end != 0;
    }
};

enum class ExpressionDisplayKind {
    leaf,
    constant,
    unary,
    binary,
    comparison,
    address,
    load,
    store,
    select,
    call_result,
    flag,
    intrinsic,
    opaque,
    unknown
};

struct ExpressionOptions {
    std::size_t max_depth{8};
    std::size_t max_nodes{64};
    std::size_t max_tokens{256};
    std::size_t max_characters{4096};
    bool inline_single_use{true};
    bool inline_loads{true};

    bool operator==(const ExpressionOptions&) const = default;
};

struct SemanticExpression {
    xair_status status{XAIR_OK};
    xair_value_id value{XAIR_INVALID_ID};
    xair_op_id root_op{XAIR_INVALID_ID};
    xair_type type{XAIR_TYPE_INVALID, 0, 0};
    SourceSpan source;
    ExpressionDisplayKind display{ExpressionDisplayKind::leaf};
    std::string text;
    std::vector<xair_op_id> operations;
    std::vector<xair_value_id> referenced_values;
    bool truncated{};
    std::size_t omitted_nodes{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == XAIR_OK && value != XAIR_INVALID_ID;
    }
};

class ExpressionRecovery final {
public:
    explicit ExpressionRecovery(const xair_module& module);
    ~ExpressionRecovery();

    ExpressionRecovery(const ExpressionRecovery&) = delete;
    ExpressionRecovery& operator=(const ExpressionRecovery&) = delete;
    ExpressionRecovery(ExpressionRecovery&&) noexcept;
    ExpressionRecovery& operator=(ExpressionRecovery&&) noexcept;

    [[nodiscard]] SemanticExpression build(
        xair_value_id value,
        const ExpressionOptions& options = {}) const;
    [[nodiscard]] std::size_t cache_size() const noexcept;
    void clear_cache() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] const char* expression_display_kind_name(
    ExpressionDisplayKind kind) noexcept;

} // namespace airece
