#pragma once

#include <airece/semantic/expression_view.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airece {

enum class VariableKind {
    argument,
    return_value,
    stack_slot,
    global,
    call_result,
    buffer,
    repeated_value,
    temporary
};

enum class VariableNameOrigin {
    user,
    debug_symbol,
    import_role,
    semantic_role,
    storage_address,
    deterministic
};

enum class PresentationTypeKind {
    boolean,
    unsigned_integer,
    signed_integer,
    address,
    pointer,
    byte_pointer,
    handle,
    function_pointer,
    unknown
};

enum VariableRole : std::uint32_t {
    variable_role_none = 0,
    variable_role_argument = 1U << 0,
    variable_role_return = 1U << 1,
    variable_role_stack_slot = 1U << 2,
    variable_role_global = 1U << 3,
    variable_role_call_result = 1U << 4,
    variable_role_buffer = 1U << 5,
    variable_role_repeated = 1U << 6,
    variable_role_function_pointer = 1U << 7
};

struct VariableEvidence {
    SourceSpan source;
    std::vector<xair_op_id> operations;
    xair_confidence confidence{XAIR_CONFIDENCE_UNKNOWN};
    bool inferred{};
    std::string reason;
};

struct PresentationName {
    std::string text;
    VariableNameOrigin origin{VariableNameOrigin::deterministic};
    VariableEvidence evidence;
};

struct PresentationType {
    PresentationTypeKind kind{PresentationTypeKind::unknown};
    std::string text;
    std::uint16_t exact_bits{};
    VariableEvidence evidence;
};

struct PresentationVariable {
    std::string stable_id;
    VariableKind kind{VariableKind::temporary};
    std::uint32_t roles{variable_role_none};
    xair_value_id primary_value{XAIR_INVALID_ID};
    std::vector<xair_value_id> values;
    /* Storage variables deliberately keep location identities separate from
     * the values read from or written to that location. */
    std::vector<xair_value_id> address_values;
    std::vector<xair_value_id> data_values;
    PresentationName name;
    PresentationType type;
    VariableEvidence evidence;
    std::uint64_t address{};
    std::int64_t stack_offset{};
    std::size_t argument_index{static_cast<std::size_t>(-1)};
    std::uint16_t storage_bits{};
    bool storage_identity{};
    bool overlaps_uncertain{};
};

enum class VariableSymbolOrigin {
    user,
    debug_symbol,
    binary_symbol,
    import
};

struct VariableSymbol {
    xair_value_id value{XAIR_INVALID_ID};
    std::uint64_t address{};
    std::uint64_t size{};
    std::string name;
    VariableSymbolOrigin origin{VariableSymbolOrigin::binary_symbol};
    xair_confidence confidence{XAIR_CONFIDENCE_HIGH};
    SourceSpan source;
};

struct VariableAddressRange {
    std::uint64_t begin{};
    std::uint64_t end{};
    bool readable{};
    bool writable{};
    bool executable{};
};

struct VariableCallHint {
    xair_op_id operation{XAIR_INVALID_ID};
    std::string module;
    std::string name;
    std::uint32_t ordinal{};
    xair_confidence confidence{XAIR_CONFIDENCE_HIGH};
};

struct VariableContext {
    std::vector<VariableSymbol> symbols;
    std::vector<VariableAddressRange> ranges;
    std::vector<VariableCallHint> calls;
};

struct VariableScope {
    std::uint64_t function_address{};
    xair_block_id entry_block{XAIR_INVALID_ID};
    std::vector<xair_block_id> blocks;
    xair_calling_convention calling_convention{XAIR_CC_UNKNOWN};

    bool operator==(const VariableScope&) const = default;
};

struct VariableOptions {
    std::size_t max_variables{4096};
    std::size_t repeated_use_threshold{2};
    bool include_repeated_values{true};
    bool include_buffers{true};

    bool operator==(const VariableOptions&) const = default;
};

struct VariableView {
    xair_status status{XAIR_OK};
    std::uint64_t function_address{};
    std::vector<PresentationVariable> variables;
    bool truncated{};
    std::size_t omitted_variables{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == XAIR_OK;
    }
};

class VariableRecovery final {
public:
    explicit VariableRecovery(
        const xair_module& module,
        VariableContext context = {});
    ~VariableRecovery();

    VariableRecovery(const VariableRecovery&) = delete;
    VariableRecovery& operator=(const VariableRecovery&) = delete;
    VariableRecovery(VariableRecovery&&) noexcept;
    VariableRecovery& operator=(VariableRecovery&&) noexcept;

    [[nodiscard]] VariableView build(
        const VariableScope& scope,
        const VariableOptions& options = {}) const;
    [[nodiscard]] std::size_t cache_size() const noexcept;
    void clear_cache() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] const char* variable_kind_name(VariableKind kind) noexcept;
[[nodiscard]] const char* variable_name_origin_name(
    VariableNameOrigin origin) noexcept;
[[nodiscard]] const char* presentation_type_kind_name(
    PresentationTypeKind kind) noexcept;

} // namespace airece
