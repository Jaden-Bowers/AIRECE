#include <airece/semantic/variable_view.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace airece {
namespace {

std::string ascii_lower(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (const unsigned char character : input) {
        output.push_back(static_cast<char>(std::tolower(character)));
    }
    return output;
}

std::string sanitize_name(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (const unsigned char character : input) {
        if (std::isalnum(character) != 0 || character == '_') {
            output.push_back(static_cast<char>(character));
        } else if (output.empty() || output.back() != '_') {
            output.push_back('_');
        }
    }
    while (!output.empty() && output.back() == '_') output.pop_back();
    if (output.empty()) output = "unnamed";
    if (std::isdigit(static_cast<unsigned char>(output.front())) != 0) {
        output.insert(output.begin(), '_');
    }
    return output;
}

std::string hex_address(const std::uint64_t value) {
    std::ostringstream output;
    output << std::hex << value;
    return output.str();
}

std::string stack_name(const std::int64_t offset) {
    if (offset == 0) return "stack_0";
    if (offset < 0) {
        const std::uint64_t magnitude = offset == std::numeric_limits<std::int64_t>::min()
            ? UINT64_C(1) << 63U : static_cast<std::uint64_t>(-offset);
        return "stack_m" + hex_address(magnitude);
    }
    return "stack_p" + hex_address(static_cast<std::uint64_t>(offset));
}

bool starts_with(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() &&
        value.compare(0, prefix.size(), prefix) == 0;
}

xair_confidence conservative_confidence(
    const xair_confidence left,
    const xair_confidence right) {
    if (left == XAIR_CONFIDENCE_UNKNOWN) return right;
    if (right == XAIR_CONFIDENCE_UNKNOWN) return left;
    return left < right ? left : right;
}

std::string integer_type_name(const bool is_signed, const std::uint16_t bits) {
    if (bits == 1) return "bool";
    if (bits == 8 || bits == 16 || bits == 32 || bits == 64) {
        return std::string(is_signed ? "i" : "u") + std::to_string(bits);
    }
    return "unknown<" + std::to_string(bits) + '>';
}

bool is_handle_api(const std::string& lower_name) {
    static constexpr std::array<const char*, 19> names{{
        "openprocess", "openthread", "createfilea", "createfilew",
        "createtoolhelp32snapshot", "openscmanagera", "openscmanagerw", "openservicea",
        "openservicew", "createservicea", "createservicew", "createmutexa",
        "createmutexw", "createeventa", "createeventw", "createthread",
        "createremotethread", "createfilemappinga", "createfilemappingw"
    }};
    return std::any_of(names.begin(), names.end(), [&](const char* name) {
        return lower_name == ascii_lower(name);
    }) || starts_with(lower_name, "loadlibrary");
}

bool is_pointer_api(const std::string& lower_name) {
    static constexpr std::array<const char*, 11> names{{
        "virtualalloc", "virtualallocex", "heapalloc", "localalloc",
        "globalalloc", "mapviewoffile", "mapviewoffileex", "malloc",
        "calloc", "realloc", "rtlallocateheap"
    }};
    return std::any_of(names.begin(), names.end(), [&](const char* name) {
        return lower_name == name;
    });
}

} // namespace

struct VariableRecovery::Impl {
    struct CacheKey {
        VariableScope scope;
        VariableOptions options;

        bool operator==(const CacheKey&) const = default;
    };

    struct CacheHash {
        std::size_t operator()(const CacheKey& key) const noexcept {
            std::size_t hash = static_cast<std::size_t>(key.scope.function_address);
            const auto mix = [&hash](const std::size_t value) {
                hash ^= value + static_cast<std::size_t>(0x9e3779b9U) +
                    (hash << 6U) + (hash >> 2U);
            };
            mix(key.scope.entry_block);
            mix(static_cast<std::size_t>(key.scope.calling_convention));
            for (const xair_block_id block : key.scope.blocks) mix(block);
            mix(key.options.max_variables);
            mix(key.options.repeated_use_threshold);
            mix(key.options.include_repeated_values ? 1U : 0U);
            mix(key.options.include_buffers ? 1U : 0U);
            return hash;
        }
    };

    struct Candidate {
        bool selected{};
        xair_value_id value{XAIR_INVALID_ID};
        std::uint32_t roles{variable_role_none};
        std::size_t argument_index{std::numeric_limits<std::size_t>::max()};
        xair_op_id call_operation{XAIR_INVALID_ID};
        std::vector<xair_op_id> operations;
        bool signed_context{};
        bool unsigned_context{};
        bool suppress_buffer{};
    };

    struct AffineStack {
        xair_value_id base{XAIR_INVALID_ID};
        std::int64_t offset{};
    };

    struct StackKey {
        xair_value_id base{XAIR_INVALID_ID};
        std::int64_t offset{};
        std::uint16_t bits{};

        bool operator<(const StackKey& other) const noexcept {
            return std::tie(base, offset, bits) <
                std::tie(other.base, other.offset, other.bits);
        }
    };

    struct GlobalKey {
        std::uint64_t address{};
        std::uint16_t bits{};

        bool operator<(const GlobalKey& other) const noexcept {
            return std::tie(address, bits) < std::tie(other.address, other.bits);
        }
    };

    struct StorageRecord {
        xair_value_id primary{XAIR_INVALID_ID};
        std::vector<xair_value_id> values;
        std::vector<xair_value_id> address_values;
        std::vector<xair_value_id> data_values;
        std::vector<xair_op_id> operations;
        xair_type data_type{XAIR_TYPE_INVALID, 0, 0};
        bool overlap{};
    };

    explicit Impl(const xair_module& input, VariableContext input_context)
        : module(&input), context(std::move(input_context)) {
        for (std::size_t index = 0; index < context.symbols.size(); ++index) {
            const VariableSymbol& symbol = context.symbols[index];
            if (symbol.value != XAIR_INVALID_ID) value_symbols[symbol.value].push_back(index);
            if (symbol.address != 0) address_symbols[symbol.address].push_back(index);
        }
        for (std::size_t index = 0; index < context.calls.size(); ++index) {
            if (context.calls[index].operation != XAIR_INVALID_ID) {
                call_hints[context.calls[index].operation] = index;
            }
        }
    }

    static void append_unique_op(std::vector<xair_op_id>& values, const xair_op_id value) {
        if (value == XAIR_INVALID_ID) return;
        if (std::find(values.begin(), values.end(), value) == values.end()) {
            values.push_back(value);
        }
    }

    static void append_unique_value(
        std::vector<xair_value_id>& values,
        const xair_value_id value) {
        if (value == XAIR_INVALID_ID) return;
        if (std::find(values.begin(), values.end(), value) == values.end()) {
            values.push_back(value);
        }
    }

    void add_operation_evidence(
        VariableEvidence& evidence,
        const xair_op_id operation) const {
        append_unique_op(evidence.operations, operation);
        const xair_source_id* sources = nullptr;
        std::size_t count = 0;
        if (xair_op_sources(module, operation, &sources, &count) != XAIR_OK) return;
        for (std::size_t index = 0; index < count; ++index) {
            xair_source_record record{};
            if (xair_module_get_source(module, sources[index], &record) != XAIR_OK) continue;
            ++evidence.source.record_count;
            evidence.source.synthetic = evidence.source.synthetic ||
                record.kind != XAIR_SOURCE_MACHINE ||
                (record.location.flags & XAIR_SOURCE_FLAG_SYNTHETIC) != 0;
            evidence.confidence = conservative_confidence(
                evidence.confidence, record.confidence);
            evidence.source.confidence = evidence.confidence;
            if (record.location.instruction_va == 0) continue;
            const std::uint64_t begin = record.location.instruction_va;
            const std::uint64_t length = record.location.instruction_length;
            const std::uint64_t end = begin >
                    std::numeric_limits<std::uint64_t>::max() - length
                ? std::numeric_limits<std::uint64_t>::max() : begin + length;
            if (evidence.source.begin == 0 || begin < evidence.source.begin) {
                evidence.source.begin = begin;
            }
            if (end > evidence.source.end) evidence.source.end = end;
        }
    }

    VariableEvidence evidence_for_operations(
        const std::vector<xair_op_id>& operations,
        const xair_confidence fallback,
        std::string reason) const {
        VariableEvidence evidence;
        evidence.inferred = true;
        evidence.reason = std::move(reason);
        for (const xair_op_id operation : operations) {
            add_operation_evidence(evidence, operation);
        }
        evidence.confidence = conservative_confidence(evidence.confidence, fallback);
        evidence.source.confidence = evidence.confidence;
        return evidence;
    }

    Candidate& select_candidate(
        std::vector<Candidate>& candidates,
        const xair_value_id value,
        const std::uint32_t role,
        const xair_op_id operation = XAIR_INVALID_ID) const {
        Candidate& candidate = candidates[value];
        candidate.selected = true;
        candidate.value = value;
        candidate.roles |= role;
        append_unique_op(candidate.operations, operation);
        xair_op_id definition = XAIR_INVALID_ID;
        if (xair_value_definition(module, value, &definition) == XAIR_OK) {
            append_unique_op(candidate.operations, definition);
        }
        return candidate;
    }

    static std::optional<std::size_t> explicit_argument_index(const char* raw_name) {
        if (raw_name == nullptr) return std::nullopt;
        const std::string name = ascii_lower(raw_name);
        if (!starts_with(name, "arg") || name.size() == 3) return std::nullopt;
        std::size_t result = 0;
        for (std::size_t index = 3; index < name.size(); ++index) {
            const unsigned char character = static_cast<unsigned char>(name[index]);
            if (std::isdigit(character) == 0) return std::nullopt;
            const std::size_t digit = static_cast<std::size_t>(character - '0');
            if (result > (std::numeric_limits<std::size_t>::max() - digit) / 10U) {
                return std::nullopt;
            }
            result = result * 10U + digit;
        }
        return result;
    }

    static std::optional<std::size_t> abi_argument_index(
        const char* raw_name,
        const xair_calling_convention convention) {
        if (const auto explicit_index = explicit_argument_index(raw_name)) {
            return explicit_index;
        }
        if (raw_name == nullptr) return std::nullopt;
        const std::string name = ascii_lower(raw_name);
        if (convention == XAIR_CC_WIN64) {
            static constexpr std::array<const char*, 4> registers{{"rcx", "rdx", "r8", "r9"}};
            for (std::size_t index = 0; index < registers.size(); ++index) {
                if (name == registers[index]) return index;
            }
        } else if (convention == XAIR_CC_SYSV_X64) {
            static constexpr std::array<const char*, 6> registers{{
                "rdi", "rsi", "rdx", "rcx", "r8", "r9"}};
            for (std::size_t index = 0; index < registers.size(); ++index) {
                if (name == registers[index]) return index;
            }
        }
        return std::nullopt;
    }

    static std::optional<std::size_t> stack_argument_index(
        const std::int64_t offset,
        const xair_calling_convention convention) {
        std::int64_t base = 0;
        std::int64_t stride = 0;
        std::size_t first = 0;
        if (convention == XAIR_CC_WIN64) {
            base = 0x28;
            stride = 8;
            first = 4;
        } else if (convention == XAIR_CC_SYSV_X64) {
            base = 8;
            stride = 8;
            first = 6;
        } else if (convention == XAIR_CC_CDECL_X86 ||
                   convention == XAIR_CC_STDCALL_X86) {
            base = 4;
            stride = 4;
        } else {
            return std::nullopt;
        }
        if (offset < base || (offset - base) % stride != 0) return std::nullopt;
        return first + static_cast<std::size_t>((offset - base) / stride);
    }

    bool constant_signed(const xair_value_id value, std::int64_t& output) const {
        xair_op_id definition = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        std::uint64_t lo = 0;
        std::uint64_t hi = 0;
        if (value >= xair_module_value_count(module) ||
            xair_value_definition(module, value, &definition) != XAIR_OK ||
            definition == XAIR_INVALID_ID ||
            xair_module_get_op_v3(module, definition, &view) != XAIR_OK ||
            view.opcode != XAIR_OP_CONST_U64 ||
            xair_op_immediate_wide(module, definition, &lo, &hi) != XAIR_OK) {
            return false;
        }
        const xair_type type = xair_value_type(module, value);
        if (type.bits != 0 && type.bits < 64) {
            const std::uint64_t mask = (UINT64_C(1) << type.bits) - 1U;
            lo &= mask;
            const std::uint64_t sign = UINT64_C(1) << (type.bits - 1U);
            if ((lo & sign) != 0) lo |= ~mask;
        }
        output = static_cast<std::int64_t>(lo);
        return true;
    }

    std::optional<AffineStack> affine_stack_impl(
        const xair_value_id value,
        const std::size_t depth,
        std::unordered_set<xair_value_id>& active) const {
        if (depth > 16 || value >= xair_module_value_count(module) ||
            !active.insert(value).second) {
            return std::nullopt;
        }
        const char* raw_name = xair_value_name(module, value);
        const std::string name = raw_name == nullptr ? std::string{} : ascii_lower(raw_name);
        if (name == "rsp" || name == "esp" || name == "rbp" || name == "ebp") {
            active.erase(value);
            return AffineStack{value, 0};
        }
        xair_op_id definition = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t count = 0;
        if (xair_value_definition(module, value, &definition) != XAIR_OK ||
            definition == XAIR_INVALID_ID ||
            xair_module_get_op_v3(module, definition, &view) != XAIR_OK ||
            xair_op_inputs(module, definition, &inputs, &count) != XAIR_OK) {
            active.erase(value);
            return std::nullopt;
        }
        if ((view.opcode == XAIR_OP_INT_TO_ADDR || view.opcode == XAIR_OP_ADDR_TO_INT ||
             view.opcode == XAIR_OP_ZEXT || view.opcode == XAIR_OP_SEXT ||
             view.opcode == XAIR_OP_TRUNC) && count == 1) {
            const auto result = affine_stack_impl(inputs[0], depth + 1, active);
            active.erase(value);
            return result;
        }
        if ((view.opcode == XAIR_OP_ADD || view.opcode == XAIR_OP_ADDR_ADD ||
             view.opcode == XAIR_OP_SUB || view.opcode == XAIR_OP_ADDR_SUB) && count >= 2) {
            std::int64_t constant = 0;
            if (constant_signed(inputs[1], constant)) {
                auto base = affine_stack_impl(inputs[0], depth + 1, active);
                if (base) {
                    const bool subtract = view.opcode == XAIR_OP_SUB ||
                        view.opcode == XAIR_OP_ADDR_SUB;
                    const bool valid = subtract
                        ? ((constant >= 0 && base->offset >=
                               std::numeric_limits<std::int64_t>::min() + constant) ||
                           (constant < 0 && base->offset <=
                               std::numeric_limits<std::int64_t>::max() + constant))
                        : ((constant >= 0 && base->offset <=
                               std::numeric_limits<std::int64_t>::max() - constant) ||
                           (constant < 0 && base->offset >=
                               std::numeric_limits<std::int64_t>::min() - constant));
                    if (valid) {
                        base->offset = subtract
                            ? base->offset - constant : base->offset + constant;
                        active.erase(value);
                        return base;
                    }
                }
            }
            if (view.opcode == XAIR_OP_ADD || view.opcode == XAIR_OP_ADDR_ADD) {
                if (constant_signed(inputs[0], constant)) {
                    auto base = affine_stack_impl(inputs[1], depth + 1, active);
                    if (base && ((constant >= 0 && base->offset <=
                                     std::numeric_limits<std::int64_t>::max() - constant) ||
                                 (constant < 0 && base->offset >=
                                     std::numeric_limits<std::int64_t>::min() - constant))) {
                        base->offset += constant;
                        active.erase(value);
                        return base;
                    }
                }
            }
        }
        active.erase(value);
        return std::nullopt;
    }

    std::optional<AffineStack> affine_stack(const xair_value_id value) const {
        std::unordered_set<xair_value_id> active;
        return affine_stack_impl(value, 0, active);
    }

    bool constant_address_impl(
        const xair_value_id value,
        const std::size_t depth,
        std::unordered_set<xair_value_id>& active,
        std::uint64_t& output) const {
        if (depth > 16 || value >= xair_module_value_count(module) ||
            !active.insert(value).second) {
            return false;
        }
        xair_op_id definition = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t count = 0;
        std::uint64_t lo = 0;
        std::uint64_t hi = 0;
        if (xair_value_definition(module, value, &definition) != XAIR_OK ||
            definition == XAIR_INVALID_ID ||
            xair_module_get_op_v3(module, definition, &view) != XAIR_OK) {
            active.erase(value);
            return false;
        }
        if (view.opcode == XAIR_OP_CONST_U64 &&
            xair_op_immediate_wide(module, definition, &lo, &hi) == XAIR_OK) {
            output = lo;
            active.erase(value);
            return true;
        }
        if (xair_op_inputs(module, definition, &inputs, &count) != XAIR_OK) {
            active.erase(value);
            return false;
        }
        if ((view.opcode == XAIR_OP_INT_TO_ADDR || view.opcode == XAIR_OP_ADDR_TO_INT ||
             view.opcode == XAIR_OP_ZEXT || view.opcode == XAIR_OP_TRUNC) && count == 1) {
            const bool result = constant_address_impl(inputs[0], depth + 1, active, output);
            active.erase(value);
            return result;
        }
        if ((view.opcode == XAIR_OP_ADD || view.opcode == XAIR_OP_ADDR_ADD ||
             view.opcode == XAIR_OP_SUB || view.opcode == XAIR_OP_ADDR_SUB) && count >= 2) {
            std::uint64_t left = 0;
            std::uint64_t right = 0;
            if (constant_address_impl(inputs[0], depth + 1, active, left) &&
                constant_address_impl(inputs[1], depth + 1, active, right)) {
                output = view.opcode == XAIR_OP_SUB || view.opcode == XAIR_OP_ADDR_SUB
                    ? left - right : left + right;
                active.erase(value);
                return true;
            }
        }
        active.erase(value);
        return false;
    }

    bool constant_address(const xair_value_id value, std::uint64_t& output) const {
        std::unordered_set<xair_value_id> active;
        return constant_address_impl(value, 0, active, output);
    }

    bool address_is_known(const std::uint64_t address) const {
        if (address_symbols.contains(address)) return true;
        return std::any_of(context.ranges.begin(), context.ranges.end(),
            [address](const VariableAddressRange& range) {
                return address >= range.begin && address < range.end;
            });
    }

    const VariableSymbol* best_value_symbol(const xair_value_id value) const {
        const auto found = value_symbols.find(value);
        if (found == value_symbols.end()) return nullptr;
        const VariableSymbol* best = nullptr;
        for (const std::size_t index : found->second) {
            const VariableSymbol& symbol = context.symbols[index];
            if (best == nullptr || static_cast<int>(symbol.origin) <
                    static_cast<int>(best->origin)) {
                best = &symbol;
            }
        }
        return best;
    }

    const VariableSymbol* best_address_symbol(const std::uint64_t address) const {
        const auto found = address_symbols.find(address);
        if (found == address_symbols.end()) return nullptr;
        const VariableSymbol* best = nullptr;
        for (const std::size_t index : found->second) {
            const VariableSymbol& symbol = context.symbols[index];
            if (best == nullptr || static_cast<int>(symbol.origin) <
                    static_cast<int>(best->origin)) {
                best = &symbol;
            }
        }
        return best;
    }

    const VariableCallHint* call_hint(const xair_op_id operation) const {
        const auto found = call_hints.find(operation);
        return found == call_hints.end() ? nullptr : &context.calls[found->second];
    }

    std::string call_name(
        const xair_op_id operation,
        xair_op_attributes* output_attributes = nullptr) const {
        xair_op_attributes attributes{};
        (void)xair_op_attributes_get(module, operation, &attributes);
        if (output_attributes != nullptr) *output_attributes = attributes;
        if (const VariableCallHint* hint = call_hint(operation)) {
            if (!hint->name.empty()) return hint->name;
            if (hint->ordinal != 0) {
                return sanitize_name(hint->module) + "_ordinal_" +
                    std::to_string(hint->ordinal);
            }
        }
        if (attributes.import_name != nullptr && attributes.import_name[0] != '\0') {
            return attributes.import_name;
        }
        if (attributes.direct_target != 0) {
            return "sub_" + hex_address(attributes.direct_target);
        }
        return "indirect";
    }

    static bool operation_implies_signedness(const xair_opcode opcode) {
        return opcode == XAIR_OP_SDIV || opcode == XAIR_OP_SREM ||
            opcode == XAIR_OP_SLT || opcode == XAIR_OP_SLE ||
            opcode == XAIR_OP_ASHR || opcode == XAIR_OP_SEXT;
    }

    static bool operation_implies_unsignedness(const xair_opcode opcode) {
        return opcode == XAIR_OP_UDIV || opcode == XAIR_OP_UREM ||
            opcode == XAIR_OP_ULT || opcode == XAIR_OP_ULE ||
            opcode == XAIR_OP_LSHR || opcode == XAIR_OP_ZEXT;
    }

    PresentationType type_for_value(
        const Candidate& candidate,
        const std::vector<xair_op_id>& operations) const {
        const xair_type raw = xair_value_type(module, candidate.value);
        PresentationType type;
        type.exact_bits = raw.bits;
        type.evidence = evidence_for_operations(
            operations, XAIR_CONFIDENCE_EXACT, "exact XAIR width and use context");
        type.evidence.inferred = false;
        if ((candidate.roles & variable_role_function_pointer) != 0) {
            type.kind = PresentationTypeKind::function_pointer;
            type.text = "function_ptr";
            type.evidence.inferred = true;
            type.evidence.reason = "value is the target of an indirect XAIR call";
            return type;
        }
        if (candidate.call_operation != XAIR_INVALID_ID) {
            const std::string lower = ascii_lower(call_name(candidate.call_operation));
            if (is_handle_api(lower)) {
                type.kind = PresentationTypeKind::handle;
                type.text = "handle";
                type.evidence.inferred = true;
                type.evidence.reason = "known imported API return role";
                return type;
            }
            if (is_pointer_api(lower)) {
                type.kind = PresentationTypeKind::byte_pointer;
                type.text = "ptr<u8>";
                type.evidence.inferred = true;
                type.evidence.reason = "known allocation API return role";
                return type;
            }
        }
        if ((candidate.roles & variable_role_buffer) != 0) {
            type.kind = PresentationTypeKind::byte_pointer;
            type.text = "ptr<u8>";
            type.evidence.inferred = true;
            type.evidence.reason = "value is used as a load/store address";
            return type;
        }
        if (raw.kind == XAIR_TYPE_INT && raw.bits == 1) {
            type.kind = PresentationTypeKind::boolean;
            type.text = "bool";
        } else if (raw.kind == XAIR_TYPE_INT &&
                   (raw.bits == 8 || raw.bits == 16 || raw.bits == 32 || raw.bits == 64) &&
                   candidate.signed_context != candidate.unsigned_context) {
            type.kind = candidate.signed_context
                ? PresentationTypeKind::signed_integer
                : PresentationTypeKind::unsigned_integer;
            type.text = integer_type_name(candidate.signed_context, raw.bits);
            if (candidate.signed_context || candidate.unsigned_context) {
                type.evidence.inferred = true;
                type.evidence.reason = candidate.signed_context
                    ? "signed XAIR operation requires signed interpretation"
                    : "unsigned XAIR operation requires unsigned interpretation";
            }
        } else if (raw.kind == XAIR_TYPE_ADDR) {
            type.kind = PresentationTypeKind::address;
            type.text = "addr" + std::to_string(raw.bits);
        } else {
            type.kind = PresentationTypeKind::unknown;
            type.text = "unknown<" + std::to_string(raw.bits) + '>';
        }
        return type;
    }

    PresentationType type_for_storage(
        const xair_type raw,
        const std::uint16_t storage_bits,
        const std::vector<xair_op_id>& operations,
        const bool signed_context,
        const bool unsigned_context,
        const std::string& reason) const {
        PresentationType type;
        type.exact_bits = storage_bits;
        type.evidence = evidence_for_operations(
            operations, XAIR_CONFIDENCE_HIGH, reason);
        if (raw.kind == XAIR_TYPE_INT && raw.bits == 1) {
            type.kind = PresentationTypeKind::boolean;
            type.text = "bool";
        } else if (raw.kind == XAIR_TYPE_INT &&
                   (raw.bits == 8 || raw.bits == 16 || raw.bits == 32 || raw.bits == 64) &&
                   signed_context != unsigned_context) {
            type.kind = signed_context
                ? PresentationTypeKind::signed_integer
                : PresentationTypeKind::unsigned_integer;
            type.text = integer_type_name(signed_context, raw.bits);
        } else if (raw.kind == XAIR_TYPE_ADDR) {
            type.kind = PresentationTypeKind::address;
            type.text = "addr" + std::to_string(raw.bits);
        } else {
            type.kind = PresentationTypeKind::unknown;
            type.text = "unknown<" + std::to_string(storage_bits) + '>';
        }
        return type;
    }

    static VariableKind primary_kind(const std::uint32_t roles) {
        if ((roles & variable_role_global) != 0) return VariableKind::global;
        if ((roles & variable_role_argument) != 0) return VariableKind::argument;
        if ((roles & variable_role_call_result) != 0) return VariableKind::call_result;
        if ((roles & variable_role_return) != 0) return VariableKind::return_value;
        if ((roles & variable_role_buffer) != 0) return VariableKind::buffer;
        if ((roles & variable_role_repeated) != 0) return VariableKind::repeated_value;
        return VariableKind::temporary;
    }

    PresentationName name_for_candidate(const Candidate& candidate) const {
        PresentationName name;
        if (const VariableSymbol* symbol = best_value_symbol(candidate.value)) {
            name.text = sanitize_name(symbol->name);
            name.origin = symbol->origin == VariableSymbolOrigin::user
                ? VariableNameOrigin::user : VariableNameOrigin::debug_symbol;
            name.evidence.confidence = symbol->confidence;
            name.evidence.source = symbol->source;
            name.evidence.reason = "user/debug value symbol";
            return name;
        }
        if (candidate.call_operation != XAIR_INVALID_ID) {
            const VariableCallHint* hint = call_hint(candidate.call_operation);
            xair_op_attributes attributes{};
            const std::string callee = call_name(candidate.call_operation, &attributes);
            name.text = "call_" + sanitize_name(callee) + "_result";
            name.origin = hint != nullptr ||
                    (attributes.import_name != nullptr && attributes.import_name[0] != '\0')
                ? VariableNameOrigin::import_role : VariableNameOrigin::semantic_role;
            name.evidence = evidence_for_operations(
                candidate.operations,
                hint == nullptr ? XAIR_CONFIDENCE_MEDIUM : hint->confidence,
                hint == nullptr ? "XAIR call-result role" : "import/API-derived call result role");
            return name;
        }
        if ((candidate.roles & variable_role_global) != 0) {
            std::uint64_t address = 0;
            if (constant_address(candidate.value, address)) {
                if (const VariableSymbol* symbol = best_address_symbol(address)) {
                    name.text = sanitize_name(symbol->name);
                    name.origin = symbol->origin == VariableSymbolOrigin::import
                        ? VariableNameOrigin::import_role : VariableNameOrigin::debug_symbol;
                    name.evidence.confidence = symbol->confidence;
                    name.evidence.source = symbol->source;
                    name.evidence.reason = "binary symbol at exact address";
                    return name;
                }
                name.text = "global_" + hex_address(address);
                name.origin = VariableNameOrigin::storage_address;
                name.evidence = evidence_for_operations(
                    candidate.operations, XAIR_CONFIDENCE_HIGH,
                    "constant address lies within a loaded binary segment");
                return name;
            }
        }
        if ((candidate.roles & variable_role_argument) != 0 &&
            candidate.argument_index != std::numeric_limits<std::size_t>::max()) {
            name.text = "arg" + std::to_string(candidate.argument_index);
            name.origin = VariableNameOrigin::semantic_role;
            name.evidence = evidence_for_operations(
                candidate.operations, XAIR_CONFIDENCE_HIGH,
                "entry parameter matches the function calling convention");
            return name;
        }
        if ((candidate.roles & variable_role_return) != 0) {
            name.text = "return_value";
            name.origin = VariableNameOrigin::semantic_role;
            name.evidence = evidence_for_operations(
                candidate.operations, XAIR_CONFIDENCE_MEDIUM,
                "first non-memory value at a function return");
            return name;
        }
        if ((candidate.roles & variable_role_function_pointer) != 0) {
            name.text = "function_ptr_v" + std::to_string(candidate.value);
            name.origin = VariableNameOrigin::semantic_role;
            name.evidence = evidence_for_operations(
                candidate.operations, XAIR_CONFIDENCE_HIGH,
                "indirect XAIR call target");
            return name;
        }
        if ((candidate.roles & variable_role_buffer) != 0) {
            name.text = "buffer_v" + std::to_string(candidate.value);
            name.origin = VariableNameOrigin::semantic_role;
            name.evidence = evidence_for_operations(
                candidate.operations, XAIR_CONFIDENCE_HIGH,
                "address participates in XAIR memory operations");
            return name;
        }
        name.text = "tmp_" + std::to_string(candidate.value);
        name.origin = VariableNameOrigin::deterministic;
        name.evidence = evidence_for_operations(
            candidate.operations, XAIR_CONFIDENCE_EXACT,
            "deterministic XAIR value identity");
        return name;
    }

    static bool intervals_overlap(
        const std::int64_t left_offset,
        const std::uint16_t left_bits,
        const std::int64_t right_offset,
        const std::uint16_t right_bits) {
        const std::uint64_t left_size = (static_cast<std::uint64_t>(left_bits) + 7U) / 8U;
        const std::uint64_t right_size = (static_cast<std::uint64_t>(right_bits) + 7U) / 8U;
        if (left_size == 0 || right_size == 0 ||
            left_offset > std::numeric_limits<std::int64_t>::max() -
                static_cast<std::int64_t>(left_size) ||
            right_offset > std::numeric_limits<std::int64_t>::max() -
                static_cast<std::int64_t>(right_size)) {
            return false;
        }
        const std::int64_t left_end = left_offset + static_cast<std::int64_t>(left_size);
        const std::int64_t right_end = right_offset + static_cast<std::int64_t>(right_size);
        return left_offset < right_end && right_offset < left_end;
    }

    VariableView build_uncached(
        const VariableScope& scope,
        const VariableOptions& options) const {
        VariableView view;
        view.function_address = scope.function_address;
        const std::size_t block_count = xair_module_block_count(module);
        if (scope.entry_block >= block_count || scope.blocks.empty() ||
            std::any_of(scope.blocks.begin(), scope.blocks.end(),
                [block_count](const xair_block_id block) { return block >= block_count; })) {
            view.status = XAIR_ERR_BAD_ARG;
            return view;
        }

        const std::size_t value_count = xair_module_value_count(module);
        std::vector<Candidate> candidates(value_count);
        std::vector<std::size_t> uses(value_count, 0);
        std::vector<std::size_t> meaningful_uses(value_count, 0);
        std::vector<bool> in_scope(value_count, false);
        std::map<StackKey, StorageRecord> stacks;
        std::map<GlobalKey, StorageRecord> globals;
        std::unordered_set<xair_block_id> seen_blocks;
        for (const xair_block_id block : scope.blocks) {
            if (!seen_blocks.insert(block).second) continue;
            const std::size_t block_params = xair_block_param_count(module, block);
            for (std::size_t index = 0; index < block_params; ++index) {
                xair_value_id parameter = XAIR_INVALID_ID;
                if (xair_block_param_value(module, block, index, &parameter) == XAIR_OK &&
                    parameter < in_scope.size()) {
                    in_scope[parameter] = true;
                }
            }
            const xair_op_id* operations = nullptr;
            std::size_t operation_count = 0;
            if (xair_block_ops(module, block, &operations, &operation_count) != XAIR_OK) continue;
            for (std::size_t operation_index = 0;
                 operation_index < operation_count; ++operation_index) {
                const xair_op_id operation = operations[operation_index];
                xair_op_view_v3 op{};
                const xair_value_id* inputs = nullptr;
                std::size_t input_count = 0;
                if (xair_module_get_op_v3(module, operation, &op) != XAIR_OK ||
                    xair_op_inputs(module, operation, &inputs, &input_count) != XAIR_OK) {
                    continue;
                }
                for (std::size_t index = 0; index < input_count; ++index) {
                    if (inputs[index] < uses.size()) {
                        ++uses[inputs[index]];
                        if (op.opcode != XAIR_OP_CALL) ++meaningful_uses[inputs[index]];
                        in_scope[inputs[index]] = true;
                        append_unique_op(candidates[inputs[index]].operations, operation);
                    }
                    if (operation_implies_signedness(op.opcode) && inputs[index] < value_count) {
                        candidates[inputs[index]].signed_context = true;
                    }
                    if (operation_implies_unsignedness(op.opcode) && inputs[index] < value_count) {
                        candidates[inputs[index]].unsigned_context = true;
                    }
                }
                const xair_value_id* results = nullptr;
                std::size_t result_count = 0;
                (void)xair_op_results(module, operation, &results, &result_count);
                for (std::size_t index = 0; index < result_count; ++index) {
                    if (results[index] < in_scope.size()) in_scope[results[index]] = true;
                }
                if (operation_implies_signedness(op.opcode)) {
                    for (std::size_t index = 0; index < result_count; ++index) {
                        if (results[index] < value_count) candidates[results[index]].signed_context = true;
                    }
                }
                if (operation_implies_unsignedness(op.opcode)) {
                    for (std::size_t index = 0; index < result_count; ++index) {
                        if (results[index] < value_count) candidates[results[index]].unsigned_context = true;
                    }
                }
                if (op.opcode == XAIR_OP_CALL) {
                    xair_value_id result = XAIR_INVALID_ID;
                    for (std::size_t index = 0; index < result_count; ++index) {
                        if (xair_value_type(module, results[index]).kind != XAIR_TYPE_MEM) {
                            result = results[index];
                            break;
                        }
                    }
                    if (result != XAIR_INVALID_ID) {
                        Candidate& candidate = select_candidate(
                            candidates, result, variable_role_call_result, operation);
                        candidate.call_operation = operation;
                    }
                    xair_op_attributes attributes{};
                    if (xair_op_attributes_get(module, operation, &attributes) == XAIR_OK &&
                        attributes.call_kind == XAIR_CALL_INDIRECT && input_count != 0) {
                        for (std::size_t index = input_count; index != 0; --index) {
                            const xair_value_id input = inputs[index - 1];
                            if (xair_value_type(module, input).kind == XAIR_TYPE_MEM) continue;
                            select_candidate(candidates, input,
                                variable_role_function_pointer, operation);
                            break;
                        }
                    }
                }
                if ((op.opcode == XAIR_OP_LOAD && input_count >= 2) ||
                    (op.opcode == XAIR_OP_STORE && input_count >= 3)) {
                    const xair_value_id address = inputs[1];
                    xair_type data_type{XAIR_TYPE_INVALID, 0, 0};
                    xair_value_id accessed_value = XAIR_INVALID_ID;
                    if (op.opcode == XAIR_OP_LOAD && result_count != 0) {
                        data_type = xair_value_type(module, results[0]);
                        accessed_value = results[0];
                    } else if (op.opcode == XAIR_OP_STORE) {
                        data_type = xair_value_type(module, inputs[2]);
                        accessed_value = inputs[2];
                    }
                    xair_op_attributes attributes{};
                    (void)xair_op_attributes_get(module, operation, &attributes);
                    const std::uint16_t bits = attributes.width_bits != 0
                        ? attributes.width_bits : data_type.bits;
                    if (const auto stack = affine_stack(address)) {
                        const StackKey key{stack->base, stack->offset, bits};
                        StorageRecord& record = stacks[key];
                        if (record.primary == XAIR_INVALID_ID) record.primary = address;
                        if (record.data_type.kind == XAIR_TYPE_INVALID) record.data_type = data_type;
                        append_unique_value(record.values, address);
                        append_unique_value(record.values, accessed_value);
                        append_unique_value(record.address_values, address);
                        append_unique_value(record.data_values, accessed_value);
                        append_unique_op(record.operations, operation);
                        if (address < candidates.size()) candidates[address].suppress_buffer = true;
                    } else {
                        std::uint64_t global_address = 0;
                        if (constant_address(address, global_address) &&
                            address_is_known(global_address)) {
                            const GlobalKey key{global_address, bits};
                            StorageRecord& record = globals[key];
                            if (record.primary == XAIR_INVALID_ID) record.primary = address;
                            if (record.data_type.kind == XAIR_TYPE_INVALID) record.data_type = data_type;
                            append_unique_value(record.values, address);
                            append_unique_value(record.values, accessed_value);
                            append_unique_value(record.address_values, address);
                            append_unique_value(record.data_values, accessed_value);
                            append_unique_op(record.operations, operation);
                            if (address < candidates.size()) candidates[address].suppress_buffer = true;
                        } else if (options.include_buffers && address < value_count) {
                            select_candidate(candidates, address, variable_role_buffer, operation);
                        }
                    }
                }
                for (std::size_t index = 0; index < result_count; ++index) {
                    const xair_value_id result = results[index];
                    if (xair_value_type(module, result).kind != XAIR_TYPE_ADDR) continue;
                    std::uint64_t address = 0;
                    if (constant_address(result, address) && address_is_known(address)) {
                        Candidate& candidate = select_candidate(
                            candidates, result, variable_role_global, operation);
                        candidate.suppress_buffer = true;
                    }
                }
            }

            xair_term_view terminator{};
            if (xair_block_terminator(module, block, &terminator) == XAIR_OK) {
                if (terminator.condition < uses.size()) {
                    ++uses[terminator.condition];
                    ++meaningful_uses[terminator.condition];
                    in_scope[terminator.condition] = true;
                }
                for (std::size_t index = 0; index < terminator.true_arg_count; ++index) {
                    if (terminator.true_args[index] < uses.size()) {
                        ++uses[terminator.true_args[index]];
                        in_scope[terminator.true_args[index]] = true;
                    }
                }
                for (std::size_t index = 0; index < terminator.false_arg_count; ++index) {
                    if (terminator.false_args[index] < uses.size()) {
                        ++uses[terminator.false_args[index]];
                        in_scope[terminator.false_args[index]] = true;
                    }
                }
                if (terminator.kind == XAIR_TERM_VIEW_RETURN) {
                    for (std::size_t index = 0; index < terminator.true_arg_count; ++index) {
                        const xair_value_id value = terminator.true_args[index];
                        const xair_type type = xair_value_type(module, value);
                        if (type.kind == XAIR_TYPE_MEM || type.kind == XAIR_TYPE_FLAGS) continue;
                        ++meaningful_uses[value];
                        select_candidate(candidates, value, variable_role_return);
                        break;
                    }
                }
            }
        }

        /* A parameter can cross one or more block arguments before its first
         * semantic use. Propagate that relevance backward through CFG edges so
         * Debug/O0 prologues retain their real arity without treating values
         * used only as speculative CALL operands as parameters. */
        for (std::size_t pass = 0; pass <= scope.blocks.size(); ++pass) {
            bool changed = false;
            for (const xair_block_id block : scope.blocks) {
                xair_term_view terminator{};
                if (xair_block_terminator(module, block, &terminator) != XAIR_OK) continue;
                const auto propagate_relevance = [&](const xair_block_id target,
                                                     const xair_value_id* arguments,
                                                     const std::size_t argument_count) {
                    if (std::find(scope.blocks.begin(), scope.blocks.end(), target) ==
                            scope.blocks.end() || arguments == nullptr) return;
                    const std::size_t count = std::min(
                        xair_block_param_count(module, target), argument_count);
                    for (std::size_t index = 0; index < count; ++index) {
                        xair_value_id parameter = XAIR_INVALID_ID;
                        if (xair_block_param_value(module, target, index, &parameter) != XAIR_OK ||
                            parameter >= meaningful_uses.size() ||
                            arguments[index] >= meaningful_uses.size() ||
                            meaningful_uses[parameter] == 0 ||
                            meaningful_uses[arguments[index]] != 0) continue;
                        meaningful_uses[arguments[index]] = 1;
                        changed = true;
                    }
                };
                propagate_relevance(
                    terminator.true_target, terminator.true_args, terminator.true_arg_count);
                propagate_relevance(
                    terminator.false_target, terminator.false_args, terminator.false_arg_count);
            }
            if (!changed) break;
        }

        const std::size_t param_count = xair_block_param_count(module, scope.entry_block);
        xair_value_id entry_stack_pointer = XAIR_INVALID_ID;
        for (std::size_t index = 0; index < param_count; ++index) {
            xair_value_id value = XAIR_INVALID_ID;
            if (xair_block_param_value(module, scope.entry_block, index, &value) != XAIR_OK ||
                value >= value_count) {
                continue;
            }
            const auto argument = abi_argument_index(
                xair_value_name(module, value), scope.calling_convention);
            const char* raw_name = xair_value_name(module, value);
            if (raw_name != nullptr) {
                const std::string lowered = ascii_lower(raw_name);
                if (lowered == "rsp" || lowered == "esp") entry_stack_pointer = value;
            }
            if (!argument || (*argument != 0 && meaningful_uses[value] == 0)) continue;
            Candidate& candidate = select_candidate(
                candidates, value, variable_role_argument);
            candidate.argument_index = *argument;
        }

        /* Entry ABI identities must survive XAIR block parameters. Propagate
         * them along explicit CFG arguments before presentation variables are
         * materialized. */
        for (std::size_t pass = 0; pass <= scope.blocks.size(); ++pass) {
            bool changed = false;
            for (const xair_block_id block : scope.blocks) {
                xair_term_view terminator{};
                if (xair_block_terminator(module, block, &terminator) != XAIR_OK) {
                    continue;
                }
                const auto propagate = [&](const xair_block_id target,
                                           const xair_value_id* arguments,
                                           const std::size_t argument_count) {
                    if (std::find(scope.blocks.begin(), scope.blocks.end(), target) ==
                            scope.blocks.end() || arguments == nullptr) return;
                    const std::size_t count = std::min(
                        xair_block_param_count(module, target), argument_count);
                    for (std::size_t index = 0; index < count; ++index) {
                        const xair_value_id source = arguments[index];
                        xair_value_id parameter = XAIR_INVALID_ID;
                        if (source >= candidates.size() ||
                            (candidates[source].roles & variable_role_argument) == 0 ||
                            xair_block_param_value(module, target, index, &parameter) != XAIR_OK ||
                            parameter >= candidates.size()) continue;
                        Candidate& destination = select_candidate(
                            candidates, parameter, variable_role_argument);
                        if (destination.argument_index !=
                            candidates[source].argument_index) {
                            destination.argument_index = candidates[source].argument_index;
                            changed = true;
                        }
                    }
                };
                propagate(terminator.true_target, terminator.true_args,
                          terminator.true_arg_count);
                propagate(terminator.false_target, terminator.false_args,
                          terminator.false_arg_count);
            }
            if (!changed) break;
        }

        for (const auto& [value, symbol_indexes] : value_symbols) {
            (void)symbol_indexes;
            if (value < value_count && in_scope[value]) {
                select_candidate(candidates, value, variable_role_none);
            }
        }

        if (options.include_repeated_values && options.repeated_use_threshold != 0) {
            for (xair_value_id value = 0; value < value_count; ++value) {
                if (uses[value] < options.repeated_use_threshold) continue;
                const xair_type type = xair_value_type(module, value);
                if (type.kind == XAIR_TYPE_MEM || type.kind == XAIR_TYPE_FLAGS ||
                    type.kind == XAIR_TYPE_VOID) {
                    continue;
                }
                xair_op_id definition = XAIR_INVALID_ID;
                xair_op_view_v3 op{};
                if (xair_value_definition(module, value, &definition) == XAIR_OK &&
                    definition != XAIR_INVALID_ID &&
                    xair_module_get_op_v3(module, definition, &op) == XAIR_OK &&
                    (op.opcode == XAIR_OP_CONST_U64 || op.opcode == XAIR_OP_CONST_WIDE)) {
                    continue;
                }
                select_candidate(candidates, value, variable_role_repeated);
            }
        }

        for (auto& [left_key, left] : stacks) {
            for (auto& [right_key, right] : stacks) {
                if (&left == &right || left_key.base != right_key.base ||
                    (left_key.offset == right_key.offset && left_key.bits == right_key.bits)) {
                    continue;
                }
                if (intervals_overlap(left_key.offset, left_key.bits,
                                      right_key.offset, right_key.bits)) {
                    left.overlap = true;
                    right.overlap = true;
                }
            }
        }

        for (const Candidate& candidate : candidates) {
            if (!candidate.selected || candidate.value == XAIR_INVALID_ID) continue;
            Candidate effective = candidate;
            if (effective.suppress_buffer) effective.roles &= ~variable_role_buffer;
            if (effective.suppress_buffer &&
                (effective.roles & ~(variable_role_global | variable_role_repeated)) == 0 &&
                best_value_symbol(effective.value) == nullptr) {
                continue;
            }
            if (effective.roles == variable_role_none &&
                best_value_symbol(effective.value) == nullptr) {
                continue;
            }
            PresentationVariable variable;
            variable.stable_id = "value:" + std::to_string(effective.value);
            variable.kind = primary_kind(effective.roles);
            variable.roles = effective.roles;
            variable.argument_index = effective.argument_index;
            variable.primary_value = effective.value;
            variable.values.push_back(effective.value);
            if ((effective.roles & variable_role_global) != 0) {
                (void)constant_address(effective.value, variable.address);
            }
            variable.name = name_for_candidate(effective);
            variable.type = type_for_value(effective, effective.operations);
            variable.evidence = evidence_for_operations(
                effective.operations, XAIR_CONFIDENCE_HIGH,
                "XAIR value and role evidence");
            if ((effective.roles & variable_role_argument) != 0 &&
                effective.argument_index != std::numeric_limits<std::size_t>::max()) {
                const auto existing = std::find_if(
                    view.variables.begin(), view.variables.end(),
                    [&](const PresentationVariable& item) {
                        return (item.roles & variable_role_argument) != 0 &&
                            !item.storage_identity &&
                            item.argument_index == effective.argument_index;
                    });
                if (existing != view.variables.end()) {
                    existing->values.push_back(effective.value);
                    existing->roles |= effective.roles;
                    existing->evidence.operations.insert(
                        existing->evidence.operations.end(),
                        effective.operations.begin(), effective.operations.end());
                    continue;
                }
            }
            view.variables.push_back(std::move(variable));
        }

        for (const auto& [key, record] : stacks) {
            PresentationVariable variable;
            variable.stable_id = "stack:" + std::to_string(key.base) + ':' +
                std::to_string(key.offset) + ':' + std::to_string(key.bits);
            const char* base_name_raw = xair_value_name(module, key.base);
            const std::string base_name = base_name_raw == nullptr
                ? std::string{} : ascii_lower(base_name_raw);
            const auto argument = key.base == entry_stack_pointer &&
                    (base_name == "rsp" || base_name == "esp")
                ? stack_argument_index(key.offset, scope.calling_convention)
                : std::nullopt;
            variable.kind = argument ? VariableKind::argument : VariableKind::stack_slot;
            variable.roles = variable_role_stack_slot |
                (argument ? variable_role_argument : variable_role_none);
            variable.primary_value = record.primary;
            variable.values = record.values;
            variable.address_values = record.address_values;
            variable.data_values = record.data_values;
            variable.stack_offset = key.offset;
            variable.argument_index = argument
                ? *argument : std::numeric_limits<std::size_t>::max();
            variable.storage_bits = key.bits;
            variable.storage_identity = true;
            variable.overlaps_uncertain = record.overlap;
            variable.name.text = argument
                ? "arg" + std::to_string(*argument) : stack_name(key.offset);
            if (record.overlap) variable.name.text += '_' + std::to_string(key.bits);
            variable.name.origin = argument
                ? VariableNameOrigin::semantic_role : VariableNameOrigin::storage_address;
            variable.name.evidence = evidence_for_operations(
                record.operations, XAIR_CONFIDENCE_HIGH,
                argument
                    ? "calling-convention stack argument at exact entry-stack offset"
                    : record.overlap
                    ? "affine stack address; overlapping access kept separate"
                    : "affine stack base and exact byte offset");
            variable.type = type_for_storage(
                record.data_type, key.bits, record.operations,
                std::any_of(record.data_values.begin(), record.data_values.end(),
                    [&](const xair_value_id value) {
                        return value < candidates.size() && candidates[value].signed_context;
                    }),
                std::any_of(record.data_values.begin(), record.data_values.end(),
                    [&](const xair_value_id value) {
                        return value < candidates.size() && candidates[value].unsigned_context;
                    }),
                "exact XAIR memory-access width");
            variable.evidence = variable.name.evidence;
            view.variables.push_back(std::move(variable));
        }

        for (const auto& [key, record] : globals) {
            PresentationVariable variable;
            variable.stable_id = "global:" + hex_address(key.address) + ':' +
                std::to_string(key.bits);
            variable.kind = VariableKind::global;
            variable.roles = variable_role_global;
            variable.primary_value = record.primary;
            variable.values = record.values;
            variable.address_values = record.address_values;
            variable.data_values = record.data_values;
            variable.address = key.address;
            variable.storage_bits = key.bits;
            variable.storage_identity = true;
            if (const VariableSymbol* symbol = best_address_symbol(key.address)) {
                variable.name.text = sanitize_name(symbol->name);
                variable.name.origin = symbol->origin == VariableSymbolOrigin::import
                    ? VariableNameOrigin::import_role : VariableNameOrigin::debug_symbol;
                variable.name.evidence.confidence = symbol->confidence;
                variable.name.evidence.source = symbol->source;
                variable.name.evidence.reason = "binary symbol at exact global address";
            } else {
                variable.name.text = "global_" + hex_address(key.address);
                variable.name.origin = VariableNameOrigin::storage_address;
                variable.name.evidence = evidence_for_operations(
                    record.operations, XAIR_CONFIDENCE_HIGH,
                    "constant address lies within a loaded binary segment");
            }
            variable.type = type_for_storage(
                record.data_type, key.bits, record.operations,
                std::any_of(record.data_values.begin(), record.data_values.end(),
                    [&](const xair_value_id value) {
                        return value < candidates.size() && candidates[value].signed_context;
                    }),
                std::any_of(record.data_values.begin(), record.data_values.end(),
                    [&](const xair_value_id value) {
                        return value < candidates.size() && candidates[value].unsigned_context;
                    }),
                "exact XAIR global memory-access width");
            variable.evidence = evidence_for_operations(
                record.operations, XAIR_CONFIDENCE_HIGH,
                "exact constant global address and XAIR access");
            view.variables.push_back(std::move(variable));
        }

        /* An unknown ABI has no arity metadata. A gap in the observed register
         * prefix means later volatile argument registers are compiler
         * temporaries, not defensible parameters. Keep the contiguous prefix
         * and let symbols/call-site evidence provide wider signatures later. */
        std::unordered_set<std::size_t> argument_indices;
        for (const PresentationVariable& variable : view.variables) {
            if ((variable.roles & variable_role_argument) != 0 &&
                !variable.storage_identity &&
                variable.argument_index != std::numeric_limits<std::size_t>::max()) {
                argument_indices.insert(variable.argument_index);
            }
        }
        std::size_t contiguous_arguments = 0;
        while (argument_indices.contains(contiguous_arguments)) ++contiguous_arguments;
        view.variables.erase(
            std::remove_if(view.variables.begin(), view.variables.end(),
                [&](const PresentationVariable& variable) {
                    return (variable.roles & variable_role_argument) != 0 &&
                        !variable.storage_identity &&
                        variable.argument_index >= contiguous_arguments;
                }),
            view.variables.end());

        std::sort(view.variables.begin(), view.variables.end(),
            [](const PresentationVariable& left, const PresentationVariable& right) {
                if (left.kind != right.kind) {
                    return static_cast<int>(left.kind) < static_cast<int>(right.kind);
                }
                if (left.kind == VariableKind::argument &&
                    left.argument_index != right.argument_index) {
                    return left.argument_index < right.argument_index;
                }
                if (left.primary_value != right.primary_value) {
                    return left.primary_value < right.primary_value;
                }
                return left.stable_id < right.stable_id;
            });

        std::unordered_set<std::string> names;
        for (PresentationVariable& variable : view.variables) {
            if (names.insert(variable.name.text).second) continue;
            const std::string base = variable.name.text;
            if (variable.primary_value != XAIR_INVALID_ID) {
                variable.name.text = base + "_v" +
                    std::to_string(variable.primary_value);
            } else {
                variable.name.text = base + "_2";
            }
            std::size_t suffix = 2;
            while (!names.insert(variable.name.text).second) {
                ++suffix;
                variable.name.text = base + '_' + std::to_string(suffix);
            }
        }

        if (options.max_variables != 0 && view.variables.size() > options.max_variables) {
            view.omitted_variables = view.variables.size() - options.max_variables;
            view.variables.resize(options.max_variables);
            view.truncated = true;
        }
        return view;
    }

    VariableView build(
        const VariableScope& scope,
        const VariableOptions& options) const {
        const CacheKey key{scope, options};
        {
            const std::scoped_lock lock(cache_mutex);
            const auto found = cache.find(key);
            if (found != cache.end()) return found->second;
        }
        VariableView result = build_uncached(scope, options);
        {
            const std::scoped_lock lock(cache_mutex);
            const auto [entry, inserted] = cache.emplace(key, result);
            if (!inserted) return entry->second;
        }
        return result;
    }

    const xair_module* module{};
    VariableContext context;
    std::unordered_map<xair_value_id, std::vector<std::size_t>> value_symbols;
    std::unordered_map<std::uint64_t, std::vector<std::size_t>> address_symbols;
    std::unordered_map<xair_op_id, std::size_t> call_hints;
    mutable std::mutex cache_mutex;
    mutable std::unordered_map<CacheKey, VariableView, CacheHash> cache;
};

VariableRecovery::VariableRecovery(
    const xair_module& module,
    VariableContext context)
    : impl_(std::make_unique<Impl>(module, std::move(context))) {}

VariableRecovery::~VariableRecovery() = default;
VariableRecovery::VariableRecovery(VariableRecovery&&) noexcept = default;
VariableRecovery& VariableRecovery::operator=(VariableRecovery&&) noexcept = default;

VariableView VariableRecovery::build(
    const VariableScope& scope,
    const VariableOptions& options) const {
    return impl_->build(scope, options);
}

std::size_t VariableRecovery::cache_size() const noexcept {
    const std::scoped_lock lock(impl_->cache_mutex);
    return impl_->cache.size();
}

void VariableRecovery::clear_cache() const {
    const std::scoped_lock lock(impl_->cache_mutex);
    impl_->cache.clear();
}

const char* variable_kind_name(const VariableKind kind) noexcept {
    switch (kind) {
    case VariableKind::argument: return "argument";
    case VariableKind::return_value: return "return-value";
    case VariableKind::stack_slot: return "stack-slot";
    case VariableKind::global: return "global";
    case VariableKind::call_result: return "call-result";
    case VariableKind::buffer: return "buffer";
    case VariableKind::repeated_value: return "repeated-value";
    case VariableKind::temporary: return "temporary";
    }
    return "temporary";
}

const char* variable_name_origin_name(const VariableNameOrigin origin) noexcept {
    switch (origin) {
    case VariableNameOrigin::user: return "user";
    case VariableNameOrigin::debug_symbol: return "debug-symbol";
    case VariableNameOrigin::import_role: return "import-role";
    case VariableNameOrigin::semantic_role: return "semantic-role";
    case VariableNameOrigin::storage_address: return "storage-address";
    case VariableNameOrigin::deterministic: return "deterministic";
    }
    return "deterministic";
}

const char* presentation_type_kind_name(const PresentationTypeKind kind) noexcept {
    switch (kind) {
    case PresentationTypeKind::boolean: return "boolean";
    case PresentationTypeKind::unsigned_integer: return "unsigned-integer";
    case PresentationTypeKind::signed_integer: return "signed-integer";
    case PresentationTypeKind::address: return "address";
    case PresentationTypeKind::pointer: return "pointer";
    case PresentationTypeKind::byte_pointer: return "byte-pointer";
    case PresentationTypeKind::handle: return "handle";
    case PresentationTypeKind::function_pointer: return "function-pointer";
    case PresentationTypeKind::unknown: return "unknown";
    }
    return "unknown";
}

} // namespace airece
