#include <airece/semantic/directed_flow.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <deque>
#include <iomanip>
#include <limits>
#include <optional>
#include <queue>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace airece {
namespace {

using Clock = std::chrono::steady_clock;

struct Tag {
    std::size_t source{};
    bool bytes{};
    bool pointer{};
    bool exact_offset{};
    std::size_t begin{};
    std::size_t end{};
    std::size_t call_depth{};
    std::vector<std::string> transforms;
};

using Tags = std::unordered_map<xair_value_id, std::vector<Tag>>;

struct OperationRecord {
    xair_function_id function{XAIR_CFG_INVALID_FUNCTION};
    xair_cfg_node_id node{XAIR_CFG_INVALID_ID};
    xair_op_id operation{XAIR_INVALID_ID};
};

struct PathRecord {
    std::vector<xair_cfg_node_id> nodes;
    std::vector<xair_cfg_edge_id> edges;
    std::size_t depth{};
};

std::string lower(std::string_view text) {
    std::string result(text);
    std::transform(result.begin(), result.end(), result.begin(),
        [](const unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return result;
}

std::string trim(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return std::string(text);
}

bool parse_number(std::string_view text, std::uint64_t& value) {
    text = std::string_view(text.data(), text.size());
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    if (text.empty()) return false;
    value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

bool parse_size_value(std::string_view text, std::size_t& value) {
    std::uint64_t parsed = 0;
    if (!parse_number(text, parsed) ||
        parsed > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }
    value = static_cast<std::size_t>(parsed);
    return true;
}

bool starts_selector(std::string_view text) {
    const std::string value = lower(text);
    return value.starts_with("register(") || value.starts_with("buffer(") ||
        value.starts_with("memory(") || value.starts_with("value(") ||
        value.starts_with("funcarg(") || value.starts_with("callarg(") ||
        value.starts_with("callresult@") || value.starts_with("reach@") ||
        value.starts_with("memory-write@");
}

bool split_call(
    std::string_view text,
    std::string_view prefix,
    std::string_view& arguments,
    std::string_view& suffix) {
    if (!lower(text).starts_with(lower(prefix))) return false;
    const std::size_t close = text.find(')', prefix.size());
    if (close == std::string_view::npos) return false;
    arguments = text.substr(prefix.size(), close - prefix.size());
    suffix = text.substr(close + 1);
    return true;
}

bool parse_anchor(std::string_view suffix, std::uint64_t& address, FlowWhen& when) {
    if (suffix.empty() || suffix.front() != '@') return false;
    suffix.remove_prefix(1);
    const std::size_t colon = suffix.rfind(':');
    if (colon != std::string_view::npos) {
        const std::string timing = lower(suffix.substr(colon + 1));
        if (timing == "before") when = FlowWhen::before;
        else if (timing == "after") when = FlowWhen::after;
        else return false;
        suffix = suffix.substr(0, colon);
    }
    return parse_number(suffix, address);
}

std::vector<std::string_view> comma_parts(std::string_view text) {
    std::vector<std::string_view> result;
    std::size_t begin = 0;
    while (begin <= text.size()) {
        const std::size_t comma = text.find(',', begin);
        const std::size_t end = comma == std::string_view::npos ? text.size() : comma;
        result.push_back(text.substr(begin, end - begin));
        if (comma == std::string_view::npos) break;
        begin = comma + 1;
    }
    return result;
}

std::string normalized_register(std::string_view name) {
    std::string value = lower(trim(name));
    if (value == "eax" || value == "ax" || value == "al" || value == "ah") return "rax";
    if (value == "ebx" || value == "bx" || value == "bl" || value == "bh") return "rbx";
    if (value == "ecx" || value == "cx" || value == "cl" || value == "ch") return "rcx";
    if (value == "edx" || value == "dx" || value == "dl" || value == "dh") return "rdx";
    if (value == "esi" || value == "si" || value == "sil") return "rsi";
    if (value == "edi" || value == "di" || value == "dil") return "rdi";
    if (value == "ebp" || value == "bp" || value == "bpl") return "rbp";
    if (value == "esp" || value == "sp" || value == "spl") return "rsp";
    if (value.size() >= 3 && value[0] == 'r' && value.back() == 'd') value.pop_back();
    return value;
}

bool value_is_scalar(const xair_module& module, const xair_value_id value) {
    const xair_type type = xair_value_type(&module, value);
    return (type.kind == XAIR_TYPE_INT || type.kind == XAIR_TYPE_ADDR) && type.bits != 0;
}

bool value_is_propagatable(const xair_module& module, const xair_value_id value) {
    const xair_type type = xair_value_type(&module, value);
    return (type.kind == XAIR_TYPE_INT || type.kind == XAIR_TYPE_ADDR ||
        type.kind == XAIR_TYPE_FLAGS) && type.bits != 0;
}

std::string value_name(const xair_module& module, const xair_value_id value) {
    const char* const name = xair_value_name(&module, value);
    return name == nullptr ? std::string{} : lower(name);
}

std::optional<std::uint64_t> constant_value(
    const xair_module& module,
    const xair_value_id value,
    std::unordered_set<xair_value_id>& active) {
    if (!active.insert(value).second) return std::nullopt;
    xair_op_id operation = XAIR_INVALID_ID;
    if (xair_value_definition(&module, value, &operation) != XAIR_OK) {
        active.erase(value);
        return std::nullopt;
    }
    xair_op_view_v3 op{};
    const xair_value_id* inputs = nullptr;
    std::size_t input_count = 0;
    std::uint64_t low = 0, high = 0;
    std::optional<std::uint64_t> result;
    if (xair_module_get_op_v3(&module, operation, &op) == XAIR_OK &&
        xair_op_inputs(&module, operation, &inputs, &input_count) == XAIR_OK) {
        if ((op.opcode == XAIR_OP_CONST_U64 || op.opcode == XAIR_OP_CONST_WIDE) &&
            xair_op_immediate_wide(&module, operation, &low, &high) == XAIR_OK && high == 0) {
            result = low;
        } else if ((op.opcode == XAIR_OP_ADD || op.opcode == XAIR_OP_ADDR_ADD ||
                    op.opcode == XAIR_OP_SUB || op.opcode == XAIR_OP_ADDR_SUB) &&
                   input_count == 2) {
            const auto lhs = constant_value(module, inputs[0], active);
            const auto rhs = constant_value(module, inputs[1], active);
            if (lhs && rhs) result = (op.opcode == XAIR_OP_SUB || op.opcode == XAIR_OP_ADDR_SUB)
                ? *lhs - *rhs : *lhs + *rhs;
        }
    }
    active.erase(value);
    return result;
}

std::optional<std::uint64_t> constant_value(
    const xair_module& module,
    const xair_value_id value) {
    std::unordered_set<xair_value_id> active;
    return constant_value(module, value, active);
}

std::vector<xair_op_id> operations_at(
    const xair_module& module,
    const xair_cfg& cfg,
    const xair_cfg_node_id node_id,
    const std::uint64_t address) {
    std::vector<xair_op_id> result;
    const xair_cfg_node* const node = xair_cfg_get_node(&cfg, node_id);
    if (node == nullptr || node->ir_block == XAIR_INVALID_ID) return result;
    const xair_op_id* operations = nullptr;
    std::size_t operation_count = 0;
    if (xair_block_ops(&module, node->ir_block, &operations, &operation_count) != XAIR_OK) {
        return result;
    }
    for (std::size_t index = 0; index < operation_count; ++index) {
        const xair_source_id* sources = nullptr;
        std::size_t source_count = 0;
        if (xair_op_sources(&module, operations[index], &sources, &source_count) != XAIR_OK) continue;
        bool matches = false;
        for (std::size_t source_index = 0; source_index < source_count; ++source_index) {
            xair_source_record source{};
            if (xair_module_get_source(&module, sources[source_index], &source) == XAIR_OK &&
                source.location.instruction_va == address) {
                matches = true;
                break;
            }
        }
        if (matches) result.push_back(operations[index]);
    }
    return result;
}

xair_function_id node_owner(const xair_cfg& cfg, const xair_cfg_node_id node) {
    xair_function_id owner = XAIR_CFG_INVALID_FUNCTION;
    return xair_cfg_node_function_owners(&cfg, node, &owner, 1) == 0
        ? XAIR_CFG_INVALID_FUNCTION : owner;
}

std::vector<xair_value_id> function_arguments(
    AnalysisSession& session,
    const xair_function_id function) {
    std::vector<std::pair<std::size_t, xair_value_id>> indexed;
    std::size_t fallback = 0;
    for (const PresentationVariable& variable : session.variable_view(function).variables) {
        if ((variable.roles & variable_role_argument) == 0U ||
            variable.primary_value == XAIR_INVALID_ID) continue;
        std::size_t index = fallback++;
        const std::string name = lower(variable.name.text);
        if (name.starts_with("arg")) {
            std::size_t parsed = 0;
            if (parse_size_value(std::string_view(name).substr(3), parsed)) index = parsed;
        }
        indexed.emplace_back(index, variable.primary_value);
    }
    std::sort(indexed.begin(), indexed.end());
    std::vector<xair_value_id> result;
    for (const auto& item : indexed) result.push_back(item.second);
    return result;
}

std::vector<xair_value_id> function_returns(
    AnalysisSession& session,
    const xair_function_id function) {
    std::vector<xair_value_id> result;
    for (const PresentationVariable& variable : session.variable_view(function).variables) {
        if ((variable.roles & variable_role_return) != 0U &&
            variable.primary_value != XAIR_INVALID_ID) result.push_back(variable.primary_value);
    }
    return result;
}

bool add_tag(
    Tags& tags,
    const xair_value_id value,
    Tag incoming,
    std::size_t& states,
    const std::size_t max_states) {
    if (value == XAIR_INVALID_ID) return false;
    auto& values = tags[value];
    for (Tag& existing : values) {
        if (existing.source != incoming.source || existing.pointer != incoming.pointer ||
            existing.bytes != incoming.bytes) continue;
        const std::size_t old_begin = existing.begin;
        const std::size_t old_end = existing.end;
        const std::size_t old_depth = existing.call_depth;
        existing.begin = std::min(existing.begin, incoming.begin);
        existing.end = std::max(existing.end, incoming.end);
        existing.call_depth = std::min(existing.call_depth, incoming.call_depth);
        existing.exact_offset = existing.exact_offset && incoming.exact_offset &&
            existing.begin == existing.end;
        if (incoming.transforms.size() < existing.transforms.size() || existing.transforms.empty()) {
            existing.transforms = std::move(incoming.transforms);
        }
        return old_begin != existing.begin || old_end != existing.end || old_depth != existing.call_depth;
    }
    if (max_states != 0 && states >= max_states) return false;
    values.push_back(std::move(incoming));
    ++states;
    return true;
}

bool expired(const Clock::time_point started, const std::uint64_t max_time_ms) {
    if (max_time_ms == 0) return false;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - started).count();
    return elapsed >= 0 && static_cast<std::uint64_t>(elapsed) >= max_time_ms;
}

bool stopped(
    DirectedFlowResult& result,
    const FlowOptions& options,
    const Clock::time_point started) {
    if (xair_cancel_token_requested(options.cancellation) != 0) {
        result.completion = FlowCompletion::canceled;
        return true;
    }
    if (expired(started, options.max_time_ms)) {
        result.completion = FlowCompletion::timeout;
        return true;
    }
    if (options.max_states != 0 && result.states >= options.max_states) {
        result.completion = FlowCompletion::limited;
        return true;
    }
    return false;
}

std::string hex_address(const std::uint64_t address) {
    std::ostringstream out;
    out << "0x" << std::hex << address;
    return out.str();
}

ResolvedFlowPoint resolve_point(
    AnalysisSession& session,
    const FlowPointSelector& selector) {
    ResolvedFlowPoint result;
    result.selector = selector;
    const xair_cfg& cfg = session.cfg();
    const xair_module* const module = session.module();
    if (module == nullptr) {
        result.message = "session has no XAIR module";
        return result;
    }

    if (selector.kind == FlowPointKind::xair_value) {
        if (selector.value >= xair_module_value_count(module)) {
            result.message = "XAIR value is outside the module";
            return result;
        }
        result.values.push_back(selector.value);
        xair_op_id definition = XAIR_INVALID_ID;
        if (xair_value_definition(module, selector.value, &definition) == XAIR_OK) {
            result.operation = definition;
            const std::size_t node_count = xair_cfg_node_count(&cfg);
            for (std::size_t index = 0; index < node_count; ++index) {
                const auto node_id = static_cast<xair_cfg_node_id>(index);
                const xair_cfg_node* const node = xair_cfg_get_node(&cfg, node_id);
                if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
                const xair_op_id* operations = nullptr;
                std::size_t count = 0;
                if (xair_block_ops(module, node->ir_block, &operations, &count) != XAIR_OK) continue;
                if (std::find(operations, operations + count, definition) != operations + count) {
                    result.node = node_id;
                    break;
                }
            }
        } else {
            const std::size_t node_count = xair_cfg_node_count(&cfg);
            for (std::size_t index = 0; index < node_count; ++index) {
                const auto node_id = static_cast<xair_cfg_node_id>(index);
                const xair_cfg_node* const node = xair_cfg_get_node(&cfg, node_id);
                if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
                const std::size_t count = xair_block_param_count(module, node->ir_block);
                for (std::size_t parameter = 0; parameter < count; ++parameter) {
                    xair_value_id value = XAIR_INVALID_ID;
                    if (xair_block_param_value(module, node->ir_block, parameter, &value) == XAIR_OK &&
                        value == selector.value) result.node = node_id;
                }
            }
        }
        if (result.node == XAIR_CFG_INVALID_ID) {
            const std::size_t node_count = xair_cfg_node_count(&cfg);
            for (std::size_t index = 0; index < node_count &&
                 result.node == XAIR_CFG_INVALID_ID; ++index) {
                const auto node_id = static_cast<xair_cfg_node_id>(index);
                const xair_cfg_node* const node = xair_cfg_get_node(&cfg, node_id);
                if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
                const xair_op_id* operations = nullptr;
                std::size_t count = 0;
                if (xair_block_ops(module, node->ir_block, &operations, &count) != XAIR_OK) continue;
                for (std::size_t operation_index = 0; operation_index < count; ++operation_index) {
                    const xair_value_id* inputs = nullptr;
                    std::size_t input_count = 0;
                    if (xair_op_inputs(module, operations[operation_index], &inputs,
                            &input_count) == XAIR_OK &&
                        std::find(inputs, inputs + input_count, selector.value) !=
                            inputs + input_count) {
                        result.node = node_id;
                        break;
                    }
                }
            }
        }
        result.function = node_owner(cfg, result.node);
        result.confidence = XAIR_CONFIDENCE_EXACT;
        return result;
    }

    result.node = xair_cfg_find_node_containing(&cfg, selector.address);
    if (result.node == XAIR_CFG_INVALID_ID) {
        result.message = "address is outside the recovered CFG";
        return result;
    }
    result.function = node_owner(cfg, result.node);
    const std::vector<xair_op_id> operations = operations_at(
        *module, cfg, result.node, selector.address);

    if (selector.kind == FlowPointKind::reach) {
        result.confidence = XAIR_CONFIDENCE_EXACT;
        return result;
    }
    if (selector.kind == FlowPointKind::function_argument) {
        const FunctionInfo* const function = session.function_by_address(selector.address);
        if (function == nullptr) {
            result.message = "function argument anchor does not identify a function";
            return result;
        }
        result.function = function->id;
        const auto arguments = function_arguments(session, function->id);
        if (selector.index >= arguments.size()) {
            result.message = "function argument index is unavailable";
            return result;
        }
        result.values.push_back(arguments[selector.index]);
        result.confidence = XAIR_CONFIDENCE_HIGH;
        return result;
    }
    if (operations.empty()) {
        result.message = "no XAIR operation is anchored to the instruction";
        return result;
    }

    if (selector.kind == FlowPointKind::call_argument ||
        selector.kind == FlowPointKind::call_result) {
        for (const xair_op_id operation : operations) {
            xair_op_view_v3 op{};
            if (xair_module_get_op_v3(module, operation, &op) != XAIR_OK ||
                op.opcode != XAIR_OP_CALL) continue;
            result.operation = operation;
            const xair_value_id* values = nullptr;
            std::size_t count = 0;
            const xair_status status = selector.kind == FlowPointKind::call_argument
                ? xair_op_inputs(module, operation, &values, &count)
                : xair_op_results(module, operation, &values, &count);
            if (status != XAIR_OK) continue;
            std::vector<xair_value_id> scalars;
            for (std::size_t index = 0; index < count; ++index) {
                if (value_is_scalar(*module, values[index])) scalars.push_back(values[index]);
            }
            const std::size_t wanted = selector.kind == FlowPointKind::call_result
                ? 0 : selector.index;
            if (wanted < scalars.size()) {
                result.values.push_back(scalars[wanted]);
                result.confidence = XAIR_CONFIDENCE_EXACT;
                return result;
            }
        }
        result.message = selector.kind == FlowPointKind::call_argument
            ? "call argument index is unavailable" : "call has no scalar result";
        return result;
    }

    if (selector.kind == FlowPointKind::register_value ||
        selector.kind == FlowPointKind::buffer) {
        const std::string wanted = normalized_register(selector.register_name);
        for (const xair_op_id operation : operations) {
            const xair_value_id* values = nullptr;
            std::size_t count = 0;
            const xair_status status = selector.when == FlowWhen::before
                ? xair_op_inputs(module, operation, &values, &count)
                : xair_op_results(module, operation, &values, &count);
            if (status != XAIR_OK) continue;
            for (std::size_t index = 0; index < count; ++index) {
                if (normalized_register(value_name(*module, values[index])) == wanted) {
                    result.values.push_back(values[index]);
                }
            }
            if (!result.values.empty()) {
                result.operation = operation;
                result.confidence = XAIR_CONFIDENCE_EXACT;
                return result;
            }
        }
        if (selector.when == FlowWhen::after) {
            for (const xair_op_id operation : operations) {
                const xair_value_id* values = nullptr;
                std::size_t count = 0;
                if (xair_op_results(module, operation, &values, &count) != XAIR_OK) continue;
                for (std::size_t index = 0; index < count; ++index) {
                    if (value_is_scalar(*module, values[index])) result.values.push_back(values[index]);
                }
                if (!result.values.empty()) {
                    result.operation = operation;
                    result.confidence = XAIR_CONFIDENCE_MEDIUM;
                    result.message = "post-state register inferred from instruction results";
                    return result;
                }
            }
        }
        result.message = "register value is not explicit at the instruction anchor";
        return result;
    }

    if (selector.kind == FlowPointKind::memory_write) {
        for (const xair_op_id operation : operations) {
            xair_op_view_v3 op{};
            if (xair_module_get_op_v3(module, operation, &op) != XAIR_OK ||
                op.opcode != XAIR_OP_STORE) continue;
            const xair_value_id* inputs = nullptr;
            std::size_t count = 0;
            if (xair_op_inputs(module, operation, &inputs, &count) != XAIR_OK) continue;
            for (std::size_t index = 0; index < count; ++index) {
                if (value_is_scalar(*module, inputs[index])) result.values.push_back(inputs[index]);
            }
            if (!result.values.empty()) result.values.erase(result.values.begin());
            result.operation = operation;
            result.confidence = XAIR_CONFIDENCE_HIGH;
            return result;
        }
        result.message = "instruction has no XAIR store";
        return result;
    }

    if (selector.kind == FlowPointKind::memory) {
        for (const xair_op_id operation : operations) {
            xair_op_view_v3 op{};
            if (xair_module_get_op_v3(module, operation, &op) != XAIR_OK ||
                op.opcode != XAIR_OP_LOAD) continue;
            const xair_value_id* outputs = nullptr;
            std::size_t count = 0;
            if (xair_op_results(module, operation, &outputs, &count) != XAIR_OK) continue;
            for (std::size_t index = 0; index < count; ++index) {
                if (value_is_scalar(*module, outputs[index])) result.values.push_back(outputs[index]);
            }
            if (!result.values.empty()) result.operation = operation;
        }
        result.confidence = result.values.empty()
            ? XAIR_CONFIDENCE_MEDIUM : XAIR_CONFIDENCE_HIGH;
        if (result.values.empty()) result.message = "no load result is explicit at the memory anchor";
        return result;
    }
    result.message = "unsupported flow point";
    return result;
}

std::vector<OperationRecord> collect_operations(
    const xair_cfg& cfg,
    const xair_module& module) {
    std::vector<OperationRecord> result;
    const std::size_t function_count = xair_cfg_function_count(&cfg);
    for (std::size_t function_index = 0; function_index < function_count; ++function_index) {
        const auto function = static_cast<xair_function_id>(function_index);
        const xair_cfg_node_id* nodes = nullptr;
        std::size_t node_count = 0;
        nodes = xair_cfg_function_nodes(&cfg, function, &node_count);
        for (std::size_t node_index = 0; node_index < node_count; ++node_index) {
            const xair_cfg_node* const node = xair_cfg_get_node(&cfg, nodes[node_index]);
            if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
            const xair_op_id* operations = nullptr;
            std::size_t operation_count = 0;
            if (xair_block_ops(&module, node->ir_block, &operations, &operation_count) != XAIR_OK) {
                continue;
            }
            for (std::size_t operation = 0; operation < operation_count; ++operation) {
                result.push_back({function, nodes[node_index], operations[operation]});
            }
        }
    }
    return result;
}

const FunctionInfo* direct_callee(
    AnalysisSession& session,
    const xair_module& module,
    const xair_op_id operation) {
    xair_op_attributes attributes{};
    if (xair_op_attributes_get(&module, operation, &attributes) != XAIR_OK ||
        attributes.direct_target == 0) return nullptr;
    const FunctionInfo* const function = session.function_by_address(attributes.direct_target);
    return function != nullptr && function->entry == attributes.direct_target ? function : nullptr;
}

void append_transform(Tag& tag, const char* const transform) {
    if (transform == nullptr || tag.transforms.size() >= 12) return;
    if (tag.transforms.empty() || tag.transforms.back() != transform) {
        tag.transforms.emplace_back(transform);
    }
}

std::size_t source_length(
    const std::vector<ResolvedFlowPoint>& sources,
    const std::size_t source) {
    return source < sources.size() ? sources[source].selector.length : 0;
}

bool propagate_operation(
    AnalysisSession& session,
    const OperationRecord& record,
    const std::vector<ResolvedFlowPoint>& sources,
    Tags& tags,
    DirectedFlowResult& result,
    const FlowOptions& options) {
    const xair_module& module = *session.module();
    xair_op_view_v3 op{};
    const xair_value_id* inputs = nullptr;
    const xair_value_id* outputs = nullptr;
    std::size_t input_count = 0, output_count = 0;
    if (xair_module_get_op_v3(&module, record.operation, &op) != XAIR_OK ||
        xair_op_inputs(&module, record.operation, &inputs, &input_count) != XAIR_OK ||
        xair_op_results(&module, record.operation, &outputs, &output_count) != XAIR_OK) {
        return false;
    }
    bool changed = false;

    if (op.opcode == XAIR_OP_CALL) {
        const FunctionInfo* const callee = direct_callee(session, module, record.operation);
        if (callee != nullptr) {
            const auto parameters = function_arguments(session, callee->id);
            std::vector<xair_value_id> scalar_inputs;
            for (std::size_t index = 0; index < input_count; ++index) {
                if (value_is_scalar(module, inputs[index])) scalar_inputs.push_back(inputs[index]);
            }
            const std::size_t count = std::min(parameters.size(), scalar_inputs.size());
            for (std::size_t index = 0; index < count; ++index) {
                const auto found = tags.find(scalar_inputs[index]);
                if (found == tags.end()) continue;
                for (Tag tag : found->second) {
                    if (tag.call_depth >= options.function_depth) continue;
                    ++tag.call_depth;
                    append_transform(tag, "call-argument");
                    result.deepest_call = std::max(result.deepest_call, tag.call_depth);
                    changed = add_tag(tags, parameters[index], std::move(tag), result.states,
                        options.max_states) || changed;
                }
            }

            const auto returns = function_returns(session, callee->id);
            std::vector<xair_value_id> scalar_outputs;
            for (std::size_t index = 0; index < output_count; ++index) {
                if (value_is_scalar(module, outputs[index])) scalar_outputs.push_back(outputs[index]);
            }
            const std::size_t return_count = std::min(returns.size(), scalar_outputs.size());
            for (std::size_t index = 0; index < return_count; ++index) {
                const auto found = tags.find(returns[index]);
                if (found == tags.end()) continue;
                for (Tag tag : found->second) {
                    if (tag.call_depth >= options.function_depth) continue;
                    ++tag.call_depth;
                    append_transform(tag, "call-return");
                    result.deepest_call = std::max(result.deepest_call, tag.call_depth);
                    changed = add_tag(tags, scalar_outputs[index], std::move(tag), result.states,
                        options.max_states) || changed;
                }
            }
            return changed;
        }
        // Unknown and imported calls are conservative summaries: a scalar input
        // may influence a scalar return, but memory-state values are never folded
        // into data taint.
    }

    std::vector<Tag> merged;
    for (std::size_t index = 0; index < input_count; ++index) {
        const auto found = tags.find(inputs[index]);
        if (found == tags.end()) continue;
        merged.insert(merged.end(), found->second.begin(), found->second.end());
    }
    if (merged.empty()) return changed;

    if (op.opcode == XAIR_OP_LOAD) {
        const std::uint16_t width_bits = output_count == 0
            ? 0 : xair_value_type(&module, outputs[0]).bits;
        const std::size_t width = std::max<std::size_t>(1, (width_bits + 7U) / 8U);
        for (Tag& tag : merged) {
            if (!tag.pointer || !tag.bytes) continue;
            tag.pointer = false;
            const std::size_t requested_length = source_length(sources, tag.source);
            const std::size_t length = options.max_taint_bytes == 0
                ? requested_length : std::min(requested_length, options.max_taint_bytes);
            if (tag.exact_offset) {
                const std::size_t maximum = length == 0 ? tag.begin + width - 1 : length - 1;
                tag.end = std::min(maximum, tag.begin + width - 1);
            } else {
                tag.begin = 0;
                tag.end = length == 0 ? width - 1 : length - 1;
            }
            append_transform(tag, "load");
        }
    } else if ((op.opcode == XAIR_OP_ADD || op.opcode == XAIR_OP_ADDR_ADD ||
                op.opcode == XAIR_OP_SUB || op.opcode == XAIR_OP_ADDR_SUB) &&
               input_count == 2) {
        for (Tag& tag : merged) {
            if (!tag.pointer || !tag.bytes) continue;
            std::optional<std::uint64_t> delta;
            bool subtract = false;
            if (tags.contains(inputs[0])) {
                delta = constant_value(module, inputs[1]);
                subtract = op.opcode == XAIR_OP_SUB || op.opcode == XAIR_OP_ADDR_SUB;
            } else if (op.opcode == XAIR_OP_ADD || op.opcode == XAIR_OP_ADDR_ADD) {
                delta = constant_value(module, inputs[0]);
            }
            if (!delta || *delta > static_cast<std::uint64_t>(
                    std::numeric_limits<std::size_t>::max())) {
                tag.exact_offset = false;
            } else {
                const std::size_t amount = static_cast<std::size_t>(*delta);
                if (subtract && amount > tag.begin) tag.exact_offset = false;
                else tag.begin = subtract ? tag.begin - amount : tag.begin + amount;
                tag.end = tag.begin;
            }
            append_transform(tag, xair_opcode_name(op.opcode));
        }
    } else {
        for (Tag& tag : merged) append_transform(tag, xair_opcode_name(op.opcode));
    }

    for (std::size_t output = 0; output < output_count; ++output) {
        if (!value_is_propagatable(module, outputs[output])) continue;
        for (const Tag& tag : merged) {
            changed = add_tag(tags, outputs[output], tag, result.states, options.max_states) || changed;
        }
    }
    return changed;
}

bool propagate_block_arguments(
    const xair_cfg& cfg,
    const xair_module& module,
    Tags& tags,
    DirectedFlowResult& result,
    const FlowOptions& options) {
    bool changed = false;
    const std::size_t node_count = xair_cfg_node_count(&cfg);
    for (std::size_t node_index = 0; node_index < node_count; ++node_index) {
        const auto node_id = static_cast<xair_cfg_node_id>(node_index);
        const xair_cfg_node* const node = xair_cfg_get_node(&cfg, node_id);
        if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
        xair_term_view terminator{};
        if (xair_block_terminator(&module, node->ir_block, &terminator) != XAIR_OK) continue;
        const auto propagate = [&](const xair_block_id target,
                                   const xair_value_id* arguments,
                                   const std::size_t argument_count) {
            if (target == XAIR_INVALID_ID || arguments == nullptr) return;
            const std::size_t parameter_count = xair_block_param_count(&module, target);
            const std::size_t count = std::min(parameter_count, argument_count);
            for (std::size_t index = 0; index < count; ++index) {
                const auto found = tags.find(arguments[index]);
                if (found == tags.end()) continue;
                xair_value_id parameter = XAIR_INVALID_ID;
                if (xair_block_param_value(&module, target, index, &parameter) != XAIR_OK) continue;
                for (Tag tag : found->second) {
                    append_transform(tag, "phi");
                    changed = add_tag(tags, parameter, std::move(tag), result.states,
                        options.max_states) || changed;
                }
            }
        };
        propagate(terminator.true_target, terminator.true_args, terminator.true_arg_count);
        propagate(terminator.false_target, terminator.false_args, terminator.false_arg_count);
    }
    return changed;
}

void seed_absolute_memory(
    const xair_module& module,
    const std::vector<OperationRecord>& operations,
    const std::vector<ResolvedFlowPoint>& sources,
    Tags& tags,
    DirectedFlowResult& result,
    const FlowOptions& options) {
    for (std::size_t source_index = 0; source_index < sources.size(); ++source_index) {
        const FlowPointSelector& selector = sources[source_index].selector;
        if (selector.kind != FlowPointKind::memory) continue;
        for (const OperationRecord& record : operations) {
            xair_op_view_v3 op{};
            const xair_value_id* inputs = nullptr;
            const xair_value_id* outputs = nullptr;
            std::size_t input_count = 0, output_count = 0;
            if (xair_module_get_op_v3(&module, record.operation, &op) != XAIR_OK ||
                op.opcode != XAIR_OP_LOAD ||
                xair_op_inputs(&module, record.operation, &inputs, &input_count) != XAIR_OK ||
                xair_op_results(&module, record.operation, &outputs, &output_count) != XAIR_OK) continue;
            std::optional<std::uint64_t> address;
            for (std::size_t input = 0; input < input_count; ++input) {
                if (value_is_scalar(module, inputs[input])) {
                    const auto candidate = constant_value(module, inputs[input]);
                    if (candidate) address = candidate;
                }
            }
            const std::uint64_t available = std::numeric_limits<std::uint64_t>::max() -
                selector.memory_address;
            const std::uint64_t end = selector.memory_address +
                std::min<std::uint64_t>(selector.length, available);
            if (!address || *address < selector.memory_address || *address >= end) continue;
            for (std::size_t output = 0; output < output_count; ++output) {
                if (!value_is_scalar(module, outputs[output])) continue;
                const std::size_t begin = static_cast<std::size_t>(*address - selector.memory_address);
                const std::size_t width = std::max<std::size_t>(1,
                    (xair_value_type(&module, outputs[output]).bits + 7U) / 8U);
                Tag tag{source_index, true, false, true, begin,
                    std::min(selector.length - 1, begin + width - 1), 0, {"load"}};
                (void)add_tag(tags, outputs[output], std::move(tag), result.states,
                    options.max_states);
            }
        }
    }
}

std::vector<PathRecord> find_paths(
    const xair_cfg& cfg,
    const xair_cfg_node_id start,
    const xair_cfg_node_id goal,
    const FlowOptions& options,
    DirectedFlowResult& result,
    const Clock::time_point started) {
    std::vector<PathRecord> found;
    if (start == XAIR_CFG_INVALID_ID || goal == XAIR_CFG_INVALID_ID) return found;
    const std::size_t node_count = xair_cfg_node_count(&cfg);
    if (node_count == 0) return found;
    struct Item {
        xair_cfg_node_id node{XAIR_CFG_INVALID_ID};
        std::vector<xair_cfg_node_id> return_stack;
        PathRecord path;
        std::size_t current_depth{};
        std::vector<std::uint64_t> history;
    };
    std::queue<Item> queue;
    Item initial;
    initial.node = start;
    initial.path.nodes.push_back(start);
    initial.history.push_back(start);
    queue.push(std::move(initial));
    const std::size_t path_limit = options.max_paths == 0
        ? std::max<std::size_t>(1, options.max_states) : options.max_paths;
    std::size_t search_states = 0;
    while (!queue.empty()) {
        if (xair_cancel_token_requested(options.cancellation) != 0 ||
            expired(started, options.max_time_ms)) break;
        if (options.max_states != 0 && search_states >= options.max_states) {
            if (result.completion == FlowCompletion::complete) {
                result.completion = FlowCompletion::limited;
            }
            break;
        }
        Item item = std::move(queue.front());
        queue.pop();
        ++search_states;
        if (item.node == goal) {
            found.push_back(std::move(item.path));
            if (found.size() >= path_limit) break;
            continue;
        }
        std::size_t edge_count = 0;
        const xair_cfg_edge* const edges = xair_cfg_node_edges(&cfg, item.node, &edge_count);
        const xair_cfg_node* const node = xair_cfg_get_node(&cfg, item.node);
        if (edges == nullptr || node == nullptr) continue;
        xair_cfg_node_id continuation = XAIR_CFG_INVALID_ID;
        for (std::size_t index = 0; index < edge_count; ++index) {
            if (edges[index].kind == XAIR_EDGE_CALL_RETURN) {
                continuation = edges[index].dst;
                break;
            }
        }
        for (std::size_t index = 0; index < edge_count; ++index) {
            Item next = item;
            xair_cfg_node_id destination = edges[index].dst;
            if (edges[index].kind == XAIR_EDGE_CALL ||
                edges[index].kind == XAIR_EDGE_INDIRECT_CALL) {
                if (next.current_depth >= options.function_depth) continue;
                ++next.current_depth;
                next.path.depth = std::max(next.path.depth, next.current_depth);
                next.return_stack.push_back(continuation);
            } else if (edges[index].kind == XAIR_EDGE_TAILCALL) {
                if (next.current_depth >= options.function_depth) continue;
                ++next.current_depth;
                next.path.depth = std::max(next.path.depth, next.current_depth);
            } else if (edges[index].kind == XAIR_EDGE_RETURN &&
                       !next.return_stack.empty()) {
                destination = next.return_stack.back();
                next.return_stack.pop_back();
                if (next.current_depth != 0) --next.current_depth;
            }
            if (destination == XAIR_CFG_INVALID_ID ||
                static_cast<std::size_t>(destination) >= node_count) continue;
            const std::uint64_t context_key =
                static_cast<std::uint64_t>(next.current_depth) * node_count + destination;
            if (std::find(next.history.begin(), next.history.end(), context_key) !=
                next.history.end()) continue;
            next.history.push_back(context_key);
            next.node = destination;
            next.path.nodes.push_back(destination);
            next.path.edges.push_back(
                node->edge_offset + static_cast<xair_cfg_edge_id>(index));
            queue.push(std::move(next));
        }
    }
    for (const PathRecord& path : found) {
        result.deepest_call = std::max(result.deepest_call, path.depth);
    }
    return found;
}

class Translator {
public:
    Translator(
        const xair_module& module,
        xair_sym_context& context,
        std::unordered_map<xair_value_id, xair_sym_expr_id> overrides)
        : module_(module), context_(context), cache_(std::move(overrides)) {}

    std::optional<xair_sym_expr_id> value(const xair_value_id id) {
        if (const auto found = cache_.find(id); found != cache_.end()) return found->second;
        if (!active_.insert(id).second) return std::nullopt;
        xair_op_id operation = XAIR_INVALID_ID;
        xair_sym_expr_id result = XAIR_SYM_INVALID_ID;
        const xair_type type = xair_value_type(&module_, id);
        if (type.bits == 0) {
            failure_ = "v" + std::to_string(id) + " has a zero-width XAIR type";
            active_.erase(id);
            return std::nullopt;
        }
        if (xair_value_definition(&module_, id, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID) {
            const std::string name = "xair_v" + std::to_string(id);
            if (xair_sym_symbol(&context_, type.bits, name.c_str(), &result) != XAIR_SYM_OK) {
                failure_ = "could not create fallback symbol for v" + std::to_string(id);
                active_.erase(id);
                return std::nullopt;
            }
        } else {
            xair_op_view_v3 op{};
            const xair_value_id* inputs = nullptr;
            std::size_t input_count = 0;
            std::uint64_t low = 0, high = 0;
            if (xair_module_get_op_v3(&module_, operation, &op) != XAIR_OK ||
                xair_op_inputs(&module_, operation, &inputs, &input_count) != XAIR_OK) {
                failure_ = "could not read definition for v" + std::to_string(id);
                active_.erase(id);
                return std::nullopt;
            }
            if ((op.opcode == XAIR_OP_CONST_U64 || op.opcode == XAIR_OP_CONST_WIDE) &&
                xair_op_immediate_wide(&module_, operation, &low, &high) == XAIR_OK) {
                if (xair_sym_const_wide(&context_, type.bits, low, high, &result) != XAIR_SYM_OK) {
                    failure_ = "could not translate constant v" + std::to_string(id);
                    active_.erase(id);
                    return std::nullopt;
                }
            } else if (input_count == 1) {
                const auto source = value(inputs[0]);
                const xair_sym_status status = source
                    ? xair_sym_unary(&context_, op.opcode, type.bits, *source, 0, &result)
                    : XAIR_SYM_ERR_UNSUPPORTED;
                if (!source || status != XAIR_SYM_OK) {
                    if (source) failure_ = "v" + std::to_string(id) + " " +
                        xair_opcode_name(op.opcode) + " unary status=" +
                        xair_sym_status_name(status);
                    active_.erase(id);
                    return std::nullopt;
                }
            } else if (input_count == 2) {
                const auto left = value(inputs[0]);
                const auto right = value(inputs[1]);
                const xair_sym_status status = left && right
                    ? xair_sym_binary(&context_, op.opcode, type.bits, *left, *right, &result)
                    : XAIR_SYM_ERR_UNSUPPORTED;
                if (!left || !right || status != XAIR_SYM_OK) {
                    if (left && right) failure_ = "v" + std::to_string(id) + " " +
                        xair_opcode_name(op.opcode) + " binary status=" +
                        xair_sym_status_name(status) + " bits=" + std::to_string(type.bits);
                    active_.erase(id);
                    return std::nullopt;
                }
            } else if (op.opcode == XAIR_OP_SELECT && input_count == 3) {
                const auto condition = value(inputs[0]);
                const auto yes = value(inputs[1]);
                const auto no = value(inputs[2]);
                if (!condition || !yes || !no ||
                    xair_sym_select(&context_, *condition, *yes, *no, &result) != XAIR_SYM_OK) {
                    active_.erase(id);
                    return std::nullopt;
                }
            } else {
                const std::string name = "xair_v" + std::to_string(id);
                if (xair_sym_symbol(&context_, type.bits, name.c_str(), &result) != XAIR_SYM_OK) {
                    active_.erase(id);
                    return std::nullopt;
                }
            }
        }
        active_.erase(id);
        cache_[id] = result;
        return result;
    }

    [[nodiscard]] const std::string& failure() const noexcept { return failure_; }

private:
    const xair_module& module_;
    xair_sym_context& context_;
    std::unordered_map<xair_value_id, xair_sym_expr_id> cache_;
    std::unordered_set<xair_value_id> active_;
    std::string failure_;
};

struct SymbolRecord {
    std::size_t source{};
    xair_sym_expr_id scalar{XAIR_SYM_INVALID_ID};
    std::size_t byte_begin{};
    std::vector<xair_sym_expr_id> bytes;
};

std::optional<xair_sym_expr_id> concat_bytes(
    xair_sym_context& context,
    const std::vector<xair_sym_expr_id>& bytes) {
    if (bytes.empty()) return std::nullopt;
    xair_sym_expr_id result = bytes.back();
    std::uint16_t bits = 8;
    for (std::size_t index = bytes.size() - 1; index > 0; --index) {
        bits = static_cast<std::uint16_t>(bits + 8U);
        if (xair_sym_binary(&context, XAIR_OP_CONCAT, bits, result, bytes[index - 1],
                &result) != XAIR_SYM_OK) return std::nullopt;
    }
    return result;
}

bool tag_for_source(const Tags& tags, const xair_value_id value, const std::size_t source) {
    const auto found = tags.find(value);
    if (found == tags.end()) return false;
    return std::any_of(found->second.begin(), found->second.end(),
        [source](const Tag& tag) { return tag.source == source; });
}

void materialize_path(
    AnalysisSession& session,
    const PathRecord& path,
    DirectedFlowResult& result) {
    result.path.clear();
    for (std::size_t index = 0; index < path.nodes.size(); ++index) {
        FlowPathStep step;
        step.node = path.nodes[index];
        const xair_cfg_node* const node = xair_cfg_get_node(&session.cfg(), step.node);
        if (node != nullptr) step.address = node->start;
        if (index != 0 && index - 1 < path.edges.size()) {
            const xair_cfg_edge* const edge = xair_cfg_get_edge(&session.cfg(), path.edges[index - 1]);
            if (edge != nullptr) {
                step.edge = xair_cfg_edge_kind_name(edge->kind);
                if (edge->condition != XAIR_INVALID_ID) {
                    step.condition = session.expression_view(edge->condition).text;
                }
            }
        }
        result.path.push_back(std::move(step));
    }
}

void run_symbolic(
    AnalysisSession& session,
    const PathRecord& path,
    const Tags& tags,
    DirectedFlowResult& result,
    const FlowOptions& options) {
    if (options.max_queries != 0 && result.queries >= options.max_queries) {
        result.completion = FlowCompletion::limited;
        return;
    }
    SessionDiagnostic diagnostic;
    xair_sym_context* const context = session.symbolic_context(&diagnostic);
    if (context == nullptr) {
        result.completion = FlowCompletion::unknown;
        result.diagnostic = diagnostic.message;
        return;
    }
    const xair_cfg_node* const start_node = xair_cfg_get_node(&session.cfg(), path.nodes.front());
    if (start_node == nullptr || start_node->ir_block == XAIR_INVALID_ID) {
        result.completion = FlowCompletion::unknown;
        result.diagnostic = "symbolic path has no XAIR entry block";
        return;
    }
    xair_analysis_options analysis{};
    xair_analysis_options_init(&analysis);
    analysis.max_wall_time = options.max_time_ms;
    analysis.cancel_token = options.cancellation;
    xair_sym_context_set_analysis_options(context, &analysis);

    std::unordered_map<xair_value_id, xair_sym_expr_id> overrides;
    std::vector<SymbolRecord> symbols;
    const xair_module& module = *session.module();
    for (std::size_t source_index = 0; source_index < result.sources.size(); ++source_index) {
        const ResolvedFlowPoint& source = result.sources[source_index];
        if (source.selector.kind == FlowPointKind::buffer ||
            source.selector.kind == FlowPointKind::memory) continue;
        SymbolRecord record;
        record.source = source_index;
        for (const xair_value_id value : source.values) {
            const xair_type type = xair_value_type(&module, value);
            if (type.bits == 0) continue;
            const std::string name = source.selector.name + "_v" + std::to_string(value);
            xair_sym_expr_id symbol = XAIR_SYM_INVALID_ID;
            if (xair_sym_symbol(context, type.bits, name.c_str(), &symbol) != XAIR_SYM_OK) continue;
            overrides[value] = symbol;
            if (record.scalar == XAIR_SYM_INVALID_ID) record.scalar = symbol;
        }
        if (record.scalar != XAIR_SYM_INVALID_ID) symbols.push_back(std::move(record));
    }

    // Only bytes proven relevant by taint are symbolized. Each load receives a
    // little-endian concatenation of those independent byte symbols.
    std::unordered_map<std::uint64_t, xair_sym_expr_id> byte_symbols;
    const std::size_t value_count = xair_module_value_count(&module);
    for (std::size_t value_index = 0; value_index < value_count; ++value_index) {
        const auto value = static_cast<xair_value_id>(value_index);
        xair_op_id definition = XAIR_INVALID_ID;
        xair_op_view_v3 op{};
        if (xair_value_definition(&module, value, &definition) != XAIR_OK ||
            xair_module_get_op_v3(&module, definition, &op) != XAIR_OK ||
            op.opcode != XAIR_OP_LOAD) continue;
        const auto found = tags.find(value);
        if (found == tags.end()) continue;
        for (const Tag& tag : found->second) {
            if (!tag.bytes || tag.pointer || tag.source >= result.sources.size()) continue;
            const std::size_t count = tag.end >= tag.begin ? tag.end - tag.begin + 1 : 0;
            if (count == 0 ||
                (options.max_symbolic_bytes != 0 && count > options.max_symbolic_bytes)) continue;
            std::vector<xair_sym_expr_id> bytes;
            for (std::size_t offset = tag.begin; offset <= tag.end; ++offset) {
                const std::uint64_t key = (static_cast<std::uint64_t>(tag.source) << 32U) |
                    static_cast<std::uint64_t>(offset);
                auto existing = byte_symbols.find(key);
                if (existing == byte_symbols.end()) {
                    const std::string name = result.sources[tag.source].selector.name + "_byte_" +
                        std::to_string(offset);
                    xair_sym_expr_id symbol = XAIR_SYM_INVALID_ID;
                    if (xair_sym_symbol(context, 8, name.c_str(), &symbol) != XAIR_SYM_OK) break;
                    existing = byte_symbols.emplace(key, symbol).first;
                }
                bytes.push_back(existing->second);
            }
            const auto expression = concat_bytes(*context, bytes);
            if (expression) overrides[value] = *expression;
        }
    }
    for (std::size_t source_index = 0; source_index < result.sources.size(); ++source_index) {
        std::vector<std::pair<std::size_t, xair_sym_expr_id>> ordered;
        for (const auto& [key, symbol] : byte_symbols) {
            if (static_cast<std::size_t>(key >> 32U) == source_index) {
                ordered.emplace_back(static_cast<std::size_t>(key & UINT64_C(0xffffffff)), symbol);
            }
        }
        if (ordered.empty()) continue;
        std::sort(ordered.begin(), ordered.end());
        SymbolRecord record;
        record.source = source_index;
        record.byte_begin = ordered.front().first;
        for (const auto& item : ordered) record.bytes.push_back(item.second);
        symbols.push_back(std::move(record));
    }

    xair_sym_state* state = nullptr;
    if (xair_sym_state_create(context, &module, start_node->ir_block, &state) != XAIR_SYM_OK) {
        result.completion = FlowCompletion::unknown;
        result.diagnostic = "xair_sym could not create a path state";
        return;
    }
    Translator translator(module, *context, std::move(overrides));
    bool supported = true;
    for (const xair_cfg_edge_id edge_id : path.edges) {
        const xair_cfg_edge* const edge = xair_cfg_get_edge(&session.cfg(), edge_id);
        if (edge == nullptr || edge->condition == XAIR_INVALID_ID) continue;
        auto condition = translator.value(edge->condition);
        if (!condition) {
            supported = false;
            result.diagnostic = "could not translate path condition v" +
                std::to_string(edge->condition) + ": " + translator.failure();
            break;
        }
        std::string text = session.expression_view(edge->condition).text;
        if (edge->kind == XAIR_EDGE_CBRANCH_FALSE) {
            xair_sym_expr_id zero = XAIR_SYM_INVALID_ID;
            xair_sym_expr_id negated = XAIR_SYM_INVALID_ID;
            const std::uint16_t bits = xair_value_type(&module, edge->condition).bits;
            if (xair_sym_const(context, bits, 0, &zero) != XAIR_SYM_OK ||
                xair_sym_binary(context, XAIR_OP_EQ, 1, *condition, zero, &negated) != XAIR_SYM_OK) {
                supported = false;
                result.diagnostic = "could not negate path condition v" +
                    std::to_string(edge->condition);
                break;
            }
            condition = negated;
            text = "not (" + text + ')';
        }
        if (xair_sym_state_assume(state, *condition) != XAIR_SYM_OK) {
            supported = false;
            result.diagnostic = "could not assume path condition v" +
                std::to_string(edge->condition);
            break;
        }
        result.constraints.push_back(std::move(text));
        for (std::size_t source = 0; source < result.sources.size(); ++source) {
            if (tag_for_source(tags, edge->condition, source)) result.source_constrained = true;
        }
    }
    if (!supported) {
        result.completion = FlowCompletion::unknown;
        if (result.diagnostic.empty()) {
            result.diagnostic = "a path condition could not be translated to xair_sym";
        }
        xair_sym_state_destroy(state);
        result.solver_initialized = xair_sym_context_solver_initialized(context) != 0;
        return;
    }

    xair_sym_sat sat = XAIR_SYM_UNKNOWN;
    const xair_sym_status check = xair_sym_check(state, XAIR_SYM_INVALID_ID, &sat);
    ++result.queries;
    if (check == XAIR_SYM_ERR_SOLVER_TIMEOUT) {
        result.completion = FlowCompletion::timeout;
        result.verdict = FlowVerdict::unknown;
    } else if (check != XAIR_SYM_OK || sat == XAIR_SYM_UNKNOWN) {
        result.completion = FlowCompletion::unknown;
        result.verdict = FlowVerdict::unknown;
        result.diagnostic = xair_sym_status_name(check);
    } else if (sat == XAIR_SYM_UNSAT) {
        result.verdict = FlowVerdict::infeasible;
    } else {
        result.verdict = FlowVerdict::feasible_flow;
        for (const SymbolRecord& symbol : symbols) {
            FlowWitness witness;
            witness.source = symbol.source;
            if (symbol.scalar != XAIR_SYM_INVALID_ID &&
                xair_sym_model_u64(state, symbol.scalar, &witness.scalar) == XAIR_SYM_OK) {
                result.witnesses.push_back(std::move(witness));
            } else if (!symbol.bytes.empty()) {
                witness.byte_values = true;
                witness.offset_begin = symbol.byte_begin;
                witness.bytes.resize(symbol.bytes.size());
                if (xair_sym_model_bytes(state, symbol.bytes.data(), symbol.bytes.size(),
                        witness.bytes.data()) == XAIR_SYM_OK) {
                    result.witnesses.push_back(std::move(witness));
                }
            }
        }
    }
    result.solver_initialized = xair_sym_context_solver_initialized(context) != 0;
    xair_sym_state_destroy(state);
}

void json_string(std::ostream& out, std::string_view value) {
    out << '"';
    for (const unsigned char character : value) {
        switch (character) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (character < 0x20U) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned int>(character) << std::dec << std::setfill(' ');
            } else out << static_cast<char>(character);
        }
    }
    out << '"';
}

const char* confidence_name(const xair_confidence confidence) {
    switch (confidence) {
    case XAIR_CONFIDENCE_EXACT: return "exact";
    case XAIR_CONFIDENCE_HIGH: return "high";
    case XAIR_CONFIDENCE_MEDIUM: return "medium";
    case XAIR_CONFIDENCE_LOW: return "low";
    case XAIR_CONFIDENCE_UNKNOWN:
    default: return "unknown";
    }
}

} // namespace

bool parse_flow_point(
    const std::string_view text,
    const bool target,
    FlowPointSelector& selector,
    std::string& diagnostic) {
    selector = {};
    selector.raw = std::string(text);
    std::string_view body = text;
    const std::size_t equals = body.find('=');
    if (equals != std::string_view::npos && starts_selector(body.substr(equals + 1))) {
        selector.name = trim(body.substr(0, equals));
        body.remove_prefix(equals + 1);
    }
    if (selector.name.empty()) selector.name = target ? "target" : "source";
    std::string_view arguments;
    std::string_view suffix;
    if (split_call(body, "register(", arguments, suffix)) {
        selector.kind = FlowPointKind::register_value;
        selector.register_name = trim(arguments);
        if (selector.register_name.empty() ||
            !parse_anchor(suffix, selector.address, selector.when)) {
            diagnostic = "register selector must be register(NAME)@ADDRESS[:before|after]";
            return false;
        }
        return true;
    }
    if (split_call(body, "buffer(", arguments, suffix)) {
        selector.kind = FlowPointKind::buffer;
        const auto parts = comma_parts(arguments);
        if (parts.size() != 2) {
            diagnostic = "buffer selector must be buffer(REGISTER,LENGTH)@ADDRESS[:before|after]";
            return false;
        }
        selector.register_name = trim(parts[0]);
        if (selector.register_name.empty() || !parse_size_value(trim(parts[1]), selector.length) ||
            selector.length == 0 || !parse_anchor(suffix, selector.address, selector.when)) {
            diagnostic = "buffer selector has an invalid register, length, address, or timing";
            return false;
        }
        return true;
    }
    if (split_call(body, "memory(", arguments, suffix)) {
        selector.kind = FlowPointKind::memory;
        const auto parts = comma_parts(arguments);
        if (parts.size() != 2 || !parse_number(trim(parts[0]), selector.memory_address) ||
            !parse_size_value(trim(parts[1]), selector.length) || selector.length == 0 ||
            !parse_anchor(suffix, selector.address, selector.when)) {
            diagnostic = "memory selector must be memory(ADDRESS,LENGTH)@INSTRUCTION[:before|after]";
            return false;
        }
        return true;
    }
    if (split_call(body, "value(", arguments, suffix)) {
        selector.kind = FlowPointKind::xair_value;
        std::string value_text = trim(arguments);
        if (!value_text.empty() && (value_text.front() == 'v' || value_text.front() == 'V')) {
            value_text.erase(value_text.begin());
        }
        std::uint64_t value = 0;
        if (!suffix.empty() || !parse_number(value_text, value) ||
            value >= static_cast<std::uint64_t>(XAIR_INVALID_ID)) {
            diagnostic = "value selector must be value(VALUE-ID)";
            return false;
        }
        selector.value = static_cast<xair_value_id>(value);
        return true;
    }
    if (split_call(body, "funcarg(", arguments, suffix)) {
        selector.kind = FlowPointKind::function_argument;
        if (!parse_size_value(trim(arguments), selector.index) ||
            !parse_anchor(suffix, selector.address, selector.when)) {
            diagnostic = "function argument selector must be funcarg(INDEX)@FUNCTION";
            return false;
        }
        return true;
    }
    if (split_call(body, "callarg(", arguments, suffix)) {
        selector.kind = FlowPointKind::call_argument;
        if (!parse_size_value(trim(arguments), selector.index) ||
            !parse_anchor(suffix, selector.address, selector.when)) {
            diagnostic = "call argument selector must be callarg(INDEX)@CALL";
            return false;
        }
        return true;
    }
    const std::string lowered = lower(body);
    if (lowered.starts_with("callresult@")) {
        selector.kind = FlowPointKind::call_result;
        selector.when = FlowWhen::after;
        if (!parse_anchor(body.substr(std::string_view("callresult").size()),
                selector.address, selector.when)) {
            diagnostic = "call result selector must be callresult@CALL";
            return false;
        }
        return true;
    }
    if (lowered.starts_with("reach@")) {
        if (!target) {
            diagnostic = "reach is a target-only selector";
            return false;
        }
        selector.kind = FlowPointKind::reach;
        if (!parse_anchor(body.substr(std::string_view("reach").size()),
                selector.address, selector.when)) {
            diagnostic = "reach selector must be reach@ADDRESS";
            return false;
        }
        return true;
    }
    if (lowered.starts_with("memory-write@")) {
        if (!target) {
            diagnostic = "memory-write is a target-only selector";
            return false;
        }
        selector.kind = FlowPointKind::memory_write;
        if (!parse_anchor(body.substr(std::string_view("memory-write").size()),
                selector.address, selector.when)) {
            diagnostic = "memory-write selector must be memory-write@ADDRESS";
            return false;
        }
        return true;
    }
    diagnostic = "unknown flow selector; expected register, buffer, memory, value, funcarg, "
        "callarg, callresult, reach, or memory-write";
    return false;
}

DirectedFlowResult directed_flow(
    AnalysisSession& session,
    const std::vector<FlowPointSelector>& source_selectors,
    const std::vector<FlowPointSelector>& target_selectors,
    const FlowOptions& options) {
    DirectedFlowResult result;
    result.mode = options.mode;
    result.function_depth = options.function_depth;
    const Clock::time_point started = Clock::now();
    if (source_selectors.empty() || target_selectors.empty() || session.module() == nullptr) {
        result.status = XAIR_ERR_BAD_ARG;
        result.completion = FlowCompletion::failed;
        result.diagnostic = "flow requires at least one source and target over a XAIR module";
        return result;
    }
    for (const FlowPointSelector& selector : source_selectors) {
        result.sources.push_back(resolve_point(session, selector));
        if ((selector.kind == FlowPointKind::buffer || selector.kind == FlowPointKind::memory) &&
            options.max_taint_bytes != 0 && selector.length > options.max_taint_bytes) {
            result.completion = FlowCompletion::limited;
        }
    }
    for (const FlowPointSelector& selector : target_selectors) {
        result.targets.push_back(resolve_point(session, selector));
    }
    const auto unresolved = [](const ResolvedFlowPoint& point) {
        return point.node == XAIR_CFG_INVALID_ID ||
            (point.values.empty() && point.selector.kind != FlowPointKind::reach &&
             point.selector.kind != FlowPointKind::memory);
    };
    const auto bad_source = std::find_if(result.sources.begin(), result.sources.end(), unresolved);
    const auto bad_target = std::find_if(result.targets.begin(), result.targets.end(),
        [](const ResolvedFlowPoint& point) {
            return point.node == XAIR_CFG_INVALID_ID ||
                (point.values.empty() && point.selector.kind != FlowPointKind::reach);
        });
    if (bad_source != result.sources.end() || bad_target != result.targets.end()) {
        const ResolvedFlowPoint& bad = bad_source != result.sources.end() ? *bad_source : *bad_target;
        result.status = XAIR_ERR_RANGE;
        result.completion = FlowCompletion::failed;
        result.diagnostic = bad.selector.raw + ": " + bad.message;
        return result;
    }

    Tags tags;
    for (std::size_t source_index = 0; source_index < result.sources.size(); ++source_index) {
        const ResolvedFlowPoint& source = result.sources[source_index];
        if (source.selector.kind == FlowPointKind::memory) continue;
        for (const xair_value_id value : source.values) {
            Tag tag;
            tag.source = source_index;
            tag.call_depth = 0;
            if (source.selector.kind == FlowPointKind::buffer) {
                tag.bytes = true;
                tag.pointer = true;
                tag.exact_offset = true;
            }
            (void)add_tag(tags, value, std::move(tag), result.states, options.max_states);
        }
    }
    const std::vector<OperationRecord> operations = collect_operations(
        session.cfg(), *session.module());
    seed_absolute_memory(*session.module(), operations, result.sources, tags, result, options);

    bool changed = true;
    while (changed && !stopped(result, options, started)) {
        changed = false;
        for (const OperationRecord& operation : operations) {
            changed = propagate_operation(session, operation, result.sources, tags, result,
                options) || changed;
            if (stopped(result, options, started)) break;
        }
        if (!stopped(result, options, started)) {
            changed = propagate_block_arguments(session.cfg(), *session.module(), tags, result,
                options) || changed;
        }
    }

    for (std::size_t target_index = 0; target_index < result.targets.size(); ++target_index) {
        const ResolvedFlowPoint& target = result.targets[target_index];
        if (target.selector.kind == FlowPointKind::reach) continue;
        for (const xair_value_id value : target.values) {
            const auto found = tags.find(value);
            if (found == tags.end()) continue;
            for (const Tag& tag : found->second) {
                FlowInfluence influence;
                influence.source = tag.source;
                influence.target = target_index;
                influence.byte_range = tag.bytes && !tag.pointer;
                influence.offset_begin = tag.begin;
                influence.offset_end = tag.end;
                influence.call_depth = tag.call_depth;
                influence.transforms = tag.transforms;
                result.influences.push_back(std::move(influence));
            }
        }
    }

    struct CandidatePath {
        PathRecord path;
        std::size_t source{};
        std::size_t target{};
    };
    std::vector<CandidatePath> candidate_paths;
    const std::size_t path_limit = options.max_paths == 0
        ? std::max<std::size_t>(1, options.max_states) : options.max_paths;
    for (std::size_t source_index = 0;
         source_index < result.sources.size() && candidate_paths.size() < path_limit;
         ++source_index) {
        for (std::size_t target_index = 0;
             target_index < result.targets.size() && candidate_paths.size() < path_limit;
             ++target_index) {
            FlowOptions search_options = options;
            search_options.max_paths = path_limit - candidate_paths.size();
            const std::vector<PathRecord> paths = find_paths(
                session.cfg(), result.sources[source_index].node,
                result.targets[target_index].node, search_options, result, started);
            for (const PathRecord& path : paths) {
                if (result.targets[target_index].selector.kind == FlowPointKind::reach &&
                    options.mode != FlowMode::symbolic) {
                    bool controls = false;
                    for (const xair_cfg_edge_id edge_id : path.edges) {
                        const xair_cfg_edge* const edge =
                            xair_cfg_get_edge(&session.cfg(), edge_id);
                        if (edge != nullptr && edge->condition != XAIR_INVALID_ID &&
                            tag_for_source(tags, edge->condition, source_index)) {
                            controls = true;
                        }
                    }
                    if (controls) {
                        const bool already = std::any_of(
                            result.influences.begin(), result.influences.end(),
                            [source_index, target_index](const FlowInfluence& item) {
                                return item.source == source_index &&
                                    item.target == target_index &&
                                    std::find(item.transforms.begin(), item.transforms.end(),
                                        "control-dependency") != item.transforms.end();
                            });
                        if (!already) {
                            FlowInfluence influence;
                            influence.source = source_index;
                            influence.target = target_index;
                            influence.call_depth = path.depth;
                            influence.transforms.push_back("control-dependency");
                            result.influences.push_back(std::move(influence));
                        }
                    }
                }
                const bool pair_influences = std::any_of(
                    result.influences.begin(), result.influences.end(),
                    [source_index, target_index](const FlowInfluence& item) {
                        return item.source == source_index && item.target == target_index;
                    });
                if (options.mode == FlowMode::symbolic || pair_influences) {
                    candidate_paths.push_back({path, source_index, target_index});
                    if (candidate_paths.size() >= path_limit) break;
                }
            }
        }
    }

    if (result.completion == FlowCompletion::complete && !session.completeness().complete) {
        result.completion = FlowCompletion::unknown;
    }
    if (options.mode == FlowMode::taint) result.paths = candidate_paths.size();
    if (options.mode == FlowMode::taint) {
        result.verdict = !result.influences.empty() ? FlowVerdict::may_flow :
            result.completion == FlowCompletion::complete ? FlowVerdict::no_flow : FlowVerdict::unknown;
    } else if (options.mode == FlowMode::taint_symbolic && result.influences.empty()) {
        result.verdict = result.completion == FlowCompletion::complete
            ? FlowVerdict::no_flow : FlowVerdict::unknown;
    } else if (candidate_paths.empty()) {
        if (options.mode == FlowMode::taint_symbolic && !result.influences.empty()) {
            result.verdict = FlowVerdict::unknown;
            result.completion = FlowCompletion::unknown;
            result.diagnostic = "taint reached the target, but no bounded context-sensitive "
                "CFG path was available for symbolic verification";
        } else {
            result.verdict = result.completion == FlowCompletion::complete
                ? FlowVerdict::infeasible : FlowVerdict::unknown;
        }
    } else {
        bool saw_unknown = false;
        bool feasible = false;
        std::size_t checked_paths = 0;
        for (const CandidatePath& candidate : candidate_paths) {
            if (stopped(result, options, started) ||
                (options.max_queries != 0 && result.queries >= options.max_queries)) break;
            result.constraints.clear();
            result.witnesses.clear();
            result.source_constrained = false;
            result.diagnostic.clear();
            materialize_path(session, candidate.path, result);
            run_symbolic(session, candidate.path, tags, result, options);
            ++checked_paths;
            if (result.verdict == FlowVerdict::feasible_flow) {
                feasible = true;
                break;
            }
            if (result.verdict == FlowVerdict::unknown) saw_unknown = true;
        }
        result.paths = checked_paths;
        if (!feasible) {
            result.verdict = saw_unknown ? FlowVerdict::unknown : FlowVerdict::infeasible;
        }
    }
    result.solver_initialized = session.solver_initialized();
    return result;
}

std::string render_flow_text(const DirectedFlowResult& result) {
    std::ostringstream out;
    out << "flow mode=" << flow_mode_name(result.mode)
        << " verdict=" << flow_verdict_name(result.verdict)
        << " completion=" << flow_completion_name(result.completion)
        << " states=" << result.states << " queries=" << result.queries
        << " paths=" << result.paths << " function-depth-limit=" << result.function_depth
        << " deepest-call=" << result.deepest_call
        << " solver=" << (result.solver_initialized ? "initialized" : "not-initialized")
        << " source-constrained=" << (result.source_constrained ? "yes" : "no") << '\n';
    for (std::size_t index = 0; index < result.sources.size(); ++index) {
        const ResolvedFlowPoint& point = result.sources[index];
        out << "source[" << index << "] name=" << point.selector.name
            << " kind=" << flow_point_kind_name(point.selector.kind)
            << " function=" << point.function << " node=" << point.node << " values=";
        if (point.values.empty()) out << '-';
        for (std::size_t value = 0; value < point.values.size(); ++value) {
            if (value != 0) out << ',';
            out << 'v' << point.values[value];
        }
        if (!point.message.empty()) out << " note=" << point.message;
        out << '\n';
    }
    for (std::size_t index = 0; index < result.targets.size(); ++index) {
        const ResolvedFlowPoint& point = result.targets[index];
        out << "target[" << index << "] name=" << point.selector.name
            << " kind=" << flow_point_kind_name(point.selector.kind)
            << " function=" << point.function << " node=" << point.node << " values=";
        if (point.values.empty()) out << '-';
        for (std::size_t value = 0; value < point.values.size(); ++value) {
            if (value != 0) out << ',';
            out << 'v' << point.values[value];
        }
        if (!point.message.empty()) out << " note=" << point.message;
        out << '\n';
    }
    for (const FlowInfluence& influence : result.influences) {
        out << "influence source=" << influence.source << " target=" << influence.target
            << " call-depth=" << influence.call_depth;
        if (influence.byte_range) {
            out << " bytes=" << influence.offset_begin << '-' << influence.offset_end;
        }
        if (!influence.transforms.empty()) {
            out << " via=";
            for (std::size_t index = 0; index < influence.transforms.size(); ++index) {
                if (index != 0) out << ',';
                out << influence.transforms[index];
            }
        }
        out << '\n';
    }
    for (const FlowPathStep& step : result.path) {
        out << "path n" << step.node << '@' << hex_address(step.address);
        if (!step.edge.empty()) out << " edge=" << step.edge;
        if (!step.condition.empty()) out << " condition=" << step.condition;
        out << '\n';
    }
    for (const std::string& constraint : result.constraints) {
        out << "constraint " << constraint << '\n';
    }
    for (const FlowWitness& witness : result.witnesses) {
        out << "witness source=" << witness.source;
        if (witness.byte_values) {
            out << " offset=" << witness.offset_begin << " bytes=";
            for (const std::uint8_t byte : witness.bytes) {
                out << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned int>(byte);
            }
            out << std::dec << std::setfill(' ');
        } else out << " value=" << hex_address(witness.scalar);
        out << '\n';
    }
    if (!result.diagnostic.empty()) out << "diagnostic " << result.diagnostic << '\n';
    return out.str();
}

std::string render_flow_json(const DirectedFlowResult& result) {
    std::ostringstream out;
    out << "{\"schema\":\"airece.flow.v1\",\"status\":";
    json_string(out, xair_status_name(result.status));
    out << ",\"verdict\":";
    json_string(out, flow_verdict_name(result.verdict));
    out << ",\"mode\":";
    json_string(out, flow_mode_name(result.mode));
    out << ",\"completion\":";
    json_string(out, flow_completion_name(result.completion));
    out << ",\"states\":" << result.states << ",\"queries\":" << result.queries
        << ",\"paths\":" << result.paths << ",\"function_depth\":" << result.function_depth
        << ",\"deepest_call\":" << result.deepest_call
        << ",\"solver_initialized\":" << (result.solver_initialized ? "true" : "false")
        << ",\"source_constrained\":" << (result.source_constrained ? "true" : "false");
    const auto points = [&out](const char* const key,
                              const std::vector<ResolvedFlowPoint>& values) {
        out << ",\"" << key << "\":[";
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (index != 0) out << ',';
            const ResolvedFlowPoint& point = values[index];
            out << "{\"selector\":";
            json_string(out, point.selector.raw);
            out << ",\"name\":";
            json_string(out, point.selector.name);
            out << ",\"kind\":";
            json_string(out, flow_point_kind_name(point.selector.kind));
            out << ",\"function\":" << point.function << ",\"node\":" << point.node
                << ",\"operation\":" << point.operation << ",\"values\":[";
            for (std::size_t value = 0; value < point.values.size(); ++value) {
                if (value != 0) out << ',';
                out << point.values[value];
            }
            out << "],\"confidence\":";
            json_string(out, confidence_name(point.confidence));
            out << ",\"message\":";
            json_string(out, point.message);
            out << '}';
        }
        out << ']';
    };
    points("sources", result.sources);
    points("targets", result.targets);
    out << ",\"influences\":[";
    for (std::size_t index = 0; index < result.influences.size(); ++index) {
        if (index != 0) out << ',';
        const FlowInfluence& influence = result.influences[index];
        out << "{\"source\":" << influence.source << ",\"target\":" << influence.target
            << ",\"call_depth\":" << influence.call_depth << ",\"byte_range\":"
            << (influence.byte_range ? "true" : "false")
            << ",\"offset_begin\":" << influence.offset_begin
            << ",\"offset_end\":" << influence.offset_end << ",\"transforms\":[";
        for (std::size_t transform = 0; transform < influence.transforms.size(); ++transform) {
            if (transform != 0) out << ',';
            json_string(out, influence.transforms[transform]);
        }
        out << "]}";
    }
    out << "],\"path\":[";
    for (std::size_t index = 0; index < result.path.size(); ++index) {
        if (index != 0) out << ',';
        const FlowPathStep& step = result.path[index];
        out << "{\"node\":" << step.node << ",\"address\":" << step.address
            << ",\"edge\":";
        json_string(out, step.edge);
        out << ",\"condition\":";
        json_string(out, step.condition);
        out << '}';
    }
    out << "],\"constraints\":[";
    for (std::size_t index = 0; index < result.constraints.size(); ++index) {
        if (index != 0) out << ',';
        json_string(out, result.constraints[index]);
    }
    out << "],\"witnesses\":[";
    for (std::size_t index = 0; index < result.witnesses.size(); ++index) {
        if (index != 0) out << ',';
        const FlowWitness& witness = result.witnesses[index];
        out << "{\"source\":" << witness.source << ",\"scalar\":" << witness.scalar
            << ",\"offset_begin\":" << witness.offset_begin << ",\"bytes\":[";
        for (std::size_t byte = 0; byte < witness.bytes.size(); ++byte) {
            if (byte != 0) out << ',';
            out << static_cast<unsigned int>(witness.bytes[byte]);
        }
        out << "]}";
    }
    out << "],\"diagnostic\":";
    json_string(out, result.diagnostic);
    out << "}\n";
    return out.str();
}

const char* flow_mode_name(const FlowMode mode) noexcept {
    switch (mode) {
    case FlowMode::taint: return "taint";
    case FlowMode::taint_symbolic: return "taint-symbolic";
    case FlowMode::symbolic: return "symbolic";
    default: return "unknown";
    }
}

const char* flow_point_kind_name(const FlowPointKind kind) noexcept {
    switch (kind) {
    case FlowPointKind::register_value: return "register";
    case FlowPointKind::buffer: return "buffer";
    case FlowPointKind::memory: return "memory";
    case FlowPointKind::xair_value: return "value";
    case FlowPointKind::function_argument: return "function-argument";
    case FlowPointKind::call_argument: return "call-argument";
    case FlowPointKind::call_result: return "call-result";
    case FlowPointKind::reach: return "reach";
    case FlowPointKind::memory_write: return "memory-write";
    default: return "unknown";
    }
}

const char* flow_completion_name(const FlowCompletion completion) noexcept {
    switch (completion) {
    case FlowCompletion::complete: return "complete";
    case FlowCompletion::limited: return "limited";
    case FlowCompletion::timeout: return "timeout";
    case FlowCompletion::canceled: return "canceled";
    case FlowCompletion::unknown: return "unknown";
    case FlowCompletion::failed: return "failed";
    default: return "unknown";
    }
}

const char* flow_verdict_name(const FlowVerdict verdict) noexcept {
    switch (verdict) {
    case FlowVerdict::may_flow: return "may-flow";
    case FlowVerdict::feasible_flow: return "feasible-flow";
    case FlowVerdict::infeasible: return "infeasible";
    case FlowVerdict::no_flow: return "no-flow";
    case FlowVerdict::unknown: return "unknown";
    default: return "unknown";
    }
}

} // namespace airece
