#include <airece/semantic/compact_view.hpp>

#include <airece/semantic/api_model.hpp>
#include <airece/semantic/expression_view.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace airece {
namespace {

std::string hex_value(const std::uint64_t value) {
    std::ostringstream stream;
    stream << std::hex << value;
    return stream.str();
}

std::string semantic_locator(
    const SemanticStatement& statement,
    const SemanticEvidence& evidence) {
    if (!evidence.operations.empty()) {
        return "O" + std::to_string(evidence.operations.front());
    }
    if (!evidence.edges.empty()) {
        return "G" + std::to_string(evidence.edges.front());
    }
    return "N" + std::to_string(evidence.node) + ":" +
        semantic_statement_kind_name(statement.kind);
}

xair_confidence conservative_confidence(
    const xair_confidence left,
    const xair_confidence right) {
    if (left == XAIR_CONFIDENCE_UNKNOWN) return right;
    if (right == XAIR_CONFIDENCE_UNKNOWN) return left;
    return left < right ? left : right;
}

bool is_unresolved_opcode(const xair_opcode opcode) {
    return opcode == XAIR_OP_UNKNOWN || opcode == XAIR_OP_UNDEF ||
        opcode == XAIR_OP_OPAQUE_PURE || opcode == XAIR_OP_OPAQUE_EFFECT;
}

std::uint64_t saturating_end(
    const std::uint64_t begin,
    const std::uint64_t length) {
    return length > std::numeric_limits<std::uint64_t>::max() - begin
        ? std::numeric_limits<std::uint64_t>::max() : begin + length;
}

struct CacheKey {
    xair_function_id function{XAIR_CFG_INVALID_ID};
    CompactOptions options;

    [[nodiscard]] bool operator<(const CacheKey& other) const noexcept {
        if (function != other.function) return function < other.function;
        const std::array<std::size_t, 8> left{
            options.max_bytes, options.max_statements, options.max_expression_depth,
            options.max_calls, options.max_evidence, options.call_offset,
            options.max_regions, options.max_transfers};
        const std::array<std::size_t, 8> right{
            other.options.max_bytes, other.options.max_statements,
            other.options.max_expression_depth, other.options.max_calls,
            other.options.max_evidence, other.options.call_offset,
            other.options.max_regions, other.options.max_transfers};
        return left < right;
    }
};

} // namespace

struct CompactRecovery::Impl {
    const xair_cfg& cfg;
    const xair_module& module;
    const xair_binary_view& binary;
    mutable ExpressionRecovery expressions;
    mutable ControlRecovery controls;
    mutable std::mutex mutex;
    mutable std::map<CacheKey, CompactFunctionView> cache;

    Impl(
        const xair_cfg& cfg_value,
        const xair_module& module_value,
        const xair_binary_view& binary_value)
        : cfg(cfg_value), module(module_value), binary(binary_value),
          expressions(module_value), controls(cfg_value, module_value) {}

    SemanticEvidence operation_evidence(
        const xair_op_id operation,
        const xair_cfg_node_id node_id,
        const xair_block_id block) const {
        SemanticEvidence evidence;
        evidence.node = node_id;
        evidence.block = block;
        evidence.operations.push_back(operation);
        const xair_source_id* sources = nullptr;
        std::size_t source_count = 0;
        if (xair_op_sources(&module, operation, &sources, &source_count) == XAIR_OK) {
            for (std::size_t index = 0; index < source_count; ++index) {
                xair_source_record source{};
                if (xair_module_get_source(&module, sources[index], &source) != XAIR_OK) {
                    continue;
                }
                evidence.confidence = conservative_confidence(
                    evidence.confidence, source.confidence);
                evidence.synthetic = evidence.synthetic ||
                    source.kind != XAIR_SOURCE_MACHINE ||
                    (source.location.flags & XAIR_SOURCE_FLAG_SYNTHETIC) != 0;
                if (source.location.instruction_va == 0) continue;
                const std::uint64_t begin = source.location.instruction_va;
                const std::uint64_t end = saturating_end(
                    begin, source.location.instruction_length);
                if (evidence.begin == 0 || begin < evidence.begin) evidence.begin = begin;
                if (end > evidence.end) evidence.end = end;
            }
        }
        const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
        if (node != nullptr) {
            if (evidence.begin == 0) evidence.begin = node->start;
            if (evidence.end == 0) evidence.end = node->end;
            const xair_confidence node_confidence =
                node->semantic_coverage == XAIR_CFG_SEMANTICS_EXACT
                ? XAIR_CONFIDENCE_EXACT
                : node->semantic_coverage == XAIR_CFG_SEMANTICS_PARTIAL
                ? XAIR_CONFIDENCE_MEDIUM : XAIR_CONFIDENCE_LOW;
            evidence.confidence = conservative_confidence(
                evidence.confidence, node_confidence);
        }
        if (evidence.confidence == XAIR_CONFIDENCE_UNKNOWN) {
            evidence.confidence = XAIR_CONFIDENCE_LOW;
        }
        return evidence;
    }

    SemanticEvidence terminator_evidence(
        const xair_cfg_node_id node_id,
        const xair_block_id block) const {
        SemanticEvidence evidence;
        evidence.node = node_id;
        evidence.block = block;
        const xair_source_id* sources = nullptr;
        std::size_t source_count = 0;
        if (xair_terminator_sources(&module, block, &sources, &source_count) == XAIR_OK) {
            for (std::size_t index = 0; index < source_count; ++index) {
                xair_source_record source{};
                if (xair_module_get_source(&module, sources[index], &source) != XAIR_OK) {
                    continue;
                }
                evidence.confidence = conservative_confidence(
                    evidence.confidence, source.confidence);
                evidence.synthetic = evidence.synthetic ||
                    source.kind != XAIR_SOURCE_MACHINE;
                if (source.location.instruction_va == 0) continue;
                const std::uint64_t begin = source.location.instruction_va;
                const std::uint64_t end = saturating_end(
                    begin, source.location.instruction_length);
                if (evidence.begin == 0 || begin < evidence.begin) evidence.begin = begin;
                if (end > evidence.end) evidence.end = end;
            }
        }
        const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
        if (node != nullptr) {
            if (evidence.begin < node->start || evidence.begin >= node->end ||
                evidence.end > node->end) {
                evidence.begin = node->start;
                evidence.end = node->end;
                evidence.confidence = conservative_confidence(
                    evidence.confidence, XAIR_CONFIDENCE_HIGH);
            }
        }
        if (evidence.confidence == XAIR_CONFIDENCE_UNKNOWN) {
            evidence.confidence = XAIR_CONFIDENCE_HIGH;
        }
        return evidence;
    }

    std::optional<std::uint64_t> constant_value(const xair_value_id value) const {
        xair_op_id operation = XAIR_INVALID_ID;
        if (xair_value_definition(&module, value, &operation) != XAIR_OK) {
            return std::nullopt;
        }
        xair_op_view_v3 raw{};
        if (xair_module_get_op_v3(&module, operation, &raw) != XAIR_OK ||
            raw.opcode != XAIR_OP_CONST_U64) {
            return std::nullopt;
        }
        std::uint64_t low = 0;
        std::uint64_t high = 0;
        if (xair_op_immediate_wide(&module, operation, &low, &high) != XAIR_OK ||
            high != 0) {
            return std::nullopt;
        }
        return low;
    }

    std::optional<std::string> string_at(const std::uint64_t address) const {
        const xair_binary_segment* segment = xair_binary_view_find_segment(
            &binary, address, XAIR_BINARY_PERM_READ);
        if (segment == nullptr || (segment->perms & XAIR_BINARY_PERM_EXEC) != 0) {
            return std::nullopt;
        }
        std::string result;
        result.reserve(32);
        for (std::size_t index = 0; index < 64; ++index) {
            if (address > std::numeric_limits<std::uint64_t>::max() - index) {
                return std::nullopt;
            }
            std::uint8_t byte = 0;
            if (xair_binary_view_read(&binary, address + index, &byte, 1) != XAIR_OK) {
                return std::nullopt;
            }
            if (byte == 0) return result.size() >= 4 ? std::optional(result) : std::nullopt;
            if (std::isprint(byte) == 0) return std::nullopt;
            if (byte == '\\' || byte == '"') result.push_back('\\');
            result.push_back(static_cast<char>(byte));
        }
        return result.size() >= 4 ? std::optional(result) : std::nullopt;
    }

    std::string value_text(
        const xair_value_id value,
        const std::unordered_map<xair_value_id, std::string>& names,
        const CompactOptions& options) const {
        const auto named = names.find(value);
        if (named != names.end()) return named->second;
        ExpressionOptions expression_options;
        expression_options.max_depth = options.max_expression_depth;
        expression_options.max_nodes = 64;
        expression_options.max_tokens = 96;
        expression_options.max_characters = 384;
        const SemanticExpression expression = expressions.build(value, expression_options);
        return expression ? expression.text : "v" + std::to_string(value);
    }

    static std::string target_for(
        const xair_block_id block,
        const std::unordered_map<xair_block_id, std::uint64_t>& block_addresses,
        const std::unordered_map<xair_block_id, std::uint64_t>& all_block_addresses) {
        const auto found = block_addresses.find(block);
        if (found != block_addresses.end()) return "label_" + hex_value(found->second);
        const auto external = all_block_addresses.find(block);
        return external == all_block_addresses.end()
            ? "unresolved_block_" + std::to_string(block)
            : "outside_function_0x" + hex_value(external->second);
    }

    static void append_statement(
        std::vector<SemanticStatement>& target,
        SemanticStatement statement,
        SemanticEvidence evidence) {
        statement.address = evidence.begin;
        statement.node = evidence.node;
        statement.block = evidence.block;
        statement.operations = evidence.operations;
        statement.confidence = evidence.confidence;
        statement.synthetic = evidence.synthetic;
        target.push_back(std::move(statement));
    }

    CompactFunctionView build_uncached(
        const CompactFunctionDescriptor& function,
        const VariableView& variables,
        const CompactOptions& options) const {
        CompactFunctionView view;
        view.function = function;
        view.complete = function.session_complete && !variables.truncated;
        if (!variables) {
            view.status = variables.status;
            return view;
        }
        if (xair_cfg_get_function(&cfg, function.id) == nullptr) {
            view.status = XAIR_ERR_BAD_ARG;
            return view;
        }

        ControlOptions control_options;
        control_options.max_regions = options.max_regions;
        control_options.max_transfers = options.max_transfers;
        control_options.max_expression_depth = options.max_expression_depth;
        view.control = controls.build(function.id, control_options);
        if (!view.control) {
            view.status = view.control.status;
            return view;
        }
        view.omitted.regions = view.control.omitted_regions;
        view.omitted.transfers = view.control.omitted_transfers;
        view.truncated = view.control.truncated;

        std::unordered_map<xair_value_id, std::string> names;
        for (const PresentationVariable& variable : variables.variables) {
            for (const xair_value_id value : variable.values) names[value] = variable.name.text;
            if (variable.primary_value != XAIR_INVALID_ID) {
                names[variable.primary_value] = variable.name.text;
            }
            if ((variable.roles & variable_role_argument) != 0) {
                view.parameters.push_back(variable);
            }
            if ((variable.roles & variable_role_return) != 0) {
                view.returns.push_back(variable);
            }
        }

        std::unordered_map<xair_block_id, xair_cfg_node_id> block_nodes;
        std::unordered_map<xair_block_id, std::uint64_t> block_addresses;
        std::unordered_map<xair_block_id, std::uint64_t> all_block_addresses;
        for (std::size_t node_index = 0; node_index < xair_cfg_node_count(&cfg);
             ++node_index) {
            const xair_cfg_node* node = xair_cfg_get_node(
                &cfg, static_cast<xair_cfg_node_id>(node_index));
            if (node != nullptr && node->ir_block != XAIR_INVALID_ID) {
                all_block_addresses[node->ir_block] = node->start;
            }
        }
        for (const xair_cfg_node_id node_id : view.control.block_order) {
            const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
            if (node == nullptr) continue;
            if (node->semantic_coverage == XAIR_CFG_SEMANTICS_EXACT) {
                ++view.coverage.exact_blocks;
            } else if (node->semantic_coverage == XAIR_CFG_SEMANTICS_PARTIAL) {
                ++view.coverage.partial_blocks;
            } else {
                ++view.coverage.opaque_blocks;
            }
            if (node->ir_block != XAIR_INVALID_ID) {
                block_nodes[node->ir_block] = node_id;
                block_addresses[node->ir_block] = node->start;
            }
        }
        /* XAIR block parameters are SSA versions of values crossing CFG edges.
         * Carry presentation identities through those edge arguments so an
         * entry ABI argument remains argN instead of reverting to rcx/rdx/r8/r9. */
        for (std::size_t pass = 0; pass <= block_nodes.size(); ++pass) {
            bool changed = false;
            for (const auto& [block, node_id] : block_nodes) {
                (void)node_id;
                xair_term_view term{};
                if (xair_block_terminator(&module, block, &term) != XAIR_OK) continue;
                const auto propagate = [&](const xair_block_id target,
                                           const xair_value_id* arguments,
                                           const std::size_t argument_count) {
                    if (!block_nodes.contains(target) || arguments == nullptr) return;
                    const std::size_t parameter_count = xair_block_param_count(&module, target);
                    const std::size_t count = std::min(parameter_count, argument_count);
                    for (std::size_t index = 0; index < count; ++index) {
                        const auto source_name = names.find(arguments[index]);
                        if (source_name == names.end()) continue;
                        xair_value_id parameter = XAIR_INVALID_ID;
                        if (xair_block_param_value(&module, target, index, &parameter) != XAIR_OK) {
                            continue;
                        }
                        changed = names.emplace(parameter, source_name->second).second || changed;
                    }
                };
                propagate(term.true_target, term.true_args, term.true_arg_count);
                propagate(term.false_target, term.false_args, term.false_arg_count);
            }
            if (!changed) break;
        }
        const std::size_t coverage_total = view.coverage.exact_blocks +
            view.coverage.partial_blocks + view.coverage.opaque_blocks;
        if (coverage_total != 0) {
            view.coverage.exact_percent = static_cast<std::uint32_t>(
                static_cast<double>(view.coverage.exact_blocks) * 100.0 /
                static_cast<double>(coverage_total));
        }

        std::vector<SemanticStatement> material;
        std::vector<SemanticStatement> deferred;
        std::vector<SemanticEvidence> material_evidence;
        std::vector<SemanticEvidence> deferred_evidence;
        std::size_t seen_calls = 0;

        for (const xair_cfg_node_id node_id : view.control.block_order) {
            const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
            if (node == nullptr) continue;
            if (node->ir_block == XAIR_INVALID_ID) {
                SemanticStatement statement;
                statement.kind = SemanticStatementKind::unresolved;
                statement.text = "opaque CFG block at 0x" + hex_value(node->start);
                SemanticEvidence evidence;
                evidence.begin = node->start;
                evidence.end = node->end;
                evidence.node = node_id;
                evidence.confidence = XAIR_CONFIDENCE_LOW;
                append_statement(material, std::move(statement), evidence);
                material_evidence.push_back(std::move(evidence));
                ++view.coverage.unresolved_operations;
                continue;
            }
            const xair_op_id* operations = nullptr;
            std::size_t operation_count = 0;
            if (xair_block_ops(
                    &module, node->ir_block, &operations, &operation_count) != XAIR_OK) {
                continue;
            }
            for (std::size_t operation_index = 0;
                 operation_index < operation_count; ++operation_index) {
                const xair_op_id operation = operations[operation_index];
                xair_op_view_v3 raw{};
                if (xair_module_get_op_v3(&module, operation, &raw) != XAIR_OK) continue;
                const xair_value_id* inputs = nullptr;
                const xair_value_id* results = nullptr;
                std::size_t input_count = 0;
                std::size_t result_count = 0;
                (void)xair_op_inputs(&module, operation, &inputs, &input_count);
                (void)xair_op_results(&module, operation, &results, &result_count);
                xair_op_attributes attributes{};
                (void)xair_op_attributes_get(&module, operation, &attributes);
                SemanticEvidence evidence = operation_evidence(
                    operation, node_id, node->ir_block);
                SemanticStatement statement;
                statement.operations.push_back(operation);
                if (raw.opcode == XAIR_OP_CALL) {
                    ++view.total_calls;
                    const std::size_t call_index = seen_calls++;
                    if (call_index < options.call_offset ||
                        (options.max_calls != 0 &&
                         call_index - options.call_offset >= options.max_calls)) {
                        ++view.omitted.calls;
                        continue;
                    }
                    statement.kind = SemanticStatementKind::call;
                    std::string callee;
                    if (attributes.import_name != nullptr &&
                        attributes.import_name[0] != '\0') {
                        if (attributes.import_module != nullptr &&
                            attributes.import_module[0] != '\0') {
                            callee = std::string(attributes.import_module) + '!';
                        }
                        callee += attributes.import_name;
                    } else if (attributes.direct_target != 0) {
                        callee = "sub_" + hex_value(attributes.direct_target);
                    } else {
                        callee = "indirect_call";
                    }
                    std::string arguments;
                    for (std::size_t input_index = 0; input_index < input_count;
                         ++input_index) {
                        if (xair_value_type(&module, inputs[input_index]).kind == XAIR_TYPE_MEM) {
                            continue;
                        }
                        if (!arguments.empty()) arguments += ", ";
                        arguments += value_text(inputs[input_index], names, options);
                        statement.values.push_back(inputs[input_index]);
                    }
                    std::string result_name;
                    for (std::size_t result_index = 0; result_index < result_count;
                         ++result_index) {
                        if (xair_value_type(&module, results[result_index]).kind ==
                            XAIR_TYPE_MEM) {
                            continue;
                        }
                        result_name = value_text(results[result_index], names, options);
                        statement.values.push_back(results[result_index]);
                        break;
                    }
                    statement.text = result_name.empty()
                        ? callee + '(' + arguments + ')'
                        : result_name + " = " + callee + '(' + arguments + ')';
                    const ApiModel* api = find_api_model(
                        attributes.import_module != nullptr
                            ? attributes.import_module : "",
                        attributes.import_name != nullptr
                            ? attributes.import_name : "",
                        attributes.import_ordinal);
                    if (api != nullptr) {
                        statement.api_model = std::string(api->module) + '!' +
                            std::string(api->name) + "@" +
                            std::string(api_model_set_version);
                        statement.effect_summary = describe_api_effects(*api);
                        statement.taint_role = api_taint_role_name(api->taint);
                        statement.return_role = api->return_role;
                        statement.constant_summary = api->constants;
                        statement.no_return = api->no_return;
                        for (const ApiArgumentModel& argument : api->arguments) {
                            statement.api_arguments.push_back(
                                std::string(argument.name) + ':' + std::string(argument.role));
                        }
                        if (!api->handles.produced.empty()) {
                            statement.handle_relationship = "produces=" +
                                std::string(api->handles.produced);
                        }
                        if (!api->handles.consumes.empty()) {
                            if (!statement.handle_relationship.empty()) {
                                statement.handle_relationship += ',';
                            }
                            statement.handle_relationship += "consumes=" +
                                std::string(api->handles.consumes);
                        }
                        statement.text += " /* model=" + statement.api_model;
                        if (!statement.effect_summary.empty()) {
                            statement.text += " effects=" + statement.effect_summary;
                        }
                        if (api->taint != ApiTaintRole::none) {
                            statement.text += " taint=" + statement.taint_role;
                        }
                        statement.text += " */";
                    }
                    append_statement(material, std::move(statement), evidence);
                    material_evidence.push_back(std::move(evidence));
                    continue;
                }
                if (raw.opcode == XAIR_OP_LOAD && input_count >= 2 && result_count != 0) {
                    statement.kind = SemanticStatementKind::memory_read;
                    const std::uint16_t bits = xair_value_type(&module, results[0]).bits;
                    statement.text = value_text(results[0], names, options) + " = load" +
                        std::to_string(bits) + '(' +
                        value_text(inputs[1], names, options) + ')';
                    statement.values = {inputs[1], results[0]};
                    append_statement(material, std::move(statement), evidence);
                    material_evidence.push_back(std::move(evidence));
                    continue;
                }
                if (raw.opcode == XAIR_OP_STORE && input_count >= 3) {
                    statement.kind = SemanticStatementKind::memory_write;
                    const std::uint16_t bits = xair_value_type(&module, inputs[2]).bits;
                    statement.text = "store" + std::to_string(bits) + '(' +
                        value_text(inputs[1], names, options) + ", " +
                        value_text(inputs[2], names, options) + ')';
                    statement.values = {inputs[1], inputs[2]};
                    append_statement(material, std::move(statement), evidence);
                    material_evidence.push_back(std::move(evidence));
                    continue;
                }
                if (is_unresolved_opcode(raw.opcode)) {
                    statement.kind = SemanticStatementKind::unresolved;
                    statement.text = std::string(xair_opcode_name(raw.opcode)) +
                        "(op" + std::to_string(operation) + ')';
                    ++view.coverage.unresolved_operations;
                    append_statement(material, std::move(statement), evidence);
                    material_evidence.push_back(std::move(evidence));
                    continue;
                }
                if (raw.opcode == XAIR_OP_MEMORY_BARRIER ||
                    raw.opcode == XAIR_OP_INTRINSIC || attributes.effects != 0) {
                    statement.kind = SemanticStatementKind::effect;
                    statement.text = std::string(xair_opcode_name(raw.opcode)) +
                        " effects=0x" + hex_value(attributes.effects);
                    append_statement(material, std::move(statement), evidence);
                    material_evidence.push_back(std::move(evidence));
                    continue;
                }
                if (raw.opcode == XAIR_OP_CONST_U64 && result_count != 0) {
                    const auto constant = constant_value(results[0]);
                    if (!constant || (*constant == 0 || *constant == 1)) continue;
                    statement.kind = SemanticStatementKind::constant;
                    statement.values.push_back(results[0]);
                    statement.text = value_text(results[0], names, options) + " = 0x" +
                        hex_value(*constant);
                    const xair_binary_segment* segment = xair_binary_view_find_segment(
                        &binary, *constant, 0);
                    if (segment != nullptr) {
                        statement.kind = SemanticStatementKind::global_reference;
                        statement.text += " (global_" + hex_value(*constant) + ')';
                    }
                    if (const auto string = string_at(*constant)) {
                        statement.kind = SemanticStatementKind::string_reference;
                        statement.text += " \"" + *string + '"';
                    }
                    append_statement(deferred, std::move(statement), evidence);
                    deferred_evidence.push_back(std::move(evidence));
                }
            }

            xair_term_view term{};
            if (xair_block_terminator(&module, node->ir_block, &term) != XAIR_OK) continue;
            SemanticEvidence evidence = terminator_evidence(node_id, node->ir_block);
            SemanticStatement statement;
            if (term.kind == XAIR_TERM_VIEW_CBRANCH) {
                statement.kind = SemanticStatementKind::branch;
                statement.values.push_back(term.condition);
                statement.text = "if " + value_text(term.condition, names, options) +
                    " -> " + target_for(term.true_target, block_addresses,
                                         all_block_addresses) +
                    " else " + target_for(term.false_target, block_addresses,
                                           all_block_addresses);
                ++view.total_branches;
            } else if (term.kind == XAIR_TERM_VIEW_JUMP) {
                statement.kind = SemanticStatementKind::branch;
                const bool local = block_addresses.contains(term.true_target);
                statement.text = local
                    ? "goto " + target_for(term.true_target, block_addresses,
                                           all_block_addresses)
                    : "control leaves function -> " +
                        target_for(term.true_target, block_addresses,
                                   all_block_addresses);
                ++view.total_branches;
            } else if (term.kind == XAIR_TERM_VIEW_RETURN) {
                statement.kind = SemanticStatementKind::return_value;
                statement.text = "return";
                for (std::size_t index = 0; index < term.true_arg_count; ++index) {
                    statement.text += index == 0 ? " " : ", ";
                    statement.text += value_text(term.true_args[index], names, options);
                    statement.values.push_back(term.true_args[index]);
                }
            } else if (term.kind == XAIR_TERM_VIEW_TRAP) {
                statement.kind = SemanticStatementKind::trap;
                statement.text = "trap(" + std::to_string(term.code) + ')';
            } else if (term.kind == XAIR_TERM_VIEW_FAULT) {
                statement.kind = SemanticStatementKind::fault;
                statement.text = "fault(" + std::to_string(term.code) + ')';
            } else {
                continue;
            }
            append_statement(material, std::move(statement), evidence);
            material_evidence.push_back(std::move(evidence));
        }

        std::unordered_set<xair_cfg_node_id> function_nodes(
            view.control.block_order.begin(), view.control.block_order.end());
        const std::size_t indirect_count = xair_cfg_indirect_count(&cfg);
        for (std::size_t index = 0; index < indirect_count; ++index) {
            const xair_indirect_resolution* indirect = xair_cfg_get_indirect(&cfg, index);
            if (indirect == nullptr) continue;
            const xair_cfg_edge* edge = xair_cfg_get_edge(&cfg, indirect->edge);
            if (edge == nullptr || !function_nodes.contains(edge->src)) continue;
            SemanticStatement statement;
            statement.kind = indirect->candidate_count == 0
                ? SemanticStatementKind::unresolved
                : SemanticStatementKind::indirect_target;
            statement.text = indirect->candidate_count == 0
                ? "unresolved indirect target"
                : "possible indirect targets:";
            std::size_t candidate_count = 0;
            const std::uint64_t* candidates = xair_cfg_indirect_candidates(
                &cfg, index, &candidate_count);
            for (std::size_t candidate = 0; candidate < candidate_count; ++candidate) {
                statement.text += (candidate == 0 ? " 0x" : ", 0x") +
                    hex_value(candidates[candidate]);
            }
            SemanticEvidence evidence;
            evidence.node = edge->src;
            evidence.edges.push_back(indirect->edge);
            const xair_cfg_node* source = xair_cfg_get_node(&cfg, edge->src);
            if (source != nullptr) {
                evidence.begin = source->start;
                evidence.end = source->end;
            }
            evidence.confidence = indirect->confidence <= XAIR_EDGE_JUMPTABLE
                ? XAIR_CONFIDENCE_HIGH : XAIR_CONFIDENCE_MEDIUM;
            append_statement(material, std::move(statement), evidence);
            material_evidence.push_back(std::move(evidence));
        }

        material.insert(material.end(),
                        std::make_move_iterator(deferred.begin()),
                        std::make_move_iterator(deferred.end()));
        material_evidence.insert(material_evidence.end(),
                                 std::make_move_iterator(deferred_evidence.begin()),
                                 std::make_move_iterator(deferred_evidence.end()));

        const std::size_t keep = options.max_statements == 0
            ? material.size() : std::min(material.size(), options.max_statements);
        if (keep < material.size()) {
            view.omitted.statements += material.size() - keep;
            for (std::size_t index = keep; index < material.size(); ++index) {
                if (material[index].kind == SemanticStatementKind::branch) {
                    ++view.omitted.branches;
                }
                if (material[index].kind == SemanticStatementKind::call) {
                    ++view.omitted.calls;
                }
            }
            view.truncated = true;
        }
        view.statements.reserve(keep);
        for (std::size_t index = 0; index < keep; ++index) {
            SemanticStatement statement = std::move(material[index]);
            const std::string function_prefix = "F" + hex_value(function.entry);
            const SemanticEvidence* identity_evidence =
                index < material_evidence.size() ? &material_evidence[index] : nullptr;
            const std::string locator = identity_evidence != nullptr
                ? semantic_locator(statement, *identity_evidence)
                : "N" + std::to_string(statement.node) + ":" +
                    semantic_statement_kind_name(statement.kind);
            statement.stable_id = function_prefix + ":S:" + locator;
            if (index < material_evidence.size()) {
                SemanticEvidence evidence = std::move(material_evidence[index]);
                if (options.max_evidence == 0 || view.evidence.size() < options.max_evidence) {
                    evidence.stable_id = function_prefix + ":E:" + locator;
                    statement.evidence_id = evidence.stable_id;
                    view.evidence.push_back(std::move(evidence));
                } else {
                    ++view.omitted.evidence;
                    view.truncated = true;
                }
            }
            view.statements.push_back(std::move(statement));
        }
        view.complete = view.complete && !view.truncated && !view.omitted.any();
        return view;
    }

    CompactFunctionView build(
        const CompactFunctionDescriptor& function,
        const VariableView& variables,
        const CompactOptions& options) const {
        const CacheKey key{function.id, options};
        {
            const std::scoped_lock lock(mutex);
            const auto found = cache.find(key);
            if (found != cache.end()) return found->second;
        }
        CompactFunctionView result = build_uncached(function, variables, options);
        const std::scoped_lock lock(mutex);
        const auto [entry, inserted] = cache.emplace(key, result);
        return inserted ? result : entry->second;
    }
};

CompactRecovery::CompactRecovery(
    const xair_cfg& cfg,
    const xair_module& module,
    const xair_binary_view& binary)
    : impl_(std::make_unique<Impl>(cfg, module, binary)) {}
CompactRecovery::~CompactRecovery() = default;
CompactRecovery::CompactRecovery(CompactRecovery&&) noexcept = default;
CompactRecovery& CompactRecovery::operator=(CompactRecovery&&) noexcept = default;

CompactFunctionView CompactRecovery::build(
    const CompactFunctionDescriptor& function,
    const VariableView& variables,
    const CompactOptions& options) const {
    return impl_->build(function, variables, options);
}

ControlView CompactRecovery::control_view(
    const xair_function_id function,
    const ControlOptions& options) const {
    return impl_->controls.build(function, options);
}

std::size_t CompactRecovery::cache_size() const noexcept {
    const std::scoped_lock lock(impl_->mutex);
    return impl_->cache.size();
}

std::size_t CompactRecovery::control_cache_size() const noexcept {
    return impl_->controls.cache_size();
}

const char* semantic_statement_kind_name(
    const SemanticStatementKind kind) noexcept {
    switch (kind) {
    case SemanticStatementKind::call: return "call";
    case SemanticStatementKind::branch: return "branch";
    case SemanticStatementKind::return_value: return "return";
    case SemanticStatementKind::memory_read: return "memory-read";
    case SemanticStatementKind::memory_write: return "memory-write";
    case SemanticStatementKind::global_reference: return "global";
    case SemanticStatementKind::string_reference: return "string";
    case SemanticStatementKind::constant: return "constant";
    case SemanticStatementKind::import_reference: return "import";
    case SemanticStatementKind::indirect_target: return "indirect-target";
    case SemanticStatementKind::effect: return "effect";
    case SemanticStatementKind::unresolved: return "unresolved";
    case SemanticStatementKind::trap: return "trap";
    case SemanticStatementKind::fault:
    default: return "fault";
    }
}

} // namespace airece
