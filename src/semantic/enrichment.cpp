#include <airece/semantic/enrichment.hpp>

#include <airece/semantic/api_model.hpp>

#include <algorithm>
#include <chrono>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace airece {
namespace {

using Clock = std::chrono::steady_clock;

class Translator {
public:
    Translator(const xair_module& module, xair_sym_context& context)
        : module_(module), context_(context) {}

    std::optional<xair_sym_expr_id> value(const xair_value_id id) {
        if (const auto found = cache_.find(id); found != cache_.end()) return found->second;
        if (!active_.insert(id).second) return std::nullopt;
        xair_op_id operation = XAIR_INVALID_ID;
        xair_sym_expr_id result = XAIR_SYM_INVALID_ID;
        if (xair_value_definition(&module_, id, &operation) != XAIR_OK) {
            const xair_type type = xair_value_type(&module_, id);
            const std::string name = "xair_v" + std::to_string(id);
            if (type.bits != 0 && xair_sym_symbol(&context_, type.bits, name.c_str(), &result) != XAIR_SYM_OK) {
                active_.erase(id);
                return std::nullopt;
            }
        } else {
            xair_op_view_v3 op{};
            const xair_value_id* inputs = nullptr;
            std::size_t input_count = 0;
            std::uint64_t low = 0, high = 0;
            const xair_type type = xair_value_type(&module_, id);
            if (xair_module_get_op_v3(&module_, operation, &op) != XAIR_OK ||
                xair_op_inputs(&module_, operation, &inputs, &input_count) != XAIR_OK) {
                active_.erase(id);
                return std::nullopt;
            }
            if ((op.opcode == XAIR_OP_CONST_U64 || op.opcode == XAIR_OP_CONST_WIDE) &&
                xair_op_immediate_wide(&module_, operation, &low, &high) == XAIR_OK) {
                if (xair_sym_const_wide(&context_, type.bits, low, high, &result) != XAIR_SYM_OK) {
                    active_.erase(id); return std::nullopt;
                }
            } else if (input_count == 1) {
                const auto src = value(inputs[0]);
                if (!src || xair_sym_unary(&context_, op.opcode, type.bits, *src, 0, &result) != XAIR_SYM_OK) {
                    active_.erase(id); return std::nullopt;
                }
            } else if (input_count == 2) {
                const auto lhs = value(inputs[0]);
                const auto rhs = value(inputs[1]);
                if (!lhs || !rhs || xair_sym_binary(&context_, op.opcode, type.bits, *lhs, *rhs, &result) != XAIR_SYM_OK) {
                    active_.erase(id); return std::nullopt;
                }
            } else if (op.opcode == XAIR_OP_SELECT && input_count == 3) {
                const auto condition = value(inputs[0]);
                const auto yes = value(inputs[1]);
                const auto no = value(inputs[2]);
                if (!condition || !yes || !no ||
                    xair_sym_select(&context_, *condition, *yes, *no, &result) != XAIR_SYM_OK) {
                    active_.erase(id); return std::nullopt;
                }
            } else {
                const std::string name = "xair_v" + std::to_string(id);
                if (type.bits == 0 || xair_sym_symbol(&context_, type.bits, name.c_str(), &result) != XAIR_SYM_OK) {
                    active_.erase(id); return std::nullopt;
                }
            }
        }
        active_.erase(id);
        cache_[id] = result;
        return result;
    }

private:
    const xair_module& module_;
    xair_sym_context& context_;
    std::unordered_map<xair_value_id, xair_sym_expr_id> cache_;
    std::unordered_set<xair_value_id> active_;
};

bool expired(const Clock::time_point start, const std::uint64_t max_ms) {
    return max_ms != 0 && static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count()) >= max_ms;
}

std::string source_name(const xair_sym_taint_category category) {
    switch (category) {
    case XAIR_SYM_TAINT_CATEGORY_NETWORK: return "network";
    case XAIR_SYM_TAINT_CATEGORY_FILE: return "file";
    case XAIR_SYM_TAINT_CATEGORY_USER: return "user";
    case XAIR_SYM_TAINT_CATEGORY_REGISTRY: return "registry";
    case XAIR_SYM_TAINT_CATEGORY_PROCESS: return "process";
    case XAIR_SYM_TAINT_CATEGORY_DRIVER: return "driver";
    default: return "unknown";
    }
}

std::string evidence_for(const CompactFunctionView& base, const xair_op_id operation) {
    for (const SemanticStatement& statement : base.statements) {
        if (std::find(statement.operations.begin(), statement.operations.end(), operation) !=
            statement.operations.end()) return statement.evidence_id;
    }
    return {};
}

std::string hex_value(const std::uint64_t value) {
    std::ostringstream out;
    out << std::hex << value;
    return out.str();
}

} // namespace

EnrichmentResult enrich_function(
    const xair_cfg& cfg,
    const xair_module& module,
    const xair_binary_view& binary,
    const xair_function_id function,
    xair_sym_context& context,
    const CompactFunctionView& base,
    const EnrichmentOptions& options) {
    EnrichmentResult result;
    const Clock::time_point started = Clock::now();
    xair_analysis_options analysis{};
    xair_analysis_options_init(&analysis);
    analysis.max_wall_time = options.max_time_ms;
    analysis.cancel_token = options.cancellation;
    xair_sym_context_set_analysis_options(&context, &analysis);
    const xair_cfg_node_id* nodes = nullptr;
    std::size_t node_count = 0;
    nodes = xair_cfg_function_nodes(&cfg, function, &node_count);
    if (nodes == nullptr || node_count == 0) {
        result.completion = EnrichmentCompletion::unknown;
        return result;
    }

    xair_sym_environment* environment = nullptr;
    xair_sym_state* process_state = nullptr;
    xair_sym_process_options process_options{};
    xair_sym_process_options_init(&process_options, binary.arch);
    const xair_sym_status process_status = xair_sym_process_create(
        &context, &cfg, &binary, &process_options, &environment, &process_state);
    if (process_status == XAIR_SYM_OK) {
        const xair_sym_status model_status = register_api_models(environment);
        if (model_status != XAIR_SYM_OK) result.completion = EnrichmentCompletion::unknown;
    }

    xair_block_id entry = XAIR_INVALID_ID;
    for (std::size_t index = 0; index < node_count; ++index) {
        const xair_cfg_node* node = xair_cfg_get_node(&cfg, nodes[index]);
        if (node != nullptr && node->ir_block != XAIR_INVALID_ID) { entry = node->ir_block; break; }
    }

    if (options.symbolic && entry != XAIR_INVALID_ID) {
        for (const SemanticStatement& statement : base.statements) {
            if (statement.kind == SemanticStatementKind::constant && !statement.values.empty()) {
                result.symbolic.push_back({
                    "expression v" + std::to_string(statement.values.front()) + " constant?",
                    "yes (XAIR-proven; presentation unchanged)", statement.evidence_id,
                    statement.values.front(), XAIR_SYM_OK});
            } else if (statement.kind == SemanticStatementKind::indirect_target ||
                       (statement.kind == SemanticStatementKind::unresolved &&
                        statement.text.find("indirect target") != std::string::npos)) {
                result.symbolic.push_back({"indirect targets?", statement.text,
                    statement.evidence_id, XAIR_INVALID_ID, XAIR_SYM_OK});
            }
        }
        xair_sym_state* state = nullptr;
        if (xair_sym_state_create(&context, &module, entry, &state) != XAIR_SYM_OK) {
            result.completion = EnrichmentCompletion::unknown;
        } else {
            Translator translator(module, context);
            for (const SemanticStatement& statement : base.statements) {
                if (xair_cancel_token_requested(options.cancellation)) {
                    result.completion = EnrichmentCompletion::canceled;
                    break;
                }
                if (statement.kind != SemanticStatementKind::branch || statement.values.empty()) continue;
                if ((options.max_queries != 0 && result.queries >= options.max_queries) ||
                    expired(started, options.max_time_ms)) {
                    result.completion = expired(started, options.max_time_ms)
                        ? EnrichmentCompletion::timeout : EnrichmentCompletion::limited;
                    break;
                }
                SymbolicFinding finding;
                finding.value = statement.values.front();
                finding.evidence_id = statement.evidence_id;
                finding.question = "branch expression v" +
                    std::to_string(finding.value) +
                    " satisfiable without predecessor path constraints?";
                const auto expression = translator.value(finding.value);
                if (!expression) {
                    finding.answer = "unknown (unsupported XAIR expression)";
                    finding.status = XAIR_SYM_ERR_UNSUPPORTED;
                    result.symbolic.push_back(std::move(finding));
                    continue;
                }
                xair_sym_expr_view expression_view{};
                if (xair_sym_expr_get(&context, *expression, &expression_view) == XAIR_SYM_OK &&
                    expression_view.kind == XAIR_SYM_EXPR_CONST) {
                    finding.answer = expression_view.immediate == 0
                        ? "unsat (constant false; expression-local)"
                        : "sat (constant true; expression-local)";
                    finding.question += " expression constant? yes";
                    result.symbolic.push_back(std::move(finding));
                    continue;
                }
                xair_sym_sat true_sat = XAIR_SYM_UNKNOWN;
                finding.status = xair_sym_check(state, *expression, &true_sat);
                ++result.queries;
                if (finding.status == XAIR_SYM_ERR_SOLVER_TIMEOUT) {
                    finding.answer = "unknown (solver timeout)";
                    result.completion = EnrichmentCompletion::timeout;
                } else if (finding.status == XAIR_SYM_ERR_SOLVER_UNKNOWN || finding.status != XAIR_SYM_OK) {
                    finding.answer = "unknown (" + std::string(xair_sym_status_name(finding.status)) + ')';
                    result.completion = EnrichmentCompletion::unknown;
                } else {
                    finding.answer = true_sat == XAIR_SYM_UNSAT
                        ? "unsat (expression-local; not a reachability proof)"
                        : true_sat == XAIR_SYM_SAT
                        ? "sat (expression-local; not a reachability proof)" : "unknown";
                    finding.inferred = true;
                }
                result.symbolic.push_back(std::move(finding));
            }
            xair_sym_state_destroy(state);
        }
    }

    if (options.taint) {
        std::unordered_map<xair_value_id, xair_sym_taint_id> taints;
        std::vector<xair_op_id> function_ops;
        for (std::size_t node_index = 0; node_index < node_count; ++node_index) {
            const xair_cfg_node* node = xair_cfg_get_node(&cfg, nodes[node_index]);
            if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
            const xair_op_id* operations = nullptr;
            std::size_t count = 0;
            if (xair_block_ops(&module, node->ir_block, &operations, &count) != XAIR_OK) continue;
            function_ops.insert(function_ops.end(), operations, operations + count);
        }
        for (const xair_op_id operation : function_ops) {
            if (xair_cancel_token_requested(options.cancellation)) {
                result.completion = EnrichmentCompletion::canceled;
                break;
            }
            if (expired(started, options.max_time_ms) ||
                (options.max_states != 0 && result.states >= options.max_states)) {
                result.completion = expired(started, options.max_time_ms)
                    ? EnrichmentCompletion::timeout : EnrichmentCompletion::limited;
                break;
            }
            xair_op_view_v3 op{};
            xair_op_attributes attributes{};
            if (xair_module_get_op_v3(&module, operation, &op) != XAIR_OK ||
                op.opcode != XAIR_OP_CALL ||
                xair_op_attributes_get(&module, operation, &attributes) != XAIR_OK) continue;
            const ApiModel* model = find_api_model(
                attributes.import_module != nullptr ? attributes.import_module : "",
                attributes.import_name != nullptr ? attributes.import_name : "",
                attributes.import_ordinal);
            if (model == nullptr || (model->taint != ApiTaintRole::source &&
                model->taint != ApiTaintRole::source_and_sink)) continue;
            xair_sym_taint_details details{};
            details.category = model->taint_category;
            details.call_site = 0;
            details.confidence = 85;
            const std::string source = source_name(model->taint_category);
            xair_sym_taint_id taint = XAIR_SYM_TAINT_NONE;
            if (xair_sym_taint_source_ex(&context, source.c_str(), &details, &taint) != XAIR_SYM_OK) continue;
            const xair_value_id* values = nullptr;
            std::size_t count = 0;
            if (xair_op_results(&module, operation, &values, &count) == XAIR_OK) {
                for (std::size_t index = 0; index < count; ++index) {
                    if (xair_value_type(&module, values[index]).kind != XAIR_TYPE_MEM) taints[values[index]] = taint;
                }
            }
            if (xair_op_inputs(&module, operation, &values, &count) == XAIR_OK) {
                for (std::size_t index = 0; index < count && index < model->arguments.size(); ++index) {
                    if (model->arguments[index].writes &&
                        xair_value_type(&module, values[index]).kind != XAIR_TYPE_MEM) taints[values[index]] = taint;
                }
            }
            result.taint.push_back({"source", source, "-", "source", "none",
                evidence_for(base, operation), taint});
            ++result.states;
        }
        // Propagate explicit dependencies using xair_sym provenance transforms.
        for (const xair_op_id operation : function_ops) {
            if (xair_cancel_token_requested(options.cancellation)) {
                result.completion = EnrichmentCompletion::canceled;
                break;
            }
            if (options.max_states != 0 && result.states >= options.max_states) {
                result.completion = EnrichmentCompletion::limited;
                break;
            }
            xair_op_view_v3 op{};
            const xair_value_id* inputs = nullptr;
            const xair_value_id* outputs = nullptr;
            std::size_t input_count = 0, output_count = 0;
            if (xair_module_get_op_v3(&module, operation, &op) != XAIR_OK || op.opcode == XAIR_OP_CALL ||
                xair_op_inputs(&module, operation, &inputs, &input_count) != XAIR_OK ||
                xair_op_results(&module, operation, &outputs, &output_count) != XAIR_OK) continue;
            xair_sym_taint_id merged = XAIR_SYM_TAINT_NONE;
            for (std::size_t index = 0; index < input_count; ++index) {
                const auto found = taints.find(inputs[index]);
                if (found == taints.end()) continue;
                if (merged == XAIR_SYM_TAINT_NONE) merged = found->second;
                else (void)xair_sym_taint_union(&context, merged, found->second, &merged);
            }
            if (merged == XAIR_SYM_TAINT_NONE) continue;
            xair_sym_taint_id transformed = merged;
            (void)xair_sym_taint_transform(&context, merged, xair_opcode_name(op.opcode),
                XAIR_SYM_INVALID_ID, 0, &transformed);
            for (std::size_t index = 0; index < output_count; ++index) taints[outputs[index]] = transformed;
            result.taint.push_back({"transform", "inherited", "-", xair_opcode_name(op.opcode), "none",
                evidence_for(base, operation), transformed});
            ++result.states;
        }
        for (const xair_op_id operation : function_ops) {
            if (xair_cancel_token_requested(options.cancellation)) {
                result.completion = EnrichmentCompletion::canceled;
                break;
            }
            if (expired(started, options.max_time_ms)) {
                result.completion = EnrichmentCompletion::timeout;
                break;
            }
            xair_op_view_v3 op{};
            xair_op_attributes attributes{};
            if (xair_module_get_op_v3(&module, operation, &op) != XAIR_OK || op.opcode != XAIR_OP_CALL ||
                xair_op_attributes_get(&module, operation, &attributes) != XAIR_OK) continue;
            const ApiModel* model = find_api_model(
                attributes.import_module != nullptr ? attributes.import_module : "",
                attributes.import_name != nullptr ? attributes.import_name : "",
                attributes.import_ordinal);
            if (model == nullptr || (model->taint != ApiTaintRole::sink &&
                model->taint != ApiTaintRole::source_and_sink)) continue;
            const xair_value_id* inputs = nullptr;
            std::size_t count = 0;
            if (xair_op_inputs(&module, operation, &inputs, &count) != XAIR_OK) continue;
            for (std::size_t index = 0; index < count; ++index) {
                const auto found = taints.find(inputs[index]);
                if (found == taints.end()) continue;
                xair_sym_taint_id sink = XAIR_SYM_TAINT_NONE;
                const std::string name = std::string(model->module) + '!' + std::string(model->name);
                if (xair_sym_taint_sink(&context, found->second, name.c_str(), 0, &sink) == XAIR_SYM_OK) {
                    result.taint.push_back({"sink", "tainted", name, "identity", "none",
                        evidence_for(base, operation), sink});
                    xair_sym_taint_details details{};
                    const std::string origin = xair_sym_taint_get_details(
                        &context, found->second, &details) == XAIR_SYM_OK
                        ? source_name(details.category) : "unknown";
                    result.taint.push_back({"flow", origin, name, "dependency",
                        details.guard == XAIR_SYM_INVALID_ID ? "none" :
                            "expr" + std::to_string(details.guard),
                        evidence_for(base, operation), sink});
                }
            }
        }
    }
    result.solver_initialized = xair_sym_context_solver_initialized(&context) != 0;
    xair_sym_state_destroy(process_state);
    xair_sym_environment_destroy(environment);
    return result;
}

void append_enrichment(CompactFunctionView& base, const EnrichmentResult& enrichment) {
    for (const SymbolicFinding& finding : enrichment.symbolic) {
        SemanticStatement statement;
        statement.stable_id = "F" + hex_value(base.function.entry) + ":Q:v" +
            std::to_string(finding.value);
        statement.kind = SemanticStatementKind::effect;
        statement.text = finding.question + " " + finding.answer;
        if (finding.inferred) statement.text += " [inferred-by-xair_sym]";
        statement.evidence_id = finding.evidence_id;
        statement.values.push_back(finding.value);
        base.statements.push_back(std::move(statement));
    }
    for (std::size_t index = 0; index < enrichment.taint.size(); ++index) {
        const TaintFinding& finding = enrichment.taint[index];
        SemanticStatement statement;
        statement.stable_id = "F" + hex_value(base.function.entry) + ":T:" +
            std::to_string(finding.taint) + ':' + std::to_string(index);
        statement.kind = SemanticStatementKind::effect;
        statement.text = "taint " + finding.kind;
        if (!finding.source.empty()) statement.text += " source=" + finding.source;
        if (!finding.sink.empty()) statement.text += " sink=" + finding.sink;
        if (!finding.transform.empty()) statement.text += " transform=" + finding.transform;
        if (!finding.guard.empty()) statement.text += " guard=" + finding.guard;
        statement.evidence_id = finding.evidence_id;
        statement.taint_role = finding.kind;
        base.statements.push_back(std::move(statement));
    }
    base.taint_status = enrichment.taint.empty()
        ? std::string(enrichment_completion_name(enrichment.completion))
        : "findings=" + std::to_string(enrichment.taint.size()) +
            " completion=" + enrichment_completion_name(enrichment.completion);
}

const char* enrichment_completion_name(const EnrichmentCompletion value) noexcept {
    switch (value) {
    case EnrichmentCompletion::complete: return "complete";
    case EnrichmentCompletion::limited: return "limited";
    case EnrichmentCompletion::timeout: return "timeout";
    case EnrichmentCompletion::canceled: return "canceled";
    case EnrichmentCompletion::unknown: return "unknown";
    case EnrichmentCompletion::failed:
    default: return "failed";
    }
}

} // namespace airece
