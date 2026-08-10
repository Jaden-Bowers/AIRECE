#include <airece/semantic/control_view.hpp>

#include <algorithm>
#include <map>
#include <limits>
#include <mutex>
#include <set>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace airece {
namespace {

xair_confidence edge_confidence(const xair_edge_confidence confidence) {
    switch (confidence) {
    case XAIR_EDGE_EXACT: return XAIR_CONFIDENCE_EXACT;
    case XAIR_EDGE_RELOCATION:
    case XAIR_EDGE_SYMBOL:
    case XAIR_EDGE_JUMPTABLE: return XAIR_CONFIDENCE_HIGH;
    case XAIR_EDGE_ABSTRACT_INTERP: return XAIR_CONFIDENCE_MEDIUM;
    case XAIR_EDGE_HEURISTIC:
    case XAIR_EDGE_SPECULATIVE:
    default: return XAIR_CONFIDENCE_LOW;
    }
}

xair_confidence conservative_confidence(
    const xair_confidence left,
    const xair_confidence right) {
    if (left == XAIR_CONFIDENCE_UNKNOWN) return right;
    if (right == XAIR_CONFIDENCE_UNKNOWN) return left;
    return left < right ? left : right;
}

std::uint64_t saturating_end(
    const std::uint64_t begin,
    const std::uint64_t length) {
    return length > std::numeric_limits<std::uint64_t>::max() - begin
        ? std::numeric_limits<std::uint64_t>::max() : begin + length;
}

bool is_call_edge(const xair_cfg_edge_kind kind) {
    return kind == XAIR_EDGE_CALL || kind == XAIR_EDGE_INDIRECT_CALL ||
        kind == XAIR_EDGE_EXTERNAL || kind == XAIR_EDGE_TAILCALL;
}

bool is_conditional_edge(const xair_cfg_edge_kind kind) {
    return kind == XAIR_EDGE_CBRANCH_TRUE || kind == XAIR_EDGE_CBRANCH_FALSE;
}

struct EdgeRecord {
    xair_cfg_edge_id id{XAIR_CFG_INVALID_ID};
    xair_cfg_edge edge{};
};

struct LoopRecord {
    xair_cfg_node_id header{XAIR_CFG_INVALID_ID};
    std::unordered_set<xair_cfg_node_id> members;
    bool irreducible{};
};

struct CacheKey {
    xair_function_id function{XAIR_CFG_INVALID_ID};
    ControlOptions options;

    [[nodiscard]] bool operator<(const CacheKey& other) const noexcept {
        if (function != other.function) return function < other.function;
        if (options.max_regions != other.options.max_regions) {
            return options.max_regions < other.options.max_regions;
        }
        if (options.max_transfers != other.options.max_transfers) {
            return options.max_transfers < other.options.max_transfers;
        }
        return options.max_expression_depth < other.options.max_expression_depth;
    }
};

} // namespace

struct ControlRecovery::Impl {
    const xair_cfg& cfg;
    const xair_module& module;
    mutable std::mutex mutex;
    mutable std::map<CacheKey, ControlView> cache;

    Impl(const xair_cfg& cfg_value, const xair_module& module_value)
        : cfg(cfg_value), module(module_value) {}

    bool constant_i64(const xair_value_id value, std::int64_t& result) const {
        xair_op_id operation = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        std::uint64_t low = 0;
        std::uint64_t high = 0;
        if (xair_value_definition(&module, value, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(&module, operation, &view) != XAIR_OK ||
            view.opcode != XAIR_OP_CONST_U64 ||
            xair_op_immediate_wide(&module, operation, &low, &high) != XAIR_OK) {
            return false;
        }
        result = static_cast<std::int64_t>(low);
        return true;
    }

    bool depends_on(
        const xair_value_id value,
        const xair_value_id needle,
        const std::size_t depth = 0) const {
        if (value == needle) return true;
        if (depth >= 16) return false;
        xair_op_id operation = XAIR_INVALID_ID;
        const xair_value_id* inputs = nullptr;
        std::size_t input_count = 0;
        if (xair_value_definition(&module, value, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_op_inputs(&module, operation, &inputs, &input_count) != XAIR_OK) {
            return false;
        }
        for (std::size_t index = 0; index < input_count; ++index) {
            if (depends_on(inputs[index], needle, depth + 1)) return true;
        }
        return false;
    }

    bool induction_step(
        const xair_value_id update,
        const xair_value_id variable,
        std::int64_t& step) const {
        xair_op_id operation = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t input_count = 0;
        if (xair_value_definition(&module, update, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(&module, operation, &view) != XAIR_OK ||
            xair_op_inputs(&module, operation, &inputs, &input_count) != XAIR_OK) {
            return false;
        }
        if ((view.opcode == XAIR_OP_ZEXT || view.opcode == XAIR_OP_SEXT ||
             view.opcode == XAIR_OP_TRUNC || view.opcode == XAIR_OP_EXTRACT) &&
            input_count != 0) {
            return induction_step(inputs[0], variable, step);
        }
        if ((view.opcode != XAIR_OP_ADD && view.opcode != XAIR_OP_SUB) ||
            input_count < 2) return false;
        std::int64_t amount = 0;
        if (depends_on(inputs[0], variable) && constant_i64(inputs[1], amount)) {
            step = view.opcode == XAIR_OP_SUB ? -amount : amount;
            return step != 0;
        }
        if (view.opcode == XAIR_OP_ADD && depends_on(inputs[1], variable) &&
            constant_i64(inputs[0], amount)) {
            step = amount;
            return step != 0;
        }
        return false;
    }

    std::optional<std::int64_t> stack_offset(
        const xair_value_id value,
        const std::size_t depth = 0) const {
        if (depth >= 16) return std::nullopt;
        const char* raw_name = xair_value_name(&module, value);
        if (raw_name != nullptr) {
            const std::string name(raw_name);
            if (name == "rsp" || name == "esp" || name == "rbp" || name == "ebp") {
                return 0;
            }
        }
        xair_op_id operation = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t input_count = 0;
        if (xair_value_definition(&module, value, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(&module, operation, &view) != XAIR_OK ||
            xair_op_inputs(&module, operation, &inputs, &input_count) != XAIR_OK) {
            return std::nullopt;
        }
        if ((view.opcode == XAIR_OP_INT_TO_ADDR || view.opcode == XAIR_OP_ADDR_TO_INT ||
             view.opcode == XAIR_OP_ZEXT || view.opcode == XAIR_OP_SEXT ||
             view.opcode == XAIR_OP_TRUNC) && input_count != 0) {
            return stack_offset(inputs[0], depth + 1);
        }
        if ((view.opcode == XAIR_OP_ADD || view.opcode == XAIR_OP_SUB ||
             view.opcode == XAIR_OP_ADDR_ADD || view.opcode == XAIR_OP_ADDR_SUB) &&
            input_count >= 2) {
            std::int64_t amount = 0;
            if (constant_i64(inputs[1], amount)) {
                const auto base = stack_offset(inputs[0], depth + 1);
                if (base) {
                    return *base + ((view.opcode == XAIR_OP_SUB ||
                        view.opcode == XAIR_OP_ADDR_SUB) ? -amount : amount);
                }
            }
        }
        return std::nullopt;
    }

    xair_value_id find_load(
        const xair_value_id value,
        const std::size_t depth = 0) const {
        if (depth >= 12) return XAIR_INVALID_ID;
        xair_op_id operation = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t input_count = 0;
        if (xair_value_definition(&module, value, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(&module, operation, &view) != XAIR_OK ||
            xair_op_inputs(&module, operation, &inputs, &input_count) != XAIR_OK) {
            return XAIR_INVALID_ID;
        }
        if (view.opcode == XAIR_OP_LOAD) return value;
        if (view.opcode == XAIR_OP_ZEXT || view.opcode == XAIR_OP_SEXT ||
            view.opcode == XAIR_OP_TRUNC || view.opcode == XAIR_OP_EXTRACT) {
            return input_count == 0 ? XAIR_INVALID_ID : find_load(inputs[0], depth + 1);
        }
        return XAIR_INVALID_ID;
    }

    bool stored_induction_step(
        const xair_value_id data,
        const std::int64_t offset,
        std::int64_t& step,
        const std::size_t depth = 0) const {
        if (depth >= 12) return false;
        xair_op_id operation = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t input_count = 0;
        if (xair_value_definition(&module, data, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(&module, operation, &view) != XAIR_OK ||
            xair_op_inputs(&module, operation, &inputs, &input_count) != XAIR_OK) {
            return false;
        }
        if ((view.opcode == XAIR_OP_ZEXT || view.opcode == XAIR_OP_SEXT ||
             view.opcode == XAIR_OP_TRUNC || view.opcode == XAIR_OP_EXTRACT) &&
            input_count != 0) {
            return stored_induction_step(inputs[0], offset, step, depth + 1);
        }
        if ((view.opcode != XAIR_OP_ADD && view.opcode != XAIR_OP_SUB) ||
            input_count < 2) return false;
        for (std::size_t load_side = 0; load_side < 2; ++load_side) {
            const xair_value_id loaded = find_load(inputs[load_side]);
            if (loaded == XAIR_INVALID_ID) continue;
            xair_op_id load_operation = XAIR_INVALID_ID;
            const xair_value_id* load_inputs = nullptr;
            std::size_t load_count = 0;
            if (xair_value_definition(&module, loaded, &load_operation) != XAIR_OK ||
                xair_op_inputs(&module, load_operation, &load_inputs, &load_count) != XAIR_OK ||
                load_count < 2 || stack_offset(load_inputs[1]) != offset) continue;
            std::int64_t amount = 0;
            if (!constant_i64(inputs[1 - load_side], amount)) continue;
            if (view.opcode == XAIR_OP_SUB && load_side != 0) continue;
            step = view.opcode == XAIR_OP_SUB ? -amount : amount;
            return step != 0;
        }
        return false;
    }

    bool recover_stored_induction(
        const LoopRecord& loop,
        const xair_value_id left,
        const xair_value_id right,
        const std::string& comparison,
        ControlRegion& region) const {
        for (const bool use_left : {true, false}) {
            const xair_value_id expression = use_left ? left : right;
            const xair_value_id loaded = find_load(expression);
            if (loaded == XAIR_INVALID_ID) continue;
            xair_op_id load_operation = XAIR_INVALID_ID;
            const xair_value_id* load_inputs = nullptr;
            std::size_t load_count = 0;
            if (xair_value_definition(&module, loaded, &load_operation) != XAIR_OK ||
                xair_op_inputs(&module, load_operation, &load_inputs, &load_count) != XAIR_OK ||
                load_count < 2) continue;
            const auto offset = stack_offset(load_inputs[1]);
            if (!offset) continue;
            for (const xair_cfg_node_id node_id : loop.members) {
                const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
                if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
                const xair_op_id* operations = nullptr;
                std::size_t operation_count = 0;
                if (xair_block_ops(
                        &module, node->ir_block, &operations, &operation_count) != XAIR_OK) continue;
                for (std::size_t index = 0; index < operation_count; ++index) {
                    xair_op_view_v3 view{};
                    const xair_value_id* inputs = nullptr;
                    std::size_t input_count = 0;
                    if (xair_module_get_op_v3(&module, operations[index], &view) != XAIR_OK ||
                        view.opcode != XAIR_OP_STORE ||
                        xair_op_inputs(&module, operations[index], &inputs, &input_count) != XAIR_OK ||
                        input_count < 3 || stack_offset(inputs[1]) != *offset) continue;
                    std::int64_t step = 0;
                    if (!stored_induction_step(inputs[2], *offset, step)) continue;
                    region.induction.recovered = true;
                    region.induction.variable = loaded;
                    region.induction.bound = use_left ? right : left;
                    region.induction.step = step;
                    region.induction.comparison = comparison;
                    return true;
                }
            }
        }
        return false;
    }

    bool comparison_operands(
        const xair_value_id condition,
        xair_value_id& left,
        xair_value_id& right,
        std::string& comparison) const {
        xair_op_id operation = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t input_count = 0;
        if (xair_value_definition(&module, condition, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(&module, operation, &view) != XAIR_OK ||
            xair_op_inputs(&module, operation, &inputs, &input_count) != XAIR_OK) {
            return false;
        }
        if ((view.opcode == XAIR_OP_EQ || view.opcode == XAIR_OP_NE ||
             view.opcode == XAIR_OP_XOR) &&
            input_count >= 2) {
            std::int64_t boolean_constant = 0;
            if (constant_i64(inputs[1], boolean_constant) &&
                xair_value_type(&module, inputs[1]).bits == 1) {
                return comparison_operands(inputs[0], left, right, comparison);
            }
            if (constant_i64(inputs[0], boolean_constant) &&
                xair_value_type(&module, inputs[0]).bits == 1) {
                return comparison_operands(inputs[1], left, right, comparison);
            }
        }
        const auto set_direct = [&](const char* name) {
            if (input_count < 2) return false;
            left = inputs[0];
            right = inputs[1];
            comparison = name;
            return true;
        };
        switch (view.opcode) {
        case XAIR_OP_EQ: return set_direct("eq");
        case XAIR_OP_NE: return set_direct("ne");
        case XAIR_OP_ULT: return set_direct("ult");
        case XAIR_OP_ULE: return set_direct("ule");
        case XAIR_OP_SLT: return set_direct("slt");
        case XAIR_OP_SLE: return set_direct("sle");
        case XAIR_OP_FLAG_ZF:
        case XAIR_OP_FLAG_CF:
            if (input_count == 0) return false;
            break;
        default: return false;
        }
        xair_op_id flags_operation = XAIR_INVALID_ID;
        xair_op_view_v3 flags_view{};
        const xair_value_id* flag_inputs = nullptr;
        std::size_t flag_count = 0;
        if (xair_value_definition(&module, inputs[0], &flags_operation) != XAIR_OK ||
            flags_operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(&module, flags_operation, &flags_view) != XAIR_OK ||
            flags_view.opcode != XAIR_OP_FLAGS_SUB ||
            xair_op_inputs(&module, flags_operation, &flag_inputs, &flag_count) != XAIR_OK ||
            flag_count < 2) return false;
        left = flag_inputs[0];
        right = flag_inputs[1];
        comparison = view.opcode == XAIR_OP_FLAG_CF ? "ult" : "eq";
        return true;
    }

    xair_value_id edge_argument(
        const xair_cfg_node_id source,
        const xair_block_id target,
        const std::size_t parameter) const {
        const xair_cfg_node* node = xair_cfg_get_node(&cfg, source);
        if (node == nullptr || node->ir_block == XAIR_INVALID_ID) return XAIR_INVALID_ID;
        xair_term_view term{};
        if (xair_block_terminator(&module, node->ir_block, &term) != XAIR_OK) {
            return XAIR_INVALID_ID;
        }
        if (term.true_target == target && parameter < term.true_arg_count) {
            return term.true_args[parameter];
        }
        if (term.false_target == target && parameter < term.false_arg_count) {
            return term.false_args[parameter];
        }
        return XAIR_INVALID_ID;
    }

    void recover_induction(
        const LoopRecord& loop,
        const std::vector<EdgeRecord>& edges,
        const std::set<std::pair<xair_cfg_node_id, xair_cfg_node_id>>& back_edges,
        ControlRegion& region) const {
        const xair_cfg_node* header_node = xair_cfg_get_node(&cfg, loop.header);
        if (header_node == nullptr || header_node->ir_block == XAIR_INVALID_ID ||
            region.condition == XAIR_INVALID_ID) return;
        xair_value_id left = XAIR_INVALID_ID;
        xair_value_id right = XAIR_INVALID_ID;
        std::string comparison;
        if (!comparison_operands(region.condition, left, right, comparison)) return;
        const std::size_t parameter_count =
            xair_block_param_count(&module, header_node->ir_block);
        for (std::size_t parameter = 0; parameter < parameter_count; ++parameter) {
            xair_value_id variable = XAIR_INVALID_ID;
            if (xair_block_param_value(
                    &module, header_node->ir_block, parameter, &variable) != XAIR_OK) continue;
            const bool left_depends = depends_on(left, variable);
            const bool right_depends = depends_on(right, variable);
            if (left_depends == right_depends) continue;
            xair_value_id update = XAIR_INVALID_ID;
            for (const auto& [source, target] : back_edges) {
                if (target != loop.header || !loop.members.contains(source)) continue;
                const xair_value_id argument = edge_argument(
                    source, header_node->ir_block, parameter);
                if (argument != XAIR_INVALID_ID) update = argument;
            }
            std::int64_t step = 0;
            if (update == XAIR_INVALID_ID || !induction_step(update, variable, step)) continue;
            xair_value_id initial = XAIR_INVALID_ID;
            for (const EdgeRecord& edge : edges) {
                if (edge.edge.dst != loop.header || loop.members.contains(edge.edge.src)) continue;
                const xair_value_id argument = edge_argument(
                    edge.edge.src, header_node->ir_block, parameter);
                if (argument != XAIR_INVALID_ID) initial = argument;
            }
            region.induction.recovered = true;
            region.induction.variable = variable;
            region.induction.initial = initial;
            region.induction.bound = left_depends ? right : left;
            region.induction.step = step;
            region.induction.comparison = comparison;
            return;
        }
        (void)recover_stored_induction(loop, left, right, comparison, region);
    }

    ControlEvidence node_evidence(const xair_cfg_node_id node_id) const {
        ControlEvidence evidence;
        evidence.nodes.push_back(node_id);
        const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
        if (node == nullptr) return evidence;
        evidence.begin = node->start;
        evidence.end = node->end;
        evidence.confidence = node->semantic_coverage == XAIR_CFG_SEMANTICS_EXACT
            ? XAIR_CONFIDENCE_EXACT
            : node->semantic_coverage == XAIR_CFG_SEMANTICS_PARTIAL
            ? XAIR_CONFIDENCE_MEDIUM : XAIR_CONFIDENCE_LOW;
        if (node->ir_block == XAIR_INVALID_ID) return evidence;
        const xair_source_id* sources = nullptr;
        std::size_t source_count = 0;
        if (xair_terminator_sources(
                &module, node->ir_block, &sources, &source_count) != XAIR_OK) {
            return evidence;
        }
        for (std::size_t index = 0; index < source_count; ++index) {
            xair_source_record source{};
            if (xair_module_get_source(&module, sources[index], &source) != XAIR_OK) {
                continue;
            }
            evidence.confidence = conservative_confidence(
                evidence.confidence, source.confidence);
            if (source.location.instruction_va == 0) continue;
            const std::uint64_t begin = source.location.instruction_va;
            const std::uint64_t end = saturating_end(
                begin, source.location.instruction_length);
            if (evidence.begin == 0 || begin < evidence.begin) evidence.begin = begin;
            if (end > evidence.end) evidence.end = end;
        }
        return evidence;
    }

    ControlEvidence region_evidence(
        const std::vector<xair_cfg_node_id>& nodes,
        const std::vector<xair_cfg_edge_id>& edges = {}) const {
        ControlEvidence evidence;
        evidence.nodes = nodes;
        evidence.edges = edges;
        for (const xair_cfg_node_id node : nodes) {
            const ControlEvidence current = node_evidence(node);
            if (evidence.begin == 0 ||
                (current.begin != 0 && current.begin < evidence.begin)) {
                evidence.begin = current.begin;
            }
            if (current.end > evidence.end) evidence.end = current.end;
            evidence.confidence = conservative_confidence(
                evidence.confidence, current.confidence);
        }
        for (const xair_cfg_edge_id edge_id : edges) {
            const xair_cfg_edge* edge = xair_cfg_get_edge(&cfg, edge_id);
            if (edge != nullptr) {
                evidence.confidence = conservative_confidence(
                    evidence.confidence, edge_confidence(edge->confidence));
            }
        }
        return evidence;
    }

    bool terminal_node(const xair_cfg_node_id node_id) const {
        const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
        if (node == nullptr) return false;
        if (node->ir_block != XAIR_INVALID_ID) {
            xair_term_view term{};
            if (xair_block_terminator(&module, node->ir_block, &term) == XAIR_OK) {
                if (term.kind == XAIR_TERM_VIEW_RETURN ||
                    term.kind == XAIR_TERM_VIEW_TRAP ||
                    term.kind == XAIR_TERM_VIEW_FAULT) {
                    return true;
                }
            }
        }
        for (std::uint16_t index = 0; index < node->edge_count; ++index) {
            const xair_cfg_edge* edge = xair_cfg_get_edge(
                &cfg, node->edge_offset + index);
            if (edge != nullptr && edge->kind == XAIR_EDGE_RETURN) return true;
        }
        return false;
    }

    static void add_region(
        ControlView& view,
        ControlRegion region,
        const ControlOptions& options) {
        if (options.max_regions != 0 && view.regions.size() >= options.max_regions) {
            ++view.omitted_regions;
            view.truncated = true;
            view.fallback = true;
            return;
        }
        region.stable_id = "R" + std::to_string(view.regions.size() + 1);
        view.regions.push_back(std::move(region));
    }

    ControlView build_uncached(
        const xair_function_id function,
        const ControlOptions& options) const {
        ControlView view;
        view.function = function;
        const xair_function* raw_function = xair_cfg_get_function(&cfg, function);
        if (raw_function == nullptr) {
            view.status = XAIR_ERR_BAD_ARG;
            return view;
        }

        std::size_t function_node_count = 0;
        const xair_cfg_node_id* function_nodes = xair_cfg_function_nodes(
            &cfg, function, &function_node_count);
        if (function_nodes == nullptr || function_node_count == 0) {
            view.status = XAIR_ERR_INCOMPLETE;
            return view;
        }
        std::unordered_set<xair_cfg_node_id> node_set;
        node_set.reserve(function_node_count);
        for (std::size_t index = 0; index < function_node_count; ++index) {
            node_set.insert(function_nodes[index]);
            const xair_cfg_node* node = xair_cfg_get_node(&cfg, function_nodes[index]);
            if (node != nullptr && node->start == raw_function->entry) {
                view.entry = function_nodes[index];
            }
        }
        /* CFG function ownership can conservatively split jump-table arms into
         * root-like fragments. A resolved indirect jump is still an
         * intra-procedural transfer, so include its cases/default in this
         * semantic function without following call edges. */
        const std::size_t resolved_indirects = xair_cfg_indirect_count(&cfg);
        for (std::size_t index = 0; index < resolved_indirects; ++index) {
            const xair_indirect_resolution* indirect = xair_cfg_get_indirect(&cfg, index);
            if (indirect == nullptr || indirect->kind != XAIR_INDIRECT_SWITCH) continue;
            const xair_cfg_edge* source_edge = xair_cfg_get_edge(&cfg, indirect->edge);
            if (source_edge == nullptr || !node_set.contains(source_edge->src)) continue;
            std::size_t candidate_count = 0;
            const std::uint64_t* candidates = xair_cfg_indirect_candidates(
                &cfg, index, &candidate_count);
            for (std::size_t candidate = 0; candidate < candidate_count; ++candidate) {
                const xair_cfg_node_id target = xair_cfg_find_node_start(
                    &cfg, candidates[candidate]);
                if (target != XAIR_CFG_INVALID_ID) node_set.insert(target);
            }
            if ((indirect->flags & XAIR_INDIRECT_RESOLUTION_HAS_DEFAULT) != 0) {
                const xair_cfg_node_id target = xair_cfg_find_node_start(
                    &cfg, indirect->default_target);
                if (target != XAIR_CFG_INVALID_ID) node_set.insert(target);
            }
        }

        xair_analysis_options analysis_options{};
        xair_analysis_options_init(&analysis_options);
        xair_cfg_function_analysis* analysis = nullptr;
        const xair_status analysis_status = xair_cfg_analyze_function_ex(
            &cfg, function, &analysis_options, &analysis);
        if (analysis_status != XAIR_OK || analysis == nullptr) {
            view.fallback = true;
        }

        if (analysis != nullptr) {
            const xair_cfg_node_id* rpo = nullptr;
            const std::size_t rpo_count =
                xair_cfg_analysis_reverse_postorder(analysis, &rpo);
            view.block_order.reserve(function_node_count);
            for (std::size_t index = 0; index < rpo_count; ++index) {
                if (node_set.contains(rpo[index])) view.block_order.push_back(rpo[index]);
            }
        }
        std::vector<xair_cfg_node_id> remaining(node_set.begin(), node_set.end());
        std::sort(remaining.begin(), remaining.end(),
            [&](const xair_cfg_node_id left, const xair_cfg_node_id right) {
                const xair_cfg_node* left_node = xair_cfg_get_node(&cfg, left);
                const xair_cfg_node* right_node = xair_cfg_get_node(&cfg, right);
                const std::uint64_t left_start = left_node == nullptr ? 0 : left_node->start;
                const std::uint64_t right_start = right_node == nullptr ? 0 : right_node->start;
                return left_start != right_start ? left_start < right_start : left < right;
            });
        for (const xair_cfg_node_id node : remaining) {
            if (std::find(view.block_order.begin(), view.block_order.end(), node) ==
                view.block_order.end()) {
                view.block_order.push_back(node);
                view.fallback = true;
            }
        }
        if (view.entry == XAIR_CFG_INVALID_ID) view.entry = view.block_order.front();

        std::unordered_map<xair_cfg_node_id, std::vector<EdgeRecord>> outgoing;
        std::unordered_map<xair_cfg_node_id, std::size_t> incoming;
        std::vector<EdgeRecord> edges;
        std::vector<EdgeRecord> transfer_edges;
        for (const xair_cfg_node_id node_id : remaining) {
            const xair_cfg_node* node = xair_cfg_get_node(&cfg, node_id);
            if (node == nullptr) continue;
            for (std::uint16_t index = 0; index < node->edge_count; ++index) {
                const xair_cfg_edge_id edge_id = node->edge_offset + index;
                const xair_cfg_edge* edge = xair_cfg_get_edge(&cfg, edge_id);
                if (edge == nullptr) continue;
                EdgeRecord record{edge_id, *edge};
                transfer_edges.push_back(record);
                if (is_call_edge(edge->kind)) continue;
                edges.push_back(record);
                outgoing[node_id].push_back(record);
                if (node_set.contains(edge->dst)) ++incoming[edge->dst];
            }
        }

        std::unordered_map<xair_cfg_node_id, std::size_t> switch_sources;
        const std::size_t indirect_count = xair_cfg_indirect_count(&cfg);
        for (std::size_t index = 0; index < indirect_count; ++index) {
            const xair_indirect_resolution* indirect = xair_cfg_get_indirect(&cfg, index);
            if (indirect == nullptr || indirect->edge == XAIR_CFG_INVALID_ID) continue;
            const xair_cfg_edge* edge = xair_cfg_get_edge(&cfg, indirect->edge);
            if (edge != nullptr && node_set.contains(edge->src) &&
                (indirect->kind == XAIR_INDIRECT_SWITCH ||
                 indirect->candidate_count >= 3)) {
                switch_sources.emplace(edge->src, index);
            }
        }

        std::set<std::pair<xair_cfg_node_id, xair_cfg_node_id>> back_edges;
        std::vector<LoopRecord> loops;
        if (analysis != nullptr) {
            const xair_cfg_node_pair* raw_back_edges = nullptr;
            const std::size_t back_edge_count =
                xair_cfg_analysis_back_edges(analysis, &raw_back_edges);
            for (std::size_t index = 0; index < back_edge_count; ++index) {
                back_edges.emplace(raw_back_edges[index].src, raw_back_edges[index].dst);
            }
            const xair_cfg_loop* raw_loops = nullptr;
            const xair_cfg_node_id* loop_nodes = nullptr;
            const std::size_t loop_count =
                xair_cfg_analysis_loops(analysis, &raw_loops, &loop_nodes);
            loops.reserve(loop_count);
            for (std::size_t index = 0; index < loop_count; ++index) {
                LoopRecord loop;
                loop.header = raw_loops[index].header;
                loop.irreducible = raw_loops[index].irreducible != 0;
                for (std::uint32_t member = 0; member < raw_loops[index].node_count;
                     ++member) {
                    loop.members.insert(loop_nodes[raw_loops[index].node_offset + member]);
                }
                loops.push_back(std::move(loop));
            }
            view.irreducible = xair_cfg_analysis_is_irreducible(analysis) != 0;
        }

        std::unordered_set<xair_cfg_node_id> covered;
        for (const LoopRecord& loop : loops) {
            std::vector<xair_cfg_node_id> members(loop.members.begin(), loop.members.end());
            std::sort(members.begin(), members.end());
            ControlRegion region;
            region.header = loop.header;
            region.condition_node = loop.header;
            region.nodes = members;
            region.evidence = region_evidence(members);
            const auto header_edges = outgoing.find(loop.header);
            bool header_exit = false;
            bool latch_condition = false;
            if (header_edges != outgoing.end()) {
                for (const EdgeRecord& edge : header_edges->second) {
                    if (is_conditional_edge(edge.edge.kind) &&
                        !loop.members.contains(edge.edge.dst)) {
                        header_exit = true;
                        region.condition = edge.edge.condition;
                        region.join = edge.edge.dst;
                    }
                }
            }
            for (const auto& [source, target] : back_edges) {
                if (target != loop.header || source == loop.header) continue;
                const auto latch_edges = outgoing.find(source);
                if (latch_edges == outgoing.end()) continue;
                for (const EdgeRecord& edge : latch_edges->second) {
                    if (is_conditional_edge(edge.edge.kind)) {
                        latch_condition = true;
                        region.condition = edge.edge.condition;
                        region.condition_node = source;
                        for (const EdgeRecord& latch_edge : latch_edges->second) {
                            if (latch_edge.edge.dst != loop.header &&
                                !loop.members.contains(latch_edge.edge.dst)) {
                                region.join = latch_edge.edge.dst;
                            }
                        }
                    }
                }
            }
            if (loop.irreducible) region.kind = ControlRegionKind::irreducible;
            else if (header_exit) region.kind = ControlRegionKind::while_loop;
            else if (latch_condition) region.kind = ControlRegionKind::do_while_loop;
            else region.kind = ControlRegionKind::while_loop;
            recover_induction(loop, edges, back_edges, region);
            add_region(view, std::move(region), options);
            covered.insert(members.begin(), members.end());
        }

        for (const xair_cfg_node_id node : view.block_order) {
            const auto found = outgoing.find(node);
            if (found == outgoing.end()) continue;
            std::vector<EdgeRecord> conditional;
            for (const EdgeRecord& edge : found->second) {
                if (is_conditional_edge(edge.edge.kind)) conditional.push_back(edge);
            }
            if (found->second.size() >= 3 || switch_sources.contains(node)) {
                ControlRegion region;
                region.kind = ControlRegionKind::switch_region;
                region.header = node;
                region.condition_node = node;
                region.nodes.push_back(node);
                for (const EdgeRecord& edge : found->second) {
                    region.evidence.edges.push_back(edge.id);
                }
                const auto switch_entry = switch_sources.find(node);
                if (switch_entry != switch_sources.end()) {
                    const xair_indirect_resolution* indirect =
                        xair_cfg_get_indirect(&cfg, switch_entry->second);
                    if (indirect != nullptr) {
                        region.condition = indirect->index_expr;
                        if (analysis != nullptr) {
                            region.join = xair_cfg_analysis_immediate_postdominator(
                                analysis, node);
                        }
                        std::size_t candidate_count = 0;
                        const std::uint64_t* candidates =
                            xair_cfg_indirect_candidates(
                                &cfg, switch_entry->second, &candidate_count);
                        const bool bounded = indirect->upper_bound >= indirect->lower_bound;
                        const std::uint64_t span = bounded
                            ? static_cast<std::uint64_t>(indirect->upper_bound) -
                                  static_cast<std::uint64_t>(indirect->lower_bound) + 1U
                            : 0;
                        const std::uint32_t unsafe_flags =
                            XAIR_INDIRECT_RESOLUTION_TRUNCATED |
                            XAIR_INDIRECT_RESOLUTION_BUDGET_LIMITED |
                            XAIR_INDIRECT_RESOLUTION_INVALID_READ;
                        region.switch_values_complete =
                            indirect->kind == XAIR_INDIRECT_SWITCH &&
                            candidates != nullptr && candidate_count != 0 && bounded &&
                            span == candidate_count;
                        bool complete = region.switch_values_complete &&
                            (indirect->flags & unsafe_flags) == 0;
                        for (std::size_t candidate = 0;
                             candidate < candidate_count; ++candidate) {
                            ControlSwitchCase item;
                            item.value = indirect->lower_bound +
                                static_cast<std::int64_t>(candidate);
                            item.raw_target = candidates[candidate];
                            item.target = xair_cfg_find_node_start(&cfg, item.raw_target);
                            if (!node_set.contains(item.target)) complete = false;
                            region.switch_cases.push_back(item);
                        }
                        if ((indirect->flags &
                             XAIR_INDIRECT_RESOLUTION_HAS_DEFAULT) != 0) {
                            region.switch_default_raw = indirect->default_target;
                            region.switch_default = xair_cfg_find_node_start(
                                &cfg, indirect->default_target);
                            if (!node_set.contains(region.switch_default)) complete = false;
                        }
                        region.switch_mapping_complete = complete;
                    }
                }
                region.evidence = region_evidence(region.nodes, region.evidence.edges);
                add_region(view, std::move(region), options);
                covered.insert(node);
                continue;
            }
            if (conditional.size() != 2 ||
                conditional[0].edge.dst == conditional[1].edge.dst ||
                std::any_of(loops.begin(), loops.end(),
                    [node](const LoopRecord& loop) { return loop.header == node; })) {
                continue;
            }
            ControlRegion region;
            region.header = node;
            region.condition_node = node;
            region.condition = conditional.front().edge.condition;
            region.nodes.push_back(node);
            const bool first_terminal = terminal_node(conditional[0].edge.dst);
            const bool second_terminal = terminal_node(conditional[1].edge.dst);
            if (first_terminal != second_terminal) {
                region.kind = ControlRegionKind::early_return;
            } else if (analysis != nullptr) {
                region.join = xair_cfg_analysis_immediate_postdominator(analysis, node);
                region.kind = region.join != XAIR_CFG_INVALID_ID && region.join != node
                    ? ControlRegionKind::if_else : ControlRegionKind::terminal_if;
            } else {
                region.kind = ControlRegionKind::terminal_if;
            }
            std::vector<xair_cfg_edge_id> conditional_ids;
            conditional_ids.reserve(conditional.size());
            for (const EdgeRecord& edge : conditional) conditional_ids.push_back(edge.id);
            region.evidence = region_evidence(region.nodes, conditional_ids);
            add_region(view, std::move(region), options);
            covered.insert(node);
        }

        for (std::size_t index = 0; index < view.block_order.size();) {
            std::vector<xair_cfg_node_id> sequence{view.block_order[index]};
            std::size_t cursor = index;
            while (cursor + 1 < view.block_order.size()) {
                const xair_cfg_node_id current = view.block_order[cursor];
                const xair_cfg_node_id next = view.block_order[cursor + 1];
                const auto found = outgoing.find(current);
                if (found == outgoing.end() || found->second.size() != 1 ||
                    found->second.front().edge.dst != next || incoming[next] != 1 ||
                    back_edges.contains({current, next}) || covered.contains(current)) {
                    break;
                }
                sequence.push_back(next);
                ++cursor;
            }
            if (sequence.size() > 1) {
                ControlRegion region;
                region.kind = ControlRegionKind::sequence;
                region.header = sequence.front();
                region.nodes = sequence;
                region.evidence = region_evidence(sequence);
                add_region(view, std::move(region), options);
                covered.insert(sequence.begin(), sequence.end());
                index = cursor + 1;
            } else {
                ++index;
            }
        }

        if (view.irreducible) {
            ControlRegion region;
            region.kind = ControlRegionKind::irreducible;
            region.header = view.entry;
            region.nodes = view.block_order;
            region.evidence = region_evidence(region.nodes);
            add_region(view, std::move(region), options);
            view.fallback = true;
        }
        for (const xair_cfg_node_id node : view.block_order) {
            if (covered.contains(node)) continue;
            ControlRegion region;
            region.kind = ControlRegionKind::sequence;
            region.header = node;
            region.nodes.push_back(node);
            region.evidence = node_evidence(node);
            add_region(view, std::move(region), options);
        }

        for (const EdgeRecord& record : transfer_edges) {
            if (options.max_transfers != 0 &&
                view.transfers.size() >= options.max_transfers) {
                ++view.omitted_transfers;
                view.truncated = true;
                view.fallback = true;
                continue;
            }
            ControlTransfer transfer;
            transfer.edge = record.id;
            transfer.source = record.edge.src;
            transfer.target = record.edge.dst;
            transfer.condition = record.edge.condition;
            transfer.raw_target = record.edge.raw_target;
            transfer.conditional = is_conditional_edge(record.edge.kind);
            transfer.condition_when_true =
                record.edge.kind == XAIR_EDGE_CBRANCH_TRUE;
            transfer.evidence = node_evidence(record.edge.src);
            transfer.evidence.edges.push_back(record.id);
            transfer.evidence.confidence = conservative_confidence(
                transfer.evidence.confidence, edge_confidence(record.edge.confidence));
            if (is_call_edge(record.edge.kind)) {
                transfer.kind = ControlTransferKind::call_target;
            } else if (record.edge.kind == XAIR_EDGE_RETURN) {
                transfer.kind = ControlTransferKind::return_from_function;
            } else if (back_edges.contains({record.edge.src, record.edge.dst})) {
                transfer.kind = ControlTransferKind::continue_loop;
            } else {
                bool loop_break = false;
                for (const LoopRecord& loop : loops) {
                    if (loop.members.contains(record.edge.src) &&
                        !loop.members.contains(record.edge.dst)) {
                        loop_break = true;
                        break;
                    }
                }
                if (loop_break) transfer.kind = ControlTransferKind::break_loop;
                else if (record.edge.kind == XAIR_EDGE_CBRANCH_TRUE) {
                    transfer.kind = ControlTransferKind::branch_true;
                } else if (record.edge.kind == XAIR_EDGE_CBRANCH_FALSE) {
                    transfer.kind = ControlTransferKind::branch_false;
                } else if (record.edge.kind == XAIR_EDGE_FALLTHROUGH ||
                           record.edge.kind == XAIR_EDGE_CALL_RETURN) {
                    transfer.kind = ControlTransferKind::fallthrough;
                } else if (record.edge.kind == XAIR_EDGE_INDIRECT_JUMP) {
                    transfer.kind = ControlTransferKind::switch_case;
                } else if (record.edge.kind == XAIR_EDGE_UNRESOLVED ||
                           record.edge.kind == XAIR_EDGE_EXCEPTION) {
                    transfer.kind = ControlTransferKind::unresolved;
                } else {
                    transfer.kind = ControlTransferKind::goto_label;
                }
            }
            transfer.explicit_goto = view.irreducible ||
                transfer.kind == ControlTransferKind::goto_label ||
                transfer.kind == ControlTransferKind::unresolved;
            view.transfers.push_back(std::move(transfer));
        }

        if (analysis != nullptr) xair_cfg_function_analysis_destroy(analysis);
        return view;
    }

    ControlView build(
        const xair_function_id function,
        const ControlOptions& options) const {
        const CacheKey key{function, options};
        {
            const std::scoped_lock lock(mutex);
            const auto found = cache.find(key);
            if (found != cache.end()) return found->second;
        }
        ControlView result = build_uncached(function, options);
        const std::scoped_lock lock(mutex);
        const auto [entry, inserted] = cache.emplace(key, result);
        return inserted ? result : entry->second;
    }
};

ControlRecovery::ControlRecovery(const xair_cfg& cfg, const xair_module& module)
    : impl_(std::make_unique<Impl>(cfg, module)) {}
ControlRecovery::~ControlRecovery() = default;
ControlRecovery::ControlRecovery(ControlRecovery&&) noexcept = default;
ControlRecovery& ControlRecovery::operator=(ControlRecovery&&) noexcept = default;

ControlView ControlRecovery::build(
    const xair_function_id function,
    const ControlOptions& options) const {
    return impl_->build(function, options);
}

std::size_t ControlRecovery::cache_size() const noexcept {
    const std::scoped_lock lock(impl_->mutex);
    return impl_->cache.size();
}

const char* control_region_kind_name(const ControlRegionKind kind) noexcept {
    switch (kind) {
    case ControlRegionKind::sequence: return "sequence";
    case ControlRegionKind::terminal_if: return "terminal-if";
    case ControlRegionKind::if_else: return "if-else";
    case ControlRegionKind::early_return: return "early-return";
    case ControlRegionKind::while_loop: return "while";
    case ControlRegionKind::do_while_loop: return "do-while";
    case ControlRegionKind::switch_region: return "switch";
    case ControlRegionKind::irreducible: return "irreducible";
    case ControlRegionKind::block:
    default: return "block";
    }
}

const char* control_transfer_kind_name(const ControlTransferKind kind) noexcept {
    switch (kind) {
    case ControlTransferKind::fallthrough: return "fallthrough";
    case ControlTransferKind::branch_true: return "true";
    case ControlTransferKind::branch_false: return "false";
    case ControlTransferKind::switch_case: return "case";
    case ControlTransferKind::call_target: return "call";
    case ControlTransferKind::goto_label: return "goto";
    case ControlTransferKind::break_loop: return "break";
    case ControlTransferKind::continue_loop: return "continue";
    case ControlTransferKind::return_from_function: return "return";
    case ControlTransferKind::trap: return "trap";
    case ControlTransferKind::fault: return "fault";
    case ControlTransferKind::unresolved:
    default: return "unresolved";
    }
}

} // namespace airece
