#include <airece/semantic/expression_view.hpp>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace airece {

namespace {

constexpr int precedence_select = 1;
constexpr int precedence_compare = 2;
constexpr int precedence_or = 3;
constexpr int precedence_xor = 4;
constexpr int precedence_and = 5;
constexpr int precedence_shift = 6;
constexpr int precedence_add = 7;
constexpr int precedence_multiply = 8;
constexpr int precedence_unary = 9;
constexpr int precedence_atom = 10;

std::string hex_value(const std::uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << value;
    return output.str();
}

std::string type_width(const xair_type type) {
    std::ostringstream output;
    switch (type.kind) {
    case XAIR_TYPE_ADDR:
        output << "addr";
        break;
    case XAIR_TYPE_FLAGS:
        output << "flags";
        break;
    case XAIR_TYPE_MEM:
        output << "mem";
        break;
    case XAIR_TYPE_INT:
    default:
        output << "bits";
        break;
    }
    output << type.bits;
    return output.str();
}

ExpressionDisplayKind display_kind(const xair_opcode opcode) {
    switch (opcode) {
    case XAIR_OP_CONST_U64:
    case XAIR_OP_CONST_WIDE:
        return ExpressionDisplayKind::constant;
    case XAIR_OP_EQ:
    case XAIR_OP_NE:
    case XAIR_OP_ULT:
    case XAIR_OP_ULE:
    case XAIR_OP_SLT:
    case XAIR_OP_SLE:
        return ExpressionDisplayKind::comparison;
    case XAIR_OP_ADDR_ADD:
    case XAIR_OP_ADDR_SUB:
    case XAIR_OP_INT_TO_ADDR:
    case XAIR_OP_ADDR_TO_INT:
        return ExpressionDisplayKind::address;
    case XAIR_OP_LOAD:
        return ExpressionDisplayKind::load;
    case XAIR_OP_STORE:
        return ExpressionDisplayKind::store;
    case XAIR_OP_SELECT:
        return ExpressionDisplayKind::select;
    case XAIR_OP_CALL:
        return ExpressionDisplayKind::call_result;
    case XAIR_OP_FLAG_ZF:
    case XAIR_OP_FLAG_CF:
    case XAIR_OP_FLAG_OF:
    case XAIR_OP_FLAG_SF:
    case XAIR_OP_FLAG_PF:
    case XAIR_OP_FLAG_AF:
    case XAIR_OP_FLAGS_ADD:
    case XAIR_OP_FLAGS_SUB:
    case XAIR_OP_FLAGS_LOGIC:
    case XAIR_OP_FLAGS_SHL:
        return ExpressionDisplayKind::flag;
    case XAIR_OP_INTRINSIC:
        return ExpressionDisplayKind::intrinsic;
    case XAIR_OP_OPAQUE_PURE:
    case XAIR_OP_OPAQUE_EFFECT:
        return ExpressionDisplayKind::opaque;
    case XAIR_OP_UNKNOWN:
    case XAIR_OP_UNDEF:
        return ExpressionDisplayKind::unknown;
    case XAIR_OP_ZEXT:
    case XAIR_OP_SEXT:
    case XAIR_OP_TRUNC:
    case XAIR_OP_EXTRACT:
        return ExpressionDisplayKind::unary;
    default:
        return ExpressionDisplayKind::binary;
    }
}

} // namespace

struct ExpressionRecovery::Impl {
    struct Location {
        xair_block_id block{XAIR_INVALID_ID};
        std::size_t position{};
    };

    struct CacheKey {
        xair_value_id value{XAIR_INVALID_ID};
        ExpressionOptions options;

        bool operator==(const CacheKey&) const = default;
    };

    struct CacheHash {
        std::size_t operator()(const CacheKey& key) const noexcept {
            std::size_t hash = key.value;
            const auto mix = [&hash](const std::size_t value) {
                hash ^= value + static_cast<std::size_t>(0x9e3779b9U) +
                    (hash << 6U) + (hash >> 2U);
            };
            mix(key.options.max_depth);
            mix(key.options.max_nodes);
            mix(key.options.max_tokens);
            mix(key.options.max_characters);
            mix(key.options.inline_single_use ? 1U : 0U);
            mix(key.options.inline_loads ? 1U : 0U);
            return hash;
        }
    };

    struct Rendered {
        std::string text;
        int precedence{precedence_atom};
        bool boolean_constant{};
        bool boolean_value{};
    };

    struct RenderState {
        const ExpressionOptions& options;
        const std::unordered_map<xair_value_id, std::string>* value_names{};
        std::size_t nodes{};
        bool truncated{};
        std::size_t omitted{};
        SourceSpan source;
        bool has_confidence{};
        std::vector<xair_op_id> operations;
        std::vector<xair_value_id> values;
        std::unordered_set<xair_value_id> active;
    };

    explicit Impl(const xair_module& input) : module(&input) {
        locations.resize(xair_module_op_count(module));
        use_counts.assign(xair_module_value_count(module), 0);
        const std::size_t block_count = xair_module_block_count(module);
        for (std::size_t block_index = 0; block_index < block_count; ++block_index) {
            const auto block = static_cast<xair_block_id>(block_index);
            const xair_op_id* operations = nullptr;
            std::size_t operation_count = 0;
            if (xair_block_ops(module, block, &operations, &operation_count) != XAIR_OK) {
                continue;
            }
            for (std::size_t position = 0; position < operation_count; ++position) {
                const xair_op_id operation = operations[position];
                if (operation < locations.size()) locations[operation] = {block, position};
                const xair_value_id* inputs = nullptr;
                std::size_t input_count = 0;
                if (xair_op_inputs(module, operation, &inputs, &input_count) != XAIR_OK) {
                    continue;
                }
                for (std::size_t input_index = 0; input_index < input_count; ++input_index) {
                    if (inputs[input_index] < use_counts.size()) ++use_counts[inputs[input_index]];
                }
            }
            xair_term_view terminator{};
            if (xair_block_terminator(module, block, &terminator) != XAIR_OK) continue;
            track_terminator_use(terminator.condition);
            for (std::size_t index = 0; index < terminator.true_arg_count; ++index) {
                track_terminator_use(terminator.true_args[index]);
            }
            for (std::size_t index = 0; index < terminator.false_arg_count; ++index) {
                track_terminator_use(terminator.false_args[index]);
            }
        }
    }

    void track_terminator_use(const xair_value_id value) {
        if (value < use_counts.size()) ++use_counts[value];
    }

    std::string leaf(const xair_value_id value, const RenderState& state) const {
        if (state.value_names != nullptr) {
            const auto named = state.value_names->find(value);
            if (named != state.value_names->end()) return named->second;
        }
        const char* name = xair_value_name(module, value);
        if (name != nullptr && name[0] != '\0') return name;
        return "v" + std::to_string(value);
    }

    static std::string parenthesize(const Rendered& value, const int precedence) {
        if (value.precedence < precedence) return '(' + value.text + ')';
        return value.text;
    }

    void track_value(RenderState& state, const xair_value_id value) const {
        if (std::find(state.values.begin(), state.values.end(), value) == state.values.end()) {
            state.values.push_back(value);
        }
    }

    void track_operation(RenderState& state, const xair_op_id operation) const {
        if (std::find(state.operations.begin(), state.operations.end(), operation) ==
            state.operations.end()) {
            state.operations.push_back(operation);
        }
        const xair_source_id* sources = nullptr;
        std::size_t source_count = 0;
        if (xair_op_sources(module, operation, &sources, &source_count) != XAIR_OK) return;
        for (std::size_t index = 0; index < source_count; ++index) {
            xair_source_record record{};
            if (xair_module_get_source(module, sources[index], &record) != XAIR_OK) continue;
            ++state.source.record_count;
            state.source.synthetic = state.source.synthetic ||
                record.kind != XAIR_SOURCE_MACHINE ||
                (record.location.flags & XAIR_SOURCE_FLAG_SYNTHETIC) != 0;
            if (!state.has_confidence || record.confidence < state.source.confidence) {
                state.source.confidence = record.confidence;
                state.has_confidence = true;
            }
            if (record.location.instruction_va == 0) continue;
            const std::uint64_t begin = record.location.instruction_va;
            const std::uint64_t length = record.location.instruction_length;
            const std::uint64_t end = begin > std::numeric_limits<std::uint64_t>::max() - length
                ? std::numeric_limits<std::uint64_t>::max() : begin + length;
            if (state.source.begin == 0 || begin < state.source.begin) state.source.begin = begin;
            if (end > state.source.end) state.source.end = end;
        }
    }

    bool clobbers_load(const xair_op_id operation) const {
        xair_op_view_v3 view{};
        if (xair_module_get_op_v3(module, operation, &view) != XAIR_OK) return true;
        if (view.opcode == XAIR_OP_STORE || view.opcode == XAIR_OP_CALL ||
            view.opcode == XAIR_OP_OPAQUE_EFFECT ||
            view.opcode == XAIR_OP_MEMORY_BARRIER) {
            return true;
        }
        xair_op_attributes attributes{};
        if (xair_op_attributes_get(module, operation, &attributes) != XAIR_OK) return true;
        constexpr std::uint32_t unsafe = XAIR_EFFECT_WRITE_MEMORY |
            XAIR_EFFECT_VOLATILE | XAIR_EFFECT_ATOMIC | XAIR_EFFECT_BARRIER;
        return (attributes.effects & unsafe) != 0;
    }

    bool load_is_safe(const xair_op_id load, const xair_op_id horizon) const {
        if (load == horizon) return true;
        if (load >= locations.size() || horizon >= locations.size()) return false;
        const Location& from = locations[load];
        const Location& to = locations[horizon];
        if (from.block == XAIR_INVALID_ID || from.block != to.block ||
            from.position >= to.position) {
            return false;
        }
        xair_op_attributes attributes{};
        if (xair_op_attributes_get(module, load, &attributes) != XAIR_OK ||
            (attributes.effects & (XAIR_EFFECT_VOLATILE | XAIR_EFFECT_ATOMIC)) != 0) {
            return false;
        }
        const xair_op_id* operations = nullptr;
        std::size_t count = 0;
        if (xair_block_ops(module, from.block, &operations, &count) != XAIR_OK) return false;
        for (std::size_t position = from.position + 1;
             position < to.position && position < count; ++position) {
            if (clobbers_load(operations[position])) return false;
        }
        return true;
    }

    bool can_expand(
        const xair_value_id value,
        const xair_op_id operation,
        const xair_opcode opcode,
        const xair_op_id horizon,
        const std::size_t depth,
        const bool root,
        RenderState& state) const {
        if (root) return true;
        if (depth >= state.options.max_depth || state.nodes >= state.options.max_nodes ||
            state.nodes >= state.options.max_tokens) {
            state.truncated = true;
            ++state.omitted;
            return false;
        }
        if (opcode == XAIR_OP_CONST_U64 || opcode == XAIR_OP_CONST_WIDE ||
            opcode == XAIR_OP_UNKNOWN || opcode == XAIR_OP_UNDEF) {
            return true;
        }
        if (opcode == XAIR_OP_LOAD) {
            return state.options.inline_loads && value < use_counts.size() &&
                use_counts[value] <= 1 && load_is_safe(operation, horizon);
        }
        xair_op_attributes attributes{};
        if (xair_op_attributes_get(module, operation, &attributes) != XAIR_OK) {
            return false;
        }
        constexpr std::uint32_t effectful = XAIR_EFFECT_READ_MEMORY |
            XAIR_EFFECT_WRITE_MEMORY | XAIR_EFFECT_MAY_FAULT |
            XAIR_EFFECT_VOLATILE | XAIR_EFFECT_ATOMIC | XAIR_EFFECT_BARRIER |
            XAIR_EFFECT_MAY_THROW | XAIR_EFFECT_NORETURN;
        if ((attributes.effects & effectful) != 0) return false;
        if (opcode == XAIR_OP_STORE || opcode == XAIR_OP_CALL ||
            opcode == XAIR_OP_OPAQUE_PURE || opcode == XAIR_OP_OPAQUE_EFFECT ||
            opcode == XAIR_OP_MEMORY_BARRIER) {
            return false;
        }
        return state.options.inline_single_use && value < use_counts.size() &&
            use_counts[value] <= 1;
    }

    Rendered render_value(
        const xair_value_id value,
        const xair_op_id horizon,
        const std::size_t depth,
        const bool root,
        RenderState& state) const {
        track_value(state, value);
        if (value >= xair_module_value_count(module)) {
            state.truncated = true;
            ++state.omitted;
            return {"invalid_value(" + std::to_string(value) + ')', precedence_atom};
        }
        xair_op_id operation = XAIR_INVALID_ID;
        if (xair_value_definition(module, value, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID) {
            return {leaf(value, state), precedence_atom};
        }
        xair_op_view_v3 view{};
        if (xair_module_get_op_v3(module, operation, &view) != XAIR_OK) {
            state.truncated = true;
            ++state.omitted;
            return {leaf(value, state), precedence_atom};
        }
        if (state.active.contains(value) ||
            !can_expand(value, operation, view.opcode, horizon, depth, root, state)) {
            return {leaf(value, state), precedence_atom};
        }
        ++state.nodes;
        state.active.insert(value);
        track_operation(state, operation);
        Rendered rendered = render_operation(value, operation, view.opcode, horizon, depth, state);
        state.active.erase(value);
        return rendered;
    }

    Rendered operand(
        const xair_value_id value,
        const xair_op_id horizon,
        const std::size_t depth,
        RenderState& state) const {
        return render_value(value, horizon, depth + 1, false, state);
    }

    Rendered render_binary(
        const xair_value_id* inputs,
        const std::size_t count,
        const char* token,
        const int precedence,
        const xair_op_id horizon,
        const std::size_t depth,
        RenderState& state) const {
        if (count < 2) return {"malformed_binary()", precedence_atom};
        const Rendered left = operand(inputs[0], horizon, depth, state);
        const Rendered right = operand(inputs[1], horizon, depth, state);
        return {parenthesize(left, precedence) + ' ' + token + ' ' +
                    parenthesize(right, precedence + 1),
                precedence};
    }

    bool constant_boolean(const xair_value_id value, bool& result) const {
        if (value >= xair_module_value_count(module) ||
            xair_value_type(module, value).bits != 1) return false;
        xair_op_id operation = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        std::uint64_t lo = 0;
        std::uint64_t hi = 0;
        if (xair_value_definition(module, value, &operation) != XAIR_OK ||
            operation == XAIR_INVALID_ID ||
            xair_module_get_op_v3(module, operation, &view) != XAIR_OK ||
            view.opcode != XAIR_OP_CONST_U64 ||
            xair_op_immediate_wide(module, operation, &lo, &hi) != XAIR_OK) {
            return false;
        }
        result = (lo & 1U) != 0;
        return true;
    }

    static Rendered negate_boolean(Rendered expression) {
        if (expression.precedence == precedence_compare) {
            constexpr std::pair<std::string_view, std::string_view> inverses[] = {
                {" == ", " != "}, {" != ", " == "},
                {" u< ", " u>= "}, {" u<= ", " u> "},
                {" s< ", " s>= "}, {" s<= ", " s> "}};
            for (const auto& [from, to] : inverses) {
                const std::size_t position = expression.text.find(from);
                if (position == std::string::npos) continue;
                expression.text.replace(position, from.size(), to);
                return expression;
            }
        }
        return {'!' + parenthesize(expression, precedence_unary), precedence_unary};
    }

    Rendered render_comparison(
        const xair_value_id* inputs,
        const std::size_t count,
        const xair_opcode opcode,
        const xair_op_id horizon,
        const std::size_t depth,
        RenderState& state) const {
        if (count < 2) return {"malformed_compare()", precedence_atom};
        if (opcode == XAIR_OP_EQ || opcode == XAIR_OP_NE) {
            bool constant = false;
            std::size_t other = 0;
            bool found = constant_boolean(inputs[1], constant);
            if (!found) {
                found = constant_boolean(inputs[0], constant);
                other = 1;
            }
            if (found) {
                Rendered expression = operand(inputs[other], horizon, depth, state);
                const bool negate = (opcode == XAIR_OP_EQ) != constant;
                if (negate) {
                    return negate_boolean(std::move(expression));
                }
                return expression;
            }
        }
        const char* token = "==";
        switch (opcode) {
        case XAIR_OP_NE: token = "!="; break;
        case XAIR_OP_ULT: token = "u<"; break;
        case XAIR_OP_ULE: token = "u<="; break;
        case XAIR_OP_SLT: token = "s<"; break;
        case XAIR_OP_SLE: token = "s<="; break;
        default: break;
        }
        return render_binary(
            inputs, count, token, precedence_compare, horizon, depth, state);
    }

    Rendered render_flag(
        const xair_opcode flag_opcode,
        const xair_value_id flags,
        const xair_op_id horizon,
        const std::size_t depth,
        RenderState& state) const {
        xair_op_id definition = XAIR_INVALID_ID;
        xair_op_view_v3 view{};
        const xair_value_id* inputs = nullptr;
        std::size_t count = 0;
        if (xair_value_definition(module, flags, &definition) != XAIR_OK ||
            definition == XAIR_INVALID_ID ||
            xair_module_get_op_v3(module, definition, &view) != XAIR_OK ||
            xair_op_inputs(module, definition, &inputs, &count) != XAIR_OK) {
            return {std::string(xair_opcode_name(flag_opcode)) + '(' + leaf(flags, state) + ')',
                    precedence_atom};
        }
        const bool add = view.opcode == XAIR_OP_FLAGS_ADD;
        const bool sub = view.opcode == XAIR_OP_FLAGS_SUB;
        const bool logic = view.opcode == XAIR_OP_FLAGS_LOGIC;
        if ((!add && !sub && !logic) || count == 0) {
            return {std::string(xair_opcode_name(flag_opcode)) + '(' + leaf(flags, state) + ')',
                    precedence_atom};
        }
        track_operation(state, definition);
        if (sub && count >= 2 && flag_opcode == XAIR_OP_FLAG_ZF) {
            return render_binary(
                inputs, count, "==", precedence_compare, horizon, depth, state);
        }
        if (sub && count >= 2 && flag_opcode == XAIR_OP_FLAG_CF) {
            return render_binary(
                inputs, count, "u<", precedence_compare, horizon, depth, state);
        }
        Rendered arithmetic;
        if (logic) {
            arithmetic = operand(inputs[0], horizon, depth, state);
        } else {
            arithmetic = render_binary(inputs, count, add ? "+" : "-",
                                       precedence_add, horizon, depth, state);
        }
        switch (flag_opcode) {
        case XAIR_OP_FLAG_ZF:
            return {parenthesize(arithmetic, precedence_compare) + " == 0", precedence_compare};
        case XAIR_OP_FLAG_SF:
            return {"signbit(" + arithmetic.text + ')', precedence_atom};
        case XAIR_OP_FLAG_PF:
            return {"parity8(" + arithmetic.text + ')', precedence_atom};
        case XAIR_OP_FLAG_CF:
            return {std::string(add ? "carry_add(" : sub ? "borrow_sub(" : "carry_logic(") +
                        arithmetic.text + ')', precedence_atom};
        case XAIR_OP_FLAG_OF:
            return {std::string(add ? "overflow_add(" : sub ? "overflow_sub(" : "overflow_logic(") +
                        arithmetic.text + ')', precedence_atom};
        case XAIR_OP_FLAG_AF:
            return {std::string(add ? "aux_carry_add(" : sub ? "aux_borrow_sub(" : "aux_logic(") +
                        arithmetic.text + ')', precedence_atom};
        default:
            return {std::string(xair_opcode_name(flag_opcode)) + '(' + arithmetic.text + ')',
                    precedence_atom};
        }
    }

    Rendered render_call(
        const xair_value_id* inputs,
        const std::size_t count,
        const xair_op_attributes& attributes,
        const xair_op_id horizon,
        const std::size_t depth,
        RenderState& state) const {
        std::string callee;
        std::size_t argument_end = count;
        if (attributes.import_name != nullptr && attributes.import_name[0] != '\0') {
            if (attributes.import_module != nullptr && attributes.import_module[0] != '\0') {
                callee = std::string(attributes.import_module) + '!';
            }
            callee += attributes.import_name;
        } else if (attributes.direct_target != 0) {
            callee = "sub_" + hex_value(attributes.direct_target).substr(2);
        } else if (attributes.call_kind == XAIR_CALL_INDIRECT && count != 0) {
            std::size_t target_index = count - 1;
            while (target_index != 0 &&
                   xair_value_type(module, inputs[target_index]).kind == XAIR_TYPE_MEM) {
                --target_index;
            }
            callee = parenthesize(operand(inputs[target_index], horizon, depth, state),
                                  precedence_atom);
            argument_end = target_index;
        } else {
            callee = "unknown_call";
        }
        std::string text = callee + '(';
        bool first = true;
        for (std::size_t index = 0; index < count; ++index) {
            track_value(state, inputs[index]);
            if (index >= argument_end ||
                xair_value_type(module, inputs[index]).kind == XAIR_TYPE_MEM) continue;
            if (!first) text += ", ";
            first = false;
            text += operand(inputs[index], horizon, depth, state).text;
        }
        text += ')';
        return {std::move(text), precedence_atom};
    }

    Rendered render_operation(
        const xair_value_id value,
        const xair_op_id operation,
        const xair_opcode opcode,
        const xair_op_id horizon,
        const std::size_t depth,
        RenderState& state) const {
        const xair_value_id* inputs = nullptr;
        std::size_t count = 0;
        if (xair_op_inputs(module, operation, &inputs, &count) != XAIR_OK) {
            return {leaf(value, state), precedence_atom};
        }
        xair_op_attributes attributes{};
        (void)xair_op_attributes_get(module, operation, &attributes);
        for (std::size_t index = 0; index < count; ++index) {
            track_value(state, inputs[index]);
        }
        const xair_type type = xair_value_type(module, value);
        std::uint64_t lo = 0;
        std::uint64_t hi = 0;
        (void)xair_op_immediate_wide(module, operation, &lo, &hi);

        switch (opcode) {
        case XAIR_OP_CONST_U64: {
            if (type.kind == XAIR_TYPE_INT && type.bits == 1) {
                return {(lo & 1U) != 0 ? "true" : "false", precedence_atom,
                        true, (lo & 1U) != 0};
            }
            if (type.bits != 0 && type.bits < 64) lo &= (UINT64_C(1) << type.bits) - 1U;
            return {hex_value(lo) + ':' + type_width(type), precedence_atom};
        }
        case XAIR_OP_CONST_WIDE: {
            std::ostringstream output;
            output << "0x" << std::hex;
            if (hi != 0) output << hi << std::setw(16) << std::setfill('0');
            output << lo << ':' << type_width(type);
            return {output.str(), precedence_atom};
        }
        case XAIR_OP_ADD:
        case XAIR_OP_ADDR_ADD:
            return render_binary(inputs, count, "+", precedence_add, horizon, depth, state);
        case XAIR_OP_SUB:
        case XAIR_OP_ADDR_SUB:
            return render_binary(inputs, count, "-", precedence_add, horizon, depth, state);
        case XAIR_OP_MUL:
            return render_binary(inputs, count, "*", precedence_multiply, horizon, depth, state);
        case XAIR_OP_UDIV:
            return render_binary(inputs, count, "/u", precedence_multiply, horizon, depth, state);
        case XAIR_OP_SDIV:
            return render_binary(inputs, count, "/s", precedence_multiply, horizon, depth, state);
        case XAIR_OP_UREM:
            return render_binary(inputs, count, "%u", precedence_multiply, horizon, depth, state);
        case XAIR_OP_SREM:
            return render_binary(inputs, count, "%s", precedence_multiply, horizon, depth, state);
        case XAIR_OP_AND:
            return render_binary(inputs, count, "&", precedence_and, horizon, depth, state);
        case XAIR_OP_OR:
            return render_binary(inputs, count, "|", precedence_or, horizon, depth, state);
        case XAIR_OP_XOR: {
            if (count >= 2 && type.bits == 1) {
                bool constant = false;
                std::size_t other = 0;
                bool found = constant_boolean(inputs[1], constant);
                if (!found) {
                    found = constant_boolean(inputs[0], constant);
                    other = 1;
                }
                if (found) {
                    Rendered expression = operand(inputs[other], horizon, depth, state);
                    return constant ? negate_boolean(std::move(expression)) : expression;
                }
            }
            return render_binary(inputs, count, "^", precedence_xor, horizon, depth, state);
        }
        case XAIR_OP_SHL:
            return render_binary(inputs, count, "<<", precedence_shift, horizon, depth, state);
        case XAIR_OP_LSHR:
            return render_binary(inputs, count, ">>u", precedence_shift, horizon, depth, state);
        case XAIR_OP_ASHR:
            return render_binary(inputs, count, ">>s", precedence_shift, horizon, depth, state);
        case XAIR_OP_ROL:
        case XAIR_OP_ROR:
        case XAIR_OP_CONCAT: {
            std::string text = std::string(xair_opcode_name(opcode)) + '(';
            for (std::size_t index = 0; index < count; ++index) {
                if (index != 0) text += ", ";
                text += operand(inputs[index], horizon, depth, state).text;
            }
            return {text + ')', precedence_atom};
        }
        case XAIR_OP_EQ:
        case XAIR_OP_NE:
        case XAIR_OP_ULT:
        case XAIR_OP_ULE:
        case XAIR_OP_SLT:
        case XAIR_OP_SLE:
            return render_comparison(inputs, count, opcode, horizon, depth, state);
        case XAIR_OP_ZEXT:
        case XAIR_OP_SEXT:
        case XAIR_OP_TRUNC:
        case XAIR_OP_INT_TO_ADDR:
        case XAIR_OP_ADDR_TO_INT: {
            if (count == 0) return {"malformed_cast()", precedence_atom};
            const xair_type input_type = xair_value_type(module, inputs[0]);
            if (xair_type_equal(input_type, type) != 0) {
                return operand(inputs[0], horizon, depth, state);
            }
            xair_op_id input_definition = XAIR_INVALID_ID;
            xair_op_view_v3 input_view{};
            if (opcode == XAIR_OP_TRUNC &&
                xair_value_definition(module, inputs[0], &input_definition) == XAIR_OK &&
                input_definition != XAIR_INVALID_ID &&
                xair_module_get_op_v3(module, input_definition, &input_view) == XAIR_OK &&
                (input_view.opcode == XAIR_OP_ZEXT || input_view.opcode == XAIR_OP_SEXT)) {
                const xair_value_id* cast_inputs = nullptr;
                std::size_t cast_count = 0;
                if (xair_op_inputs(module, input_definition, &cast_inputs, &cast_count) == XAIR_OK &&
                    cast_count == 1 &&
                    xair_type_equal(xair_value_type(module, cast_inputs[0]), type) != 0) {
                    return operand(cast_inputs[0], horizon, depth, state);
                }
            }
            const Rendered input = operand(inputs[0], horizon, depth, state);
            return {std::string(xair_opcode_name(opcode)) + '<' + type_width(type) + ">(" +
                        input.text + ')', precedence_atom};
        }
        case XAIR_OP_EXTRACT: {
            if (count == 0) return {"malformed_extract()", precedence_atom};
            const Rendered input = operand(inputs[0], horizon, depth, state);
            return {"extract<" + std::to_string(lo) + ':' + std::to_string(type.bits) + ">(" +
                        input.text + ')', precedence_atom};
        }
        case XAIR_OP_SELECT: {
            if (count < 3) return {"malformed_select()", precedence_atom};
            const Rendered condition = operand(inputs[0], horizon, depth, state);
            const Rendered when_true = operand(inputs[1], horizon, depth, state);
            const Rendered when_false = operand(inputs[2], horizon, depth, state);
            return {parenthesize(condition, precedence_select) + " ? " +
                        parenthesize(when_true, precedence_select) + " : " +
                        parenthesize(when_false, precedence_select), precedence_select};
        }
        case XAIR_OP_LOAD: {
            if (count < 2) return {"malformed_load()", precedence_atom};
            track_value(state, inputs[0]);
            const Rendered address = operand(inputs[1], horizon, depth, state);
            return {"load" + std::to_string(type.bits) + '(' + address.text + ')', precedence_atom};
        }
        case XAIR_OP_STORE: {
            if (count < 3) return {"malformed_store()", precedence_atom};
            track_value(state, inputs[0]);
            const Rendered address = operand(inputs[1], horizon, depth, state);
            const Rendered data = operand(inputs[2], horizon, depth, state);
            const xair_type data_type = xair_value_type(module, inputs[2]);
            return {"store" + std::to_string(data_type.bits) + '(' + address.text + ", " +
                        data.text + ')', precedence_atom};
        }
        case XAIR_OP_FLAG_ZF:
        case XAIR_OP_FLAG_CF:
        case XAIR_OP_FLAG_OF:
        case XAIR_OP_FLAG_SF:
        case XAIR_OP_FLAG_PF:
        case XAIR_OP_FLAG_AF:
            if (count == 0) return {"malformed_flag()", precedence_atom};
            return render_flag(opcode, inputs[0], horizon, depth, state);
        case XAIR_OP_CALL:
            return render_call(inputs, count, attributes, horizon, depth, state);
        case XAIR_OP_UNKNOWN:
        case XAIR_OP_UNDEF: {
            const char* origin = attributes.semantic_id;
            const std::string label = origin != nullptr && origin[0] != '\0'
                ? origin : xair_opcode_name(opcode);
            return {std::string(xair_opcode_name(opcode)) + '<' + type_width(type) + ">(" +
                        label + ')', precedence_atom};
        }
        case XAIR_OP_OPAQUE_PURE:
        case XAIR_OP_OPAQUE_EFFECT:
        case XAIR_OP_INTRINSIC:
        case XAIR_OP_MEMORY_BARRIER:
        case XAIR_OP_FLAGS_ADD:
        case XAIR_OP_FLAGS_SUB:
        case XAIR_OP_FLAGS_LOGIC:
        case XAIR_OP_FLAGS_SHL:
        default: {
            std::string text = std::string(xair_opcode_name(opcode)) + '<';
            if (attributes.semantic_id != nullptr && attributes.semantic_id[0] != '\0') {
                text += attributes.semantic_id;
                text += ':';
            }
            text += type_width(type) + ">(";
            for (std::size_t index = 0; index < count; ++index) {
                if (index != 0) text += ", ";
                text += operand(inputs[index], horizon, depth, state).text;
            }
            return {text + ')', precedence_atom};
        }
        }
    }

    SemanticExpression build_uncached(
        const xair_value_id value,
        const ExpressionOptions& options,
        const std::unordered_map<xair_value_id, std::string>* value_names = nullptr) const {
        SemanticExpression result;
        result.value = value;
        if (value >= xair_module_value_count(module)) {
            result.status = XAIR_ERR_BAD_ARG;
            result.text = "invalid_value(" + std::to_string(value) + ')';
            return result;
        }
        result.type = xair_value_type(module, value);
        xair_op_id root = XAIR_INVALID_ID;
        if (xair_value_definition(module, value, &root) != XAIR_OK) {
            result.status = XAIR_ERR_BAD_ARG;
            return result;
        }
        result.root_op = root;
        if (root != XAIR_INVALID_ID) {
            xair_op_view_v3 view{};
            if (xair_module_get_op_v3(module, root, &view) == XAIR_OK) {
                result.display = display_kind(view.opcode);
            }
        }
        RenderState state{options, value_names};
        const Rendered rendered = render_value(value, root, 0, true, state);
        result.text = rendered.text;
        if (options.max_characters != 0 && result.text.size() > options.max_characters) {
            const std::size_t suffix_size = 3;
            if (options.max_characters > suffix_size) {
                result.text.resize(options.max_characters - suffix_size);
                result.text += "...";
            } else {
                result.text.assign(options.max_characters, '.');
            }
            state.truncated = true;
            ++state.omitted;
        }
        result.source = state.source;
        result.operations = std::move(state.operations);
        result.referenced_values = std::move(state.values);
        result.truncated = state.truncated;
        result.omitted_nodes = state.omitted;
        return result;
    }

    SemanticExpression build(
        const xair_value_id value,
        const ExpressionOptions& options) const {
        const CacheKey key{value, options};
        {
            const std::scoped_lock lock(cache_mutex);
            const auto found = cache.find(key);
            if (found != cache.end()) return found->second;
        }
        SemanticExpression result = build_uncached(value, options);
        {
            const std::scoped_lock lock(cache_mutex);
            const auto [entry, inserted] = cache.emplace(key, result);
            if (!inserted) return entry->second;
        }
        return result;
    }

    SemanticExpression build_named(
        const xair_value_id value,
        const std::unordered_map<xair_value_id, std::string>& value_names,
        const ExpressionOptions& options) const {
        return build_uncached(value, options, &value_names);
    }

    const xair_module* module{};
    std::vector<Location> locations;
    std::vector<std::size_t> use_counts;
    mutable std::mutex cache_mutex;
    mutable std::unordered_map<CacheKey, SemanticExpression, CacheHash> cache;
};

ExpressionRecovery::ExpressionRecovery(const xair_module& module)
    : impl_(std::make_unique<Impl>(module)) {}

ExpressionRecovery::~ExpressionRecovery() = default;
ExpressionRecovery::ExpressionRecovery(ExpressionRecovery&&) noexcept = default;
ExpressionRecovery& ExpressionRecovery::operator=(ExpressionRecovery&&) noexcept = default;

SemanticExpression ExpressionRecovery::build(
    const xair_value_id value,
    const ExpressionOptions& options) const {
    return impl_->build(value, options);
}

SemanticExpression ExpressionRecovery::build_named(
    const xair_value_id value,
    const std::unordered_map<xair_value_id, std::string>& value_names,
    const ExpressionOptions& options) const {
    return impl_->build_named(value, value_names, options);
}

std::size_t ExpressionRecovery::cache_size() const noexcept {
    const std::scoped_lock lock(impl_->cache_mutex);
    return impl_->cache.size();
}

void ExpressionRecovery::clear_cache() const {
    const std::scoped_lock lock(impl_->cache_mutex);
    impl_->cache.clear();
}

const char* expression_display_kind_name(const ExpressionDisplayKind kind) noexcept {
    switch (kind) {
    case ExpressionDisplayKind::leaf: return "leaf";
    case ExpressionDisplayKind::constant: return "constant";
    case ExpressionDisplayKind::unary: return "unary";
    case ExpressionDisplayKind::binary: return "binary";
    case ExpressionDisplayKind::comparison: return "comparison";
    case ExpressionDisplayKind::address: return "address";
    case ExpressionDisplayKind::load: return "load";
    case ExpressionDisplayKind::store: return "store";
    case ExpressionDisplayKind::select: return "select";
    case ExpressionDisplayKind::call_result: return "call-result";
    case ExpressionDisplayKind::flag: return "flag";
    case ExpressionDisplayKind::intrinsic: return "intrinsic";
    case ExpressionDisplayKind::opaque: return "opaque";
    case ExpressionDisplayKind::unknown: return "unknown";
    }
    return "unknown";
}

} // namespace airece
