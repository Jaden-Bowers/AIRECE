#include <airece/emit/agent_json.hpp>

#include <airece/session/analysis_session.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace airece {
namespace {

std::string escape(const std::string_view value) {
    std::ostringstream out;
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') <<
                    static_cast<unsigned>(c) << std::dec;
            } else {
                out << static_cast<char>(c);
            }
        }
    }
    return out.str();
}

void quoted(std::ostringstream& out, const std::string_view value) {
    out << '"' << escape(value) << '"';
}

std::string hex_value(const std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

std::string evidence_id(const std::uint64_t begin, const std::uint64_t end) {
    return "A:" + hex_value(begin) + '-' + hex_value(end);
}

std::optional<std::int64_t> constant_value(const std::string_view text) {
    try {
        std::size_t consumed = 0;
        const std::string value(text);
        const std::int64_t parsed = std::stoll(value, &consumed, 0);
        if (consumed == value.size()) return parsed;
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

bool simple_expression(const std::string_view value) {
    return value.find_first_of(" +-*/&|^") == std::string_view::npos;
}

std::string grouped(const std::string& value) {
    return simple_expression(value) ? value : '(' + value + ')';
}

std::string binary_expression(
    const std::string& left,
    const std::string_view operation,
    const std::string& right) {
    if ((operation == "^" || operation == "-") && left == right) return "0";
    if ((operation == "+" || operation == "|" || operation == "^") && left == "0") {
        return right;
    }
    if ((operation == "+" || operation == "-" || operation == "|" ||
         operation == "^") && right == "0") return left;
    if (operation == "*" && (left == "0" || right == "0")) return "0";
    if (operation == "*" && left == "1") return right;
    if (operation == "*" && right == "1") return left;
    const auto left_constant = constant_value(left);
    const auto right_constant = constant_value(right);
    if (left_constant && right_constant) {
        std::int64_t value{};
        if (operation == "+") value = *left_constant + *right_constant;
        else if (operation == "-") value = *left_constant - *right_constant;
        else if (operation == "&") value = *left_constant & *right_constant;
        else if (operation == "|") value = *left_constant | *right_constant;
        else if (operation == "^") value = *left_constant ^ *right_constant;
        else if (operation == "*") value = *left_constant * *right_constant;
        else return grouped(left) + ' ' + std::string(operation) + ' ' + grouped(right);
        if (value < 0) return std::to_string(value);
        return value <= 9 ? std::to_string(value) : hex_value(static_cast<std::uint64_t>(value));
    }
    if (operation == "+" && left == right) return grouped(left) + " * 2";
    if (operation == "+" && right == grouped(left) + " * 2") {
        return grouped(left) + " * 3";
    }
    if (operation == "+" && right.size() > 1 && right.front() == '-' &&
        std::all_of(right.begin() + 1, right.end(), [](const char c) {
            return c >= '0' && c <= '9';
        })) {
        const std::uint64_t magnitude = std::stoull(right.substr(1));
        return grouped(left) + " - " +
            (magnitude <= 9 ? std::to_string(magnitude) : hex_value(magnitude));
    }
    return grouped(left) + ' ' + std::string(operation) + ' ' + grouped(right);
}

struct State {
    std::array<std::string, XAIR_X86_REG_COUNT> registers;
    std::array<std::int64_t, XAIR_X86_REG_COUNT> stack_offsets;
    std::map<std::string, std::string> stack_values;
    std::map<std::uint64_t, std::string> global_values;
};

State initial_state() {
    State state;
    for (std::size_t index = 0; index < state.registers.size(); ++index) {
        state.registers[index] = "reg" + std::to_string(index);
        state.stack_offsets[index] = std::numeric_limits<std::int64_t>::min();
    }
    state.registers[XAIR_X86_RCX] = "arg0";
    state.registers[XAIR_X86_RDX] = "arg1";
    state.registers[XAIR_X86_R8] = "arg2";
    state.registers[XAIR_X86_R9] = "arg3";
    state.registers[XAIR_X86_RAX] = "unknown_return";
    state.stack_offsets[XAIR_X86_RSP] = 0;
    return state;
}

std::uint64_t mask_for_bits(const std::uint16_t bits) {
    return bits == 0 || bits >= 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

std::string immediate_text(const xair_x86_operand& operand) {
    const std::uint64_t masked = operand.value.imm & mask_for_bits(operand.size_bits);
    if (operand.immediate_is_signed != 0 && operand.size_bits != 0 &&
        operand.size_bits < 64 && (masked & (UINT64_C(1) << (operand.size_bits - 1))) != 0) {
        const std::int64_t signed_value = static_cast<std::int64_t>(
            masked | ~mask_for_bits(operand.size_bits));
        return std::to_string(signed_value);
    }
    return masked <= 9 ? std::to_string(masked) : hex_value(masked);
}

std::string register_value(const State& state, const xair_x86_register& reg) {
    const auto parent = static_cast<std::size_t>(reg.parent);
    return parent < state.registers.size() ? state.registers[parent] : "unknown_register";
}

std::string memory_address(const State& state, const xair_x86_memory_operand& memory) {
    std::string result;
    if (memory.has_base != 0) result = register_value(state, memory.base);
    if (memory.has_index != 0) {
        std::string index = register_value(state, memory.index);
        if (memory.scale > 1) index = grouped(index) + " * " + std::to_string(memory.scale);
        result = result.empty() ? index : binary_expression(result, "+", index);
    }
    if (memory.displacement != 0 || result.empty()) {
        const std::uint64_t magnitude = memory.displacement < 0
            ? static_cast<std::uint64_t>(-memory.displacement)
            : static_cast<std::uint64_t>(memory.displacement);
        const std::string amount = magnitude <= 9 ? std::to_string(magnitude) : hex_value(magnitude);
        if (result.empty()) result = memory.displacement < 0 ? '-' + amount : amount;
        else result = binary_expression(result, memory.displacement < 0 ? "-" : "+", amount);
    }
    return result;
}

std::string classify_memory(const xair_x86_memory_operand& memory);

std::optional<std::uint64_t> global_address(
    const xair_x86_memory_operand& memory,
    const std::uint64_t instruction_end) {
    if (memory.kind == XAIR_X86_MEM_RIP_REL) {
        return static_cast<std::uint64_t>(
            static_cast<std::int64_t>(instruction_end) + memory.displacement);
    }
    if (memory.kind == XAIR_X86_MEM_ABSOLUTE && memory.has_base == 0 &&
        memory.has_index == 0) {
        return static_cast<std::uint64_t>(memory.displacement);
    }
    return std::nullopt;
}

std::string stack_key(const State& state, const xair_x86_memory_operand& memory) {
    if (memory.has_base == 0) return {};
    const auto parent = static_cast<std::size_t>(memory.base.parent);
    if (parent >= state.stack_offsets.size() ||
        state.stack_offsets[parent] == std::numeric_limits<std::int64_t>::min()) return {};
    std::int64_t offset = state.stack_offsets[parent] + memory.displacement;
    if (memory.has_index != 0) {
        const auto index = constant_value(register_value(state, memory.index));
        if (!index) return {};
        offset += *index * memory.scale;
    }
    return "stack:" + std::to_string(offset);
}

std::string operand_value(
    const xair_binary_view& binary,
    const State& state,
    const xair_x86_operand& operand,
    const std::uint64_t instruction_end) {
    switch (operand.kind) {
    case XAIR_X86_OPERAND_REGISTER: return register_value(state, operand.value.reg);
    case XAIR_X86_OPERAND_IMMEDIATE: return immediate_text(operand);
    case XAIR_X86_OPERAND_MEMORY:
        if (classify_memory(operand.value.mem) == "stack") {
            const auto found = state.stack_values.find(stack_key(state, operand.value.mem));
            if (found != state.stack_values.end()) return found->second;
        }
        if (const auto address = global_address(operand.value.mem, instruction_end)) {
            if (const auto found = state.global_values.find(*address);
                found != state.global_values.end()) return found->second;
            if (operand.size_bits > 0 && operand.size_bits <= 64 &&
                operand.size_bits % 8 == 0) {
                std::uint64_t initial{};
                const std::size_t bytes = operand.size_bits / 8;
                if (xair_binary_view_read(&binary, *address, &initial, bytes) == XAIR_OK) {
                    return "global" + std::to_string(operand.size_bits) + '(' +
                        hex_value(*address) + ", initial=" + hex_value(initial) + ')';
                }
            }
            return "global" + std::to_string(operand.size_bits) + '(' +
                hex_value(*address) + ')';
        }
        return "load" + std::to_string(operand.size_bits) + "(" +
            memory_address(state, operand.value.mem) + ')';
    default: return "unknown";
    }
}

void write_register(State& state, const xair_x86_operand& operand, std::string value) {
    if (operand.kind != XAIR_X86_OPERAND_REGISTER) return;
    const auto parent = static_cast<std::size_t>(operand.value.reg.parent);
    if (parent < state.registers.size()) state.registers[parent] = std::move(value);
}

void write_memory(
    State& state,
    const xair_x86_operand& operand,
    std::string value,
    const std::uint64_t instruction_end) {
    if (operand.kind == XAIR_X86_OPERAND_MEMORY &&
        classify_memory(operand.value.mem) == "stack") {
        const std::string key = stack_key(state, operand.value.mem);
        if (!key.empty()) state.stack_values[key] = std::move(value);
    } else if (operand.kind == XAIR_X86_OPERAND_MEMORY) {
        if (const auto address = global_address(operand.value.mem, instruction_end)) {
            state.global_values[*address] = std::move(value);
        }
    }
}

std::string condition_token(const xair_x86_condition condition) {
    switch (condition) {
    case XAIR_X86_COND_E: return "==";
    case XAIR_X86_COND_NE: return "!=";
    case XAIR_X86_COND_B: return "<u";
    case XAIR_X86_COND_AE: return ">=u";
    case XAIR_X86_COND_BE: return "<=u";
    case XAIR_X86_COND_A: return ">u";
    case XAIR_X86_COND_L: return "<s";
    case XAIR_X86_COND_GE: return ">=s";
    case XAIR_X86_COND_LE: return "<=s";
    case XAIR_X86_COND_G: return ">s";
    case XAIR_X86_COND_S: return "sign";
    case XAIR_X86_COND_NS: return "not-sign";
    default: return "condition";
    }
}

struct Fact {
    std::string text;
    std::string evidence;
};

struct SwitchFact {
    std::string selector;
    std::string evidence;
    std::vector<std::pair<std::int64_t, Fact>> cases;
    Fact default_result;
};

struct Digest {
    std::size_t instruction_count{};
    std::vector<std::uint16_t> parameter_bits;
    std::vector<Fact> returns;
    std::vector<Fact> conditions;
    std::vector<Fact> calls;
    std::vector<Fact> memory;
    std::set<std::uint64_t> constants;
    std::vector<SwitchFact> switches;
    std::size_t unresolved{};
    std::size_t omitted{};
};

void append_unique(std::vector<Fact>& facts, Fact fact) {
    if (std::none_of(facts.begin(), facts.end(), [&](const Fact& existing) {
            return existing.text == fact.text && existing.evidence == fact.evidence;
        })) {
        facts.push_back(std::move(fact));
    }
}

std::string classify_memory(const xair_x86_memory_operand& memory) {
    if (memory.has_base != 0 &&
        (memory.base.parent == XAIR_X86_RSP || memory.base.parent == XAIR_X86_RBP)) {
        return "stack";
    }
    if (memory.kind == XAIR_X86_MEM_RIP_REL || memory.kind == XAIR_X86_MEM_ABSOLUTE) {
        return "global";
    }
    return "indirect";
}

struct NodeResult {
    State state;
    std::string return_expression;
    std::string index_expression;
    std::optional<bool> branch_taken;
};

struct PathState {
    xair_cfg_node_id node{XAIR_CFG_INVALID_ID};
    State state;
    std::unordered_map<xair_cfg_node_id, std::size_t> visits;
};

std::optional<bool> evaluate_condition(
    const std::string& left,
    const std::string& right,
    const xair_x86_condition condition) {
    const auto lhs = constant_value(left);
    const auto rhs = constant_value(right);
    if (!lhs || !rhs) return std::nullopt;
    const auto ulhs = static_cast<std::uint64_t>(*lhs);
    const auto urhs = static_cast<std::uint64_t>(*rhs);
    switch (condition) {
    case XAIR_X86_COND_E: return *lhs == *rhs;
    case XAIR_X86_COND_NE: return *lhs != *rhs;
    case XAIR_X86_COND_B: return ulhs < urhs;
    case XAIR_X86_COND_AE: return ulhs >= urhs;
    case XAIR_X86_COND_BE: return ulhs <= urhs;
    case XAIR_X86_COND_A: return ulhs > urhs;
    case XAIR_X86_COND_L: return *lhs < *rhs;
    case XAIR_X86_COND_GE: return *lhs >= *rhs;
    case XAIR_X86_COND_LE: return *lhs <= *rhs;
    case XAIR_X86_COND_G: return *lhs > *rhs;
    default: return std::nullopt;
    }
}

NodeResult interpret_node(
    const xair_binary_view& binary,
    const xair_cfg_node& node,
    State state,
    Digest& digest,
    const bool switch_header) {
    std::string compare_left;
    std::string compare_right;
    NodeResult result{std::move(state), {}, {}, std::nullopt};
    std::uint64_t address = node.start;
    while (address < node.end) {
        xair_x86_decoded_inst instruction{};
        if (xair_decode_instruction(&binary, address, &instruction) != XAIR_OK ||
            instruction.length == 0) {
            ++digest.unresolved;
            break;
        }
        const std::uint64_t end = address + instruction.length;
        ++digest.instruction_count;
        const std::string evidence = evidence_id(address, end);
        const bool zeroing_xor = instruction.mnemonic == XAIR_X86_MNEMONIC_XOR &&
            instruction.visible_operand_count >= 2 &&
            instruction.operands[0].kind == XAIR_X86_OPERAND_REGISTER &&
            instruction.operands[1].kind == XAIR_X86_OPERAND_REGISTER &&
            instruction.operands[0].value.reg.parent ==
                instruction.operands[1].value.reg.parent;
        for (std::size_t index = 0; index < instruction.visible_operand_count; ++index) {
            const xair_x86_operand& operand = instruction.operands[index];
            if (!zeroing_xor && operand.kind == XAIR_X86_OPERAND_REGISTER &&
                (operand.actions & XAIR_X86_ACTION_READ) != 0) {
                std::size_t argument = static_cast<std::size_t>(-1);
                const std::string value = register_value(result.state, operand.value.reg);
                if (value == "arg0") argument = 0;
                else if (value == "arg1") argument = 1;
                else if (value == "arg2") argument = 2;
                else if (value == "arg3") argument = 3;
                if (argument < digest.parameter_bits.size()) {
                    digest.parameter_bits[argument] = std::max(
                        digest.parameter_bits[argument], operand.size_bits);
                }
            }
            if (operand.kind == XAIR_X86_OPERAND_IMMEDIATE &&
                operand.immediate_is_relative == 0) {
                const bool stack_adjustment = index == 1 &&
                    (instruction.mnemonic == XAIR_X86_MNEMONIC_ADD ||
                     instruction.mnemonic == XAIR_X86_MNEMONIC_SUB) &&
                    instruction.visible_operand_count > 0 &&
                    instruction.operands[0].kind == XAIR_X86_OPERAND_REGISTER &&
                    (instruction.operands[0].value.reg.parent == XAIR_X86_RSP ||
                     instruction.operands[0].value.reg.parent == XAIR_X86_RBP);
                if (!stack_adjustment) {
                    digest.constants.insert(
                        operand.value.imm & mask_for_bits(operand.size_bits));
                }
            }
            if (operand.kind == XAIR_X86_OPERAND_MEMORY) {
                const bool imported_call = instruction.mnemonic == XAIR_X86_MNEMONIC_CALL &&
                    operand.value.mem.kind == XAIR_X86_MEM_RIP_REL;
                const std::string kind = imported_call
                    ? "api-mediated" : classify_memory(operand.value.mem);
                const bool promoted_stack = kind == "stack" && operand.value.mem.has_index == 0;
                if (!switch_header && !promoted_stack &&
                    (operand.actions & XAIR_X86_ACTION_READ) != 0) {
                    append_unique(digest.memory, {"read:" + kind, evidence});
                }
                if (!switch_header && !promoted_stack &&
                    (operand.actions & XAIR_X86_ACTION_WRITE) != 0) {
                    append_unique(digest.memory, {"write:" + kind, evidence});
                }
                if (operand.value.mem.has_index != 0 && result.index_expression.empty()) {
                    result.index_expression = register_value(result.state, operand.value.mem.index);
                }
            }
        }
        const auto operand = [&](const std::size_t index) {
            return index < instruction.visible_operand_count
                ? operand_value(binary, result.state, instruction.operands[index], end)
                : std::string("unknown");
        };
        switch (instruction.mnemonic) {
        case XAIR_X86_MNEMONIC_MOV:
        case XAIR_X86_MNEMONIC_MOVZX:
        case XAIR_X86_MNEMONIC_MOVSX:
        case XAIR_X86_MNEMONIC_MOVSXD:
            if (instruction.visible_operand_count >= 2) {
                const std::string value = operand(1);
                if (instruction.operands[0].kind == XAIR_X86_OPERAND_REGISTER) {
                    const auto target = static_cast<std::size_t>(
                        instruction.operands[0].value.reg.parent);
                    result.state.stack_offsets[target] =
                        instruction.operands[1].kind == XAIR_X86_OPERAND_REGISTER
                        ? result.state.stack_offsets[static_cast<std::size_t>(
                            instruction.operands[1].value.reg.parent)]
                        : std::numeric_limits<std::int64_t>::min();
                }
                write_register(result.state, instruction.operands[0], value);
                write_memory(result.state, instruction.operands[0], value, end);
            }
            break;
        case XAIR_X86_MNEMONIC_LEA:
            if (instruction.visible_operand_count >= 2 &&
                instruction.operands[1].kind == XAIR_X86_OPERAND_MEMORY) {
                const xair_x86_memory_operand& memory = instruction.operands[1].value.mem;
                if (memory.displacement != 0 && memory.kind != XAIR_X86_MEM_RIP_REL) {
                    const std::uint64_t magnitude = memory.displacement < 0
                        ? static_cast<std::uint64_t>(-(memory.displacement + 1)) + 1
                        : static_cast<std::uint64_t>(memory.displacement);
                    digest.constants.insert(magnitude);
                }
                if (memory.has_base != 0 && memory.has_index != 0 &&
                    register_value(result.state, memory.base) ==
                        register_value(result.state, memory.index) && memory.scale > 0) {
                    digest.constants.insert(static_cast<std::uint64_t>(memory.scale) + 1);
                }
                write_register(result.state, instruction.operands[0],
                    memory_address(result.state, memory));
            }
            break;
        case XAIR_X86_MNEMONIC_ADD:
        case XAIR_X86_MNEMONIC_SUB:
        case XAIR_X86_MNEMONIC_AND:
        case XAIR_X86_MNEMONIC_OR:
        case XAIR_X86_MNEMONIC_XOR:
        case XAIR_X86_MNEMONIC_SHL:
        case XAIR_X86_MNEMONIC_SHR:
        case XAIR_X86_MNEMONIC_SAR:
        case XAIR_X86_MNEMONIC_ROL:
        case XAIR_X86_MNEMONIC_ROR:
            if (instruction.visible_operand_count >= 2) {
                std::string operation;
                switch (instruction.mnemonic) {
                case XAIR_X86_MNEMONIC_ADD: operation = "+"; break;
                case XAIR_X86_MNEMONIC_SUB: operation = "-"; break;
                case XAIR_X86_MNEMONIC_AND: operation = "&"; break;
                case XAIR_X86_MNEMONIC_OR: operation = "|"; break;
                case XAIR_X86_MNEMONIC_XOR: operation = "^"; break;
                case XAIR_X86_MNEMONIC_SHL: operation = "<<"; break;
                case XAIR_X86_MNEMONIC_SHR: operation = ">>u"; break;
                case XAIR_X86_MNEMONIC_SAR: operation = ">>s"; break;
                case XAIR_X86_MNEMONIC_ROL: operation = "rol"; break;
                case XAIR_X86_MNEMONIC_ROR: operation = "ror"; break;
                default: break;
                }
                const std::string left = operand(0);
                const std::string right = operand(1);
                if ((instruction.mnemonic == XAIR_X86_MNEMONIC_ADD ||
                     instruction.mnemonic == XAIR_X86_MNEMONIC_SUB) &&
                    instruction.operands[0].kind == XAIR_X86_OPERAND_REGISTER &&
                    instruction.operands[1].kind == XAIR_X86_OPERAND_IMMEDIATE) {
                    const auto target = static_cast<std::size_t>(
                        instruction.operands[0].value.reg.parent);
                    if (result.state.stack_offsets[target] !=
                        std::numeric_limits<std::int64_t>::min()) {
                        const std::int64_t amount = static_cast<std::int64_t>(
                            instruction.operands[1].value.imm &
                            mask_for_bits(instruction.operands[1].size_bits));
                        result.state.stack_offsets[target] +=
                            instruction.mnemonic == XAIR_X86_MNEMONIC_ADD ? amount : -amount;
                    }
                }
                const std::string expression = operation == "rol" || operation == "ror"
                    ? operation + '(' + left + ", " + right + ')'
                    : binary_expression(left, operation, right);
                write_register(result.state, instruction.operands[0], expression);
            }
            break;
        case XAIR_X86_MNEMONIC_IMUL:
            if (instruction.visible_operand_count >= 2) {
                const std::string left = instruction.visible_operand_count >= 3
                    ? operand(1) : operand(0);
                const std::string right = instruction.visible_operand_count >= 3
                    ? operand(2) : operand(1);
                write_register(result.state, instruction.operands[0],
                    binary_expression(left, "*", right));
            }
            break;
        case XAIR_X86_MNEMONIC_INC:
        case XAIR_X86_MNEMONIC_DEC:
            if (instruction.visible_operand_count >= 1) {
                write_register(result.state, instruction.operands[0],
                    binary_expression(operand(0),
                        instruction.mnemonic == XAIR_X86_MNEMONIC_INC ? "+" : "-", "1"));
            }
            break;
        case XAIR_X86_MNEMONIC_CMP:
        case XAIR_X86_MNEMONIC_TEST:
            if (instruction.visible_operand_count >= 2) {
                compare_left = operand(0);
                compare_right = operand(1);
            }
            break;
        case XAIR_X86_MNEMONIC_JCC:
            if (!compare_left.empty()) {
                append_unique(digest.conditions, {
                    compare_left + ' ' + condition_token(instruction.condition) + ' ' +
                        compare_right,
                    evidence});
                result.branch_taken = evaluate_condition(
                    compare_left, compare_right, instruction.condition);
            }
            break;
        case XAIR_X86_MNEMONIC_CALL: {
            std::string call;
            if (instruction.branch_target_valid != 0) {
                call = "direct:" + hex_value(instruction.branch_target);
            } else if (instruction.visible_operand_count > 0 &&
                       instruction.operands[0].kind == XAIR_X86_OPERAND_MEMORY &&
                       instruction.operands[0].value.mem.kind == XAIR_X86_MEM_RIP_REL) {
                const auto displacement = instruction.operands[0].value.mem.displacement;
                call = "imported:" + hex_value(static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(end) + displacement));
            } else {
                call = "indirect";
            }
            append_unique(digest.calls, {call, evidence});
            result.state.registers[XAIR_X86_RAX] = "result(" + call + ')';
            break;
        }
        default: break;
        }
        if (instruction.flow == XAIR_X86_FLOW_RETURN) {
            result.return_expression = result.state.registers[XAIR_X86_RAX];
        }
        address = end;
    }
    return result;
}

NodeResult trace_return(
    const AnalysisSession& session,
    xair_cfg_node_id node_id,
    State state,
    Digest& digest,
    const std::unordered_map<xair_cfg_node_id, std::vector<xair_cfg_node_id>>& successors,
    const std::unordered_set<xair_cfg_node_id>& switch_headers) {
    std::unordered_set<xair_cfg_node_id> visited;
    NodeResult result{std::move(state), {}, {}, std::nullopt};
    for (std::size_t step = 0; step < 64 && visited.insert(node_id).second; ++step) {
        const xair_cfg_node* node = xair_cfg_get_node(&session.cfg(), node_id);
        if (node == nullptr) break;
        result = interpret_node(session.binary(), *node, std::move(result.state), digest,
            switch_headers.contains(node_id));
        if (!result.return_expression.empty()) return result;
        const auto found = successors.find(node_id);
        if (found == successors.end() || found->second.size() != 1) break;
        node_id = found->second.front();
    }
    return result;
}

bool node_ends_in_call(const xair_binary_view& binary, const xair_cfg_node& node) {
    std::uint64_t address = node.start;
    xair_x86_decoded_inst last{};
    while (address < node.end) {
        xair_x86_decoded_inst instruction{};
        if (xair_decode_instruction(&binary, address, &instruction) != XAIR_OK ||
            instruction.length == 0 || address + instruction.length > node.end) return false;
        last = instruction;
        address += instruction.length;
    }
    return address == node.end && last.mnemonic == XAIR_X86_MNEMONIC_CALL;
}

NodeResult interpret_linear_fallthrough(
    const xair_binary_view& binary,
    std::uint64_t address,
    State state,
    Digest& digest) {
    NodeResult result{std::move(state), {}, {}, std::nullopt};
    std::unordered_set<std::uint64_t> visited;
    for (std::size_t count = 0; count < 256 && visited.insert(address).second; ++count) {
        xair_x86_decoded_inst instruction{};
        if (xair_decode_instruction(&binary, address, &instruction) != XAIR_OK ||
            instruction.length == 0) break;
        const std::uint64_t end = address + instruction.length;
        xair_cfg_node instruction_node{};
        instruction_node.start = address;
        instruction_node.end = end;
        result = interpret_node(binary, instruction_node, std::move(result.state), digest, false);
        if (!result.return_expression.empty()) return result;
        if (instruction.flow == XAIR_X86_FLOW_DIRECT_JUMP) {
            if (instruction.branch_target_valid == 0) break;
            address = instruction.branch_target;
        } else {
            address = end;
        }
    }
    return result;
}

std::string render_digest(
    const FunctionInfo& function,
    const CompactFunctionView& semantic,
    const Digest& digest) {
    std::ostringstream out;
    std::size_t parameter_count = digest.parameter_bits.size();
    const auto mentions_argument = [&](const std::size_t index) {
        const std::string name = "arg" + std::to_string(index);
        const auto facts_mention = [&](const std::vector<Fact>& facts) {
            return std::any_of(facts.begin(), facts.end(), [&](const Fact& fact) {
                return fact.text.find(name) != std::string::npos;
            });
        };
        if (facts_mention(digest.returns) || facts_mention(digest.conditions) ||
            facts_mention(digest.calls) || facts_mention(digest.memory)) return true;
        return std::any_of(digest.switches.begin(), digest.switches.end(),
            [&](const SwitchFact& item) {
                if (item.selector.find(name) != std::string::npos ||
                    item.default_result.text.find(name) != std::string::npos) return true;
                return std::any_of(item.cases.begin(), item.cases.end(),
                    [&](const auto& entry) {
                        return entry.second.text.find(name) != std::string::npos;
                    });
            });
    };
    while (parameter_count > 0 && digest.parameter_bits[parameter_count - 1] == 0 &&
           !mentions_argument(parameter_count - 1)) {
        --parameter_count;
    }
    out << "{\"schema\":\"" << agent_json_schema << "\",\"function\":{\"entry\":\"" <<
        hex_value(function.entry) << "\",\"name\":";
    quoted(out, function.name);
    out << ",\"parameter_count\":" << parameter_count <<
        ",\"instruction_count\":" << digest.instruction_count <<
        ",\"parameters\":[";
    for (std::size_t index = 0; index < parameter_count; ++index) {
        if (index != 0) out << ',';
        out << "{\"name\":\"arg" << index << "\",\"observed_bits\":" <<
            (index < digest.parameter_bits.size() && digest.parameter_bits[index] != 0
                ? digest.parameter_bits[index] : mentions_argument(index) ? 32 : 0) << '}';
    }
    out << "]},\"returns\":[";
    for (std::size_t index = 0; index < digest.returns.size(); ++index) {
        if (index != 0) out << ',';
        out << "{\"expression\":"; quoted(out, digest.returns[index].text);
        out << ",\"evidence\":"; quoted(out, digest.returns[index].evidence); out << '}';
    }
    out << "],\"conditions\":[";
    for (std::size_t index = 0; index < digest.conditions.size(); ++index) {
        if (index != 0) out << ',';
        out << "{\"expression\":"; quoted(out, digest.conditions[index].text);
        out << ",\"evidence\":"; quoted(out, digest.conditions[index].evidence); out << '}';
    }
    out << "],\"switches\":[";
    for (std::size_t index = 0; index < digest.switches.size(); ++index) {
        if (index != 0) out << ',';
        const SwitchFact& item = digest.switches[index];
        out << "{\"selector\":"; quoted(out, item.selector);
        out << ",\"evidence\":"; quoted(out, item.evidence);
        out << ",\"cases\":[";
        for (std::size_t case_index = 0; case_index < item.cases.size(); ++case_index) {
            if (case_index != 0) out << ',';
            out << "{\"value\":" << item.cases[case_index].first << ",\"result\":";
            quoted(out, item.cases[case_index].second.text);
            out << ",\"evidence\":"; quoted(out, item.cases[case_index].second.evidence);
            out << '}';
        }
        out << "],\"default\":{\"result\":"; quoted(out, item.default_result.text);
        out << ",\"evidence\":"; quoted(out, item.default_result.evidence); out << "}}";
    }
    out << "],\"calls\":[";
    for (std::size_t index = 0; index < digest.calls.size(); ++index) {
        if (index != 0) out << ',';
        out << "{\"kind_target\":"; quoted(out, digest.calls[index].text);
        out << ",\"evidence\":"; quoted(out, digest.calls[index].evidence); out << '}';
    }
    out << "],\"memory_effects\":[";
    for (std::size_t index = 0; index < digest.memory.size(); ++index) {
        if (index != 0) out << ',';
        out << "{\"effect\":"; quoted(out, digest.memory[index].text);
        out << ",\"evidence\":"; quoted(out, digest.memory[index].evidence); out << '}';
    }
    out << "],\"constants\":[";
    std::size_t constant_index = 0;
    for (const std::uint64_t constant : digest.constants) {
        if (constant_index++ != 0) out << ',';
        quoted(out, hex_value(constant));
    }
    out << "],\"unresolved\":{\"count\":" << digest.unresolved <<
        ",\"summary\":\"unsupported instructions or conflicting paths only\"},"
        "\"omitted\":{\"facts\":" << digest.omitted << "},\"complete\":" <<
        (semantic.complete && digest.omitted == 0 ? "true" : "false") << "}\n";
    return out.str();
}

} // namespace

std::string render_agent_json(
    const AnalysisSession& session,
    const FunctionInfo& function,
    const CompactFunctionView& semantic,
    const std::size_t max_bytes) {
    Digest digest;
    digest.parameter_bits.resize(std::max<std::size_t>(semantic.parameters.size(), 4));
    std::unordered_map<xair_cfg_node_id, State> inputs;
    std::unordered_map<xair_cfg_node_id, NodeResult> outputs;
    std::deque<xair_cfg_node_id> worklist;
    inputs.emplace(semantic.control.entry, initial_state());
    worklist.push_back(semantic.control.entry);

    std::unordered_map<xair_cfg_node_id, std::vector<xair_cfg_node_id>> successors;
    std::unordered_map<xair_cfg_node_id,
        std::unordered_map<xair_cfg_node_id, ControlTransferKind>> successor_kinds;
    std::unordered_set<xair_cfg_node_id> switch_headers;
    for (const ControlTransfer& transfer : semantic.control.transfers) {
        if (transfer.source != XAIR_CFG_INVALID_ID && transfer.target != XAIR_CFG_INVALID_ID) {
            successors[transfer.source].push_back(transfer.target);
            successor_kinds[transfer.source][transfer.target] = transfer.kind;
        }
    }
    // Compact control recovery can intentionally omit call-return fallthroughs.
    // Supplement it with intra-function raw CFG edges so the agent digest still
    // reaches instructions after imported or indirect calls.
    std::size_t function_node_count = 0;
    const xair_cfg_node_id* function_nodes = xair_cfg_function_nodes(
        &session.cfg(), function.id, &function_node_count);
    std::unordered_set<xair_cfg_node_id> function_members;
    for (std::size_t index = 0; index < function_node_count; ++index) {
        function_members.insert(function_nodes[index]);
    }
    for (const xair_cfg_node_id source : function_members) {
        std::size_t edge_count = 0;
        const xair_cfg_edge* edges = xair_cfg_node_edges(&session.cfg(), source, &edge_count);
        for (std::size_t index = 0; index < edge_count; ++index) {
            const xair_cfg_edge& edge = edges[index];
            const bool call_target = edge.kind == XAIR_EDGE_CALL ||
                edge.kind == XAIR_EDGE_INDIRECT_CALL || edge.kind == XAIR_EDGE_EXTERNAL ||
                edge.kind == XAIR_EDGE_TAILCALL;
            if (call_target || edge.dst == XAIR_CFG_INVALID_ID ||
                !function_members.contains(edge.dst)) continue;
            auto& targets = successors[source];
            if (std::find(targets.begin(), targets.end(), edge.dst) == targets.end()) {
                targets.push_back(edge.dst);
            }
            successor_kinds[source][edge.dst] =
                edge.kind == XAIR_EDGE_CBRANCH_TRUE ? ControlTransferKind::branch_true :
                edge.kind == XAIR_EDGE_CBRANCH_FALSE ? ControlTransferKind::branch_false :
                ControlTransferKind::fallthrough;
        }
    }
    for (const ControlRegion& region : semantic.control.regions) {
        if (region.kind != ControlRegionKind::switch_region) continue;
        switch_headers.insert(region.header);
        for (const ControlSwitchCase& item : region.switch_cases) {
            if (item.target != XAIR_CFG_INVALID_ID) successors[region.header].push_back(item.target);
        }
        if (region.switch_default != XAIR_CFG_INVALID_ID) {
            successors[region.header].push_back(region.switch_default);
        }
    }
    while (!worklist.empty()) {
        const xair_cfg_node_id node_id = worklist.front();
        worklist.pop_front();
        if (outputs.contains(node_id)) continue;
        const xair_cfg_node* node = xair_cfg_get_node(&session.cfg(), node_id);
        if (node == nullptr) continue;
        NodeResult result = interpret_node(session.binary(), *node, inputs.at(node_id), digest,
            switch_headers.contains(node_id));
        if (successors[node_id].empty() && node_ends_in_call(session.binary(), *node)) {
            NodeResult tail = interpret_linear_fallthrough(
                session.binary(), node->end, result.state, digest);
            if (!tail.return_expression.empty()) result = std::move(tail);
        }
        if (!result.return_expression.empty()) {
            append_unique(digest.returns, {result.return_expression,
                evidence_id(node->start, node->end)});
        }
        outputs.emplace(node_id, result);
        for (const xair_cfg_node_id successor : successors[node_id]) {
            if (!inputs.contains(successor)) {
                inputs.emplace(successor, result.state);
                worklist.push_back(successor);
            }
        }
    }

    // Reinterpret branch paths independently so fixed stack slots retain their
    // path-specific values at shared return blocks. The ordinary traversal above
    // intentionally visits a CFG node once; that is useful for a stable digest but
    // would otherwise collapse O0 diamonds onto whichever predecessor arrived first.
    std::deque<PathState> paths;
    paths.push_back({semantic.control.entry, initial_state(), {}});
    std::size_t explored_paths = 0;
    while (!paths.empty() && explored_paths < 1024) {
        PathState path = std::move(paths.front());
        paths.pop_front();
        if (path.node == XAIR_CFG_INVALID_ID || ++path.visits[path.node] > 16) {
            continue;
        }
        const xair_cfg_node* node = xair_cfg_get_node(&session.cfg(), path.node);
        if (node == nullptr) continue;
        ++explored_paths;
        NodeResult result = interpret_node(session.binary(), *node, std::move(path.state),
            digest, switch_headers.contains(path.node));
        if (!result.return_expression.empty()) {
            append_unique(digest.returns, {result.return_expression,
                evidence_id(node->start, node->end)});
            continue;
        }
        std::unordered_set<xair_cfg_node_id> queued;
        for (const xair_cfg_node_id successor : successors[path.node]) {
            const auto kinds = successor_kinds.find(path.node);
            const ControlTransferKind kind = kinds != successor_kinds.end() &&
                kinds->second.contains(successor)
                ? kinds->second.at(successor) : ControlTransferKind::unresolved;
            if (result.branch_taken.has_value() &&
                ((kind == ControlTransferKind::branch_true && !*result.branch_taken) ||
                 (kind == ControlTransferKind::branch_false && *result.branch_taken))) {
                continue;
            }
            if (queued.insert(successor).second) {
                paths.push_back({successor, result.state, path.visits});
            }
        }
    }
    if (!paths.empty()) ++digest.unresolved;
    for (const ControlRegion& region : semantic.control.regions) {
        if (region.kind != ControlRegionKind::switch_region) continue;
        SwitchFact fact;
        const auto header_input = inputs.find(region.header);
        const auto header_output = outputs.find(region.header);
        if (header_output != outputs.end() && !header_output->second.index_expression.empty()) {
            fact.selector = header_output->second.index_expression;
        } else if (header_input != inputs.end()) {
            fact.selector = header_input->second.registers[XAIR_X86_RCX];
        } else {
            fact.selector = "unknown";
        }
        const xair_cfg_node* header = xair_cfg_get_node(&session.cfg(), region.header);
        fact.evidence = header == nullptr ? "" : evidence_id(header->start, header->end);
        for (const ControlSwitchCase& item : region.switch_cases) {
            const auto found = outputs.find(item.target);
            const xair_cfg_node* node = xair_cfg_get_node(&session.cfg(), item.target);
            std::string expression = found == outputs.end()
                ? "unknown" : found->second.return_expression;
            if (expression.empty() && header_output != outputs.end()) {
                expression = trace_return(session, item.target, header_output->second.state,
                    digest, successors, switch_headers).return_expression;
            }
            fact.cases.push_back({item.value, {
                expression.empty() ? "unknown" : expression,
                node == nullptr ? "" : evidence_id(node->start, node->end)}});
        }
        const auto found_default = outputs.find(region.switch_default);
        const xair_cfg_node* default_node =
            xair_cfg_get_node(&session.cfg(), region.switch_default);
        std::string default_expression = found_default == outputs.end()
            ? "unknown" : found_default->second.return_expression;
        if (default_expression.empty() && header_output != outputs.end()) {
            default_expression = trace_return(session, region.switch_default,
                header_output->second.state, digest, successors,
                switch_headers).return_expression;
        }
        fact.default_result = {
            default_expression.empty() ? "unknown" : default_expression,
            default_node == nullptr ? "" : evidence_id(default_node->start, default_node->end)};
        digest.switches.push_back(std::move(fact));
    }

    std::string rendered = render_digest(function, semantic, digest);
    while (max_bytes != 0 && rendered.size() > max_bytes) {
        bool removed = false;
        const auto trim = [&](auto& items) {
            if (items.empty()) return false;
            items.pop_back();
            ++digest.omitted;
            return true;
        };
        removed = trim(digest.memory) || trim(digest.conditions) || trim(digest.calls) ||
            trim(digest.returns);
        if (!removed && !digest.constants.empty()) {
            digest.constants.erase(std::prev(digest.constants.end()));
            ++digest.omitted;
            removed = true;
        }
        if (!removed && !digest.switches.empty() && !digest.switches.back().cases.empty()) {
            digest.switches.back().cases.pop_back();
            ++digest.omitted;
            removed = true;
        }
        if (!removed) return "{\"schema\":\"airece.agent-function.v1\",\"complete\":false,"
            "\"truncated\":true,\"omitted\":{\"facts\":1}}\n";
        rendered = render_digest(function, semantic, digest);
    }
    return rendered;
}

} // namespace airece
