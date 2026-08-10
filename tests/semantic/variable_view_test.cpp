#include <airece/semantic/variable_view.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
    if (condition) return;
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
}

void require_xair(const xair_status status, const std::string& operation) {
    if (status == XAIR_OK) return;
    std::cerr << "FAIL: " << operation << ": " << xair_status_name(status) << '\n';
    ++failures;
}

struct ModuleOwner {
    xair_module* module{};

    ModuleOwner() { require_xair(xair_module_create(&module), "create module"); }
    ~ModuleOwner() { xair_module_destroy(module); }
    ModuleOwner(const ModuleOwner&) = delete;
    ModuleOwner& operator=(const ModuleOwner&) = delete;
};

const airece::PresentationVariable* find_value(
    const airece::VariableView& view,
    const xair_value_id value) {
    const auto found = std::find_if(view.variables.begin(), view.variables.end(),
        [value](const airece::PresentationVariable& variable) {
            return !variable.storage_identity && variable.primary_value == value;
        });
    return found == view.variables.end() ? nullptr : &*found;
}

std::vector<const airece::PresentationVariable*> find_kind(
    const airece::VariableView& view,
    const airece::VariableKind kind) {
    std::vector<const airece::PresentationVariable*> result;
    for (const airece::PresentationVariable& variable : view.variables) {
        if (variable.kind == kind) result.push_back(&variable);
    }
    return result;
}

void add_source(ModuleOwner& owner) {
    xair_source_record record{};
    record.kind = XAIR_SOURCE_MACHINE;
    record.confidence = XAIR_CONFIDENCE_EXACT;
    record.location.instruction_va = UINT64_C(0x140001020);
    record.location.instruction_length = 6;
    record.decoder_name = "test";
    record.decoder_version = "1";
    record.semantic_id = "test.variables";
    xair_source_id source = XAIR_INVALID_SOURCE_ID;
    require_xair(xair_module_add_source(owner.module, &record, &source), "add source");
    require_xair(xair_module_set_current_source(owner.module, source), "set source");
}

void test_function_variables() {
    ModuleOwner owner;
    xair_block_id entry = XAIR_INVALID_ID;
    require_xair(xair_block_create(owner.module, "entry", &entry), "entry block");
    add_source(owner);

    xair_value_id rcx = XAIR_INVALID_ID;
    xair_value_id rdx = XAIR_INVALID_ID;
    xair_value_id r8 = XAIR_INVALID_ID;
    xair_value_id rsp = XAIR_INVALID_ID;
    xair_value_id memory = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, entry, xair_type_addr(64), "rcx", &rcx), "rcx");
    require_xair(xair_block_add_param(
        owner.module, entry, xair_type_i(32), "rdx", &rdx), "rdx");
    require_xair(xair_block_add_param(
        owner.module, entry, xair_type_i(32), "r8", &r8), "r8");
    require_xair(xair_block_add_param(
        owner.module, entry, xair_type_addr(64), "rsp", &rsp), "rsp");
    require_xair(xair_block_add_param(
        owner.module, entry, xair_type_mem(0, 64), "mem", &memory), "memory");

    xair_value_id frame_size = XAIR_INVALID_ID;
    xair_value_id frame = XAIR_INVALID_ID;
    xair_value_id offset = XAIR_INVALID_ID;
    xair_value_id stack_address = XAIR_INVALID_ID;
    require_xair(xair_build_const_u64(
        owner.module, entry, xair_type_i(64), 0x20, "frame_size", &frame_size),
        "frame size");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_ADDR_SUB, xair_type_addr(64),
        rsp, frame_size, "frame", &frame), "stack frame");
    require_xair(xair_build_const_u64(
        owner.module, entry, xair_type_i(64), 8, "offset", &offset),
        "stack offset");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_ADDR_ADD, xair_type_addr(64),
        frame, offset, "stack_address", &stack_address), "stack address");

    xair_value_id stack32 = XAIR_INVALID_ID;
    xair_value_id stack64 = XAIR_INVALID_ID;
    xair_value_id stored_memory = XAIR_INVALID_ID;
    require_xair(xair_build_load(
        owner.module, entry, xair_type_i(32), memory, stack_address,
        XAIR_ENDIAN_LE, "stack32", &stack32), "stack load32");
    require_xair(xair_build_load(
        owner.module, entry, xair_type_i(64), memory, stack_address,
        XAIR_ENDIAN_LE, "stack64", &stack64), "stack load64");
    require_xair(xair_build_store(
        owner.module, entry, memory, stack_address, stack32,
        XAIR_ENDIAN_LE, "stored_memory", &stored_memory), "stack store32");

    xair_value_id stack_argument_offset = XAIR_INVALID_ID;
    xair_value_id stack_argument_address = XAIR_INVALID_ID;
    xair_value_id stack_argument_value = XAIR_INVALID_ID;
    require_xair(xair_build_const_u64(
        owner.module, entry, xair_type_i(64), 0x28,
        "stack_argument_offset", &stack_argument_offset), "stack argument offset");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_ADDR_ADD, xair_type_addr(64),
        rsp, stack_argument_offset, "stack_argument_address", &stack_argument_address),
        "stack argument address");
    require_xair(xair_build_load(
        owner.module, entry, xair_type_i(16), stored_memory, stack_argument_address,
        XAIR_ENDIAN_LE, "stack_argument_value", &stack_argument_value),
        "stack argument load");

    xair_value_id global_address = XAIR_INVALID_ID;
    xair_value_id global_byte = XAIR_INVALID_ID;
    require_xair(xair_build_const_u64(
        owner.module, entry, xair_type_addr(64), UINT64_C(0x140005000),
        "global_address", &global_address), "global address");
    require_xair(xair_build_load(
        owner.module, entry, xair_type_i(8), stored_memory, global_address,
        XAIR_ENDIAN_LE, "global_byte", &global_byte), "global load");

    xair_value_id pointed_byte = XAIR_INVALID_ID;
    require_xair(xair_build_load(
        owner.module, entry, xair_type_i(8), stored_memory, rcx,
        XAIR_ENDIAN_LE, "pointed_byte", &pointed_byte), "argument buffer load");

    xair_value_id signed_zero = XAIR_INVALID_ID;
    xair_value_id signed_condition = XAIR_INVALID_ID;
    require_xair(xair_build_const_u64(
        owner.module, entry, xair_type_i(32), 0, "zero", &signed_zero),
        "signed zero");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_SLT, xair_type_i(1),
        rdx, signed_zero, "negative", &signed_condition), "signed comparison");

    xair_value_id unsigned_limit = XAIR_INVALID_ID;
    xair_value_id unsigned_condition = XAIR_INVALID_ID;
    require_xair(xair_build_const_u64(
        owner.module, entry, xair_type_i(32), 0x100, "limit", &unsigned_limit),
        "unsigned limit");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_ULT, xair_type_i(1),
        r8, unsigned_limit, "below_limit", &unsigned_condition), "unsigned comparison");

    xair_value_id one = XAIR_INVALID_ID;
    xair_value_id repeated = XAIR_INVALID_ID;
    xair_value_id repeated_first = XAIR_INVALID_ID;
    xair_value_id repeated_second = XAIR_INVALID_ID;
    require_xair(xair_build_const_u64(
        owner.module, entry, xair_type_i(32), 1, "one", &one), "one");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_MUL, xair_type_i(32),
        stack32, one, "repeated", &repeated), "repeated value");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_ADD, xair_type_i(32),
        repeated, one, "repeated_first", &repeated_first), "repeated use one");
    require_xair(xair_build_binary(
        owner.module, entry, XAIR_OP_SUB, xair_type_i(32),
        repeated, one, "repeated_second", &repeated_second), "repeated use two");

    const xair_value_id call_inputs[2]{rcx, stored_memory};
    const xair_type call_types[2]{xair_type_i(64), xair_type_mem(0, 64)};
    const char* const call_names[2]{"call_rax", "call_memory"};
    xair_value_id call_results[2]{XAIR_INVALID_ID, XAIR_INVALID_ID};
    xair_op_attributes call_attributes{};
    call_attributes.kind = XAIR_ATTR_CALL;
    call_attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL;
    call_attributes.calling_convention = XAIR_CC_WIN64;
    call_attributes.effects = XAIR_EFFECT_READ_MEMORY | XAIR_EFFECT_WRITE_MEMORY;
    call_attributes.confidence = XAIR_CONFIDENCE_HIGH;
    require_xair(xair_build_call(
        owner.module, entry, call_inputs, 2, call_types, call_names, 2,
        &call_attributes, call_results), "OpenProcess call");
    require_xair(xair_set_return(
        owner.module, entry, &call_results[0], 1), "function return");

    xair_op_id call_operation = XAIR_INVALID_ID;
    require_xair(xair_value_definition(
        owner.module, call_results[0], &call_operation), "call definition");

    airece::VariableContext context;
    airece::VariableSymbol argument_symbol;
    argument_symbol.value = rcx;
    argument_symbol.name = "request_buffer";
    argument_symbol.origin = airece::VariableSymbolOrigin::debug_symbol;
    argument_symbol.confidence = XAIR_CONFIDENCE_EXACT;
    context.symbols.push_back(argument_symbol);
    airece::VariableSymbol global_symbol;
    global_symbol.address = UINT64_C(0x140005000);
    global_symbol.size = 0x100;
    global_symbol.name = "config_blob";
    global_symbol.origin = airece::VariableSymbolOrigin::binary_symbol;
    context.symbols.push_back(global_symbol);
    context.ranges.push_back({UINT64_C(0x140005000), UINT64_C(0x140006000),
                              true, true, false});
    context.calls.push_back({call_operation, "kernel32.dll", "OpenProcess", 0,
                             XAIR_CONFIDENCE_HIGH});

    airece::VariableRecovery recovery(*owner.module, std::move(context));
    airece::VariableScope scope;
    scope.function_address = UINT64_C(0x140001000);
    scope.entry_block = entry;
    scope.blocks.push_back(entry);
    scope.calling_convention = XAIR_CC_WIN64;

    expect(recovery.cache_size() == 0, "variable cache starts empty");
    const airece::VariableView view = recovery.build(scope);
    expect(static_cast<bool>(view), "variable view builds");
    expect(recovery.cache_size() == 1, "variable view is cached");

    const airece::PresentationVariable* arg0 = find_value(view, rcx);
    expect(arg0 != nullptr && arg0->kind == airece::VariableKind::argument,
           "Win64 rcx becomes the first function argument");
    expect(arg0 != nullptr && arg0->name.text == "request_buffer" &&
               arg0->name.origin == airece::VariableNameOrigin::debug_symbol,
           "debug symbol outranks semantic argument naming");
    expect(arg0 != nullptr && arg0->type.text == "ptr<u8>" &&
               arg0->type.exact_bits == 64,
           "argument used for memory receives byte-pointer presentation type");

    const airece::PresentationVariable* arg1 = find_value(view, rdx);
    expect(arg1 != nullptr && arg1->name.text == "arg1",
           "calling-convention argument receives stable semantic name");
    expect(arg1 != nullptr && arg1->type.text == "i32" &&
               arg1->type.exact_bits == 32,
           "signed operation supplies signed presentation context");

    const airece::PresentationVariable* arg2 = find_value(view, r8);
    expect(arg2 != nullptr && arg2->name.text == "arg2" &&
               arg2->type.text == "u32" && arg2->type.exact_bits == 32,
           "unsigned operation supplies unsigned presentation context");

    const airece::PresentationVariable* call_result = find_value(view, call_results[0]);
    expect(call_result != nullptr &&
               call_result->name.text == "call_OpenProcess_result",
           "import/API role names the call result");
    expect(call_result != nullptr && call_result->type.text == "handle" &&
               call_result->type.exact_bits == 64,
           "known OpenProcess result is presented as a width-backed handle");
    expect(call_result != nullptr &&
               (call_result->roles & airece::variable_role_return) != 0,
           "call result also retains its return-value role");

    const airece::PresentationVariable* repeated_variable = find_value(view, repeated);
    expect(repeated_variable != nullptr &&
               repeated_variable->kind == airece::VariableKind::repeated_value,
           "repeated SSA value receives a presentation identity");
    expect(repeated_variable != nullptr &&
               repeated_variable->name.text == "tmp_" + std::to_string(repeated),
           "repeated SSA fallback name is deterministic from value id");

    const auto stack_slots = find_kind(view, airece::VariableKind::stack_slot);
    expect(stack_slots.size() == 2, "overlapping 32-bit and 64-bit stack accesses stay separate");
    if (stack_slots.size() == 2) {
        expect(stack_slots[0]->stack_offset == -24 && stack_slots[1]->stack_offset == -24,
               "stack affine recovery accounts for frame adjustment and displacement");
        expect(stack_slots[0]->overlaps_uncertain && stack_slots[1]->overlaps_uncertain,
               "overlapping stack identities are explicitly uncertain");
        expect(stack_slots[0]->storage_bits != stack_slots[1]->storage_bits,
               "overlapping slots retain their exact access widths");
        expect(stack_slots[0]->stable_id != stack_slots[1]->stable_id &&
                   stack_slots[0]->name.text != stack_slots[1]->name.text,
               "overlapping slots have distinct stable identities and names");
    }

    const auto arguments = find_kind(view, airece::VariableKind::argument);
    const auto stack_argument = std::find_if(arguments.begin(), arguments.end(),
        [](const airece::PresentationVariable* variable) {
            return variable->storage_identity && variable->name.text == "arg4";
        });
    expect(stack_argument != arguments.end(),
           "Win64 entry-stack offset 0x28 becomes the fifth argument");
    if (stack_argument != arguments.end()) {
        expect(((*stack_argument)->roles & airece::variable_role_stack_slot) != 0 &&
                   (*stack_argument)->stack_offset == 0x28 &&
                   (*stack_argument)->type.exact_bits == 16,
               "stack argument keeps storage evidence, offset, and exact width");
    }

    const auto globals = find_kind(view, airece::VariableKind::global);
    const auto named_global = std::find_if(globals.begin(), globals.end(),
        [](const airece::PresentationVariable* variable) {
            return variable->name.text == "config_blob";
        });
    expect(named_global != globals.end(), "exact global symbol names the storage identity");
    if (named_global != globals.end()) {
        expect((*named_global)->address == UINT64_C(0x140005000) &&
                   (*named_global)->storage_bits == 8,
               "global identity retains exact address and access width");
    }

    std::unordered_set<std::string> stable_ids;
    std::unordered_set<std::string> names;
    for (const airece::PresentationVariable& variable : view.variables) {
        expect(stable_ids.insert(variable.stable_id).second,
               "each presentation identity has a unique stable id");
        expect(names.insert(variable.name.text).second,
               "each presentation identity has a unique deterministic name");
        expect(!variable.name.evidence.reason.empty() &&
                   variable.name.evidence.confidence != XAIR_CONFIDENCE_UNKNOWN,
               "every inferred name carries reason and confidence");
        expect(!variable.type.evidence.reason.empty() &&
                   variable.type.evidence.confidence != XAIR_CONFIDENCE_UNKNOWN,
               "every presentation type carries reason and confidence");
    }

    const airece::VariableView cached = recovery.build(scope);
    expect(cached.variables.size() == view.variables.size(),
           "cached variable view has deterministic cardinality");
    if (cached.variables.size() == view.variables.size()) {
        for (std::size_t index = 0; index < view.variables.size(); ++index) {
            expect(cached.variables[index].stable_id == view.variables[index].stable_id &&
                       cached.variables[index].name.text == view.variables[index].name.text &&
                       cached.variables[index].type.text == view.variables[index].type.text,
                   "cached variable ordering, naming, and typing are deterministic");
        }
    }
    expect(recovery.cache_size() == 1, "identical variable request reuses cache entry");

    airece::VariableOptions bounded_options;
    bounded_options.max_variables = 2;
    const airece::VariableView bounded = recovery.build(scope, bounded_options);
    expect(bounded.truncated && bounded.variables.size() == 2 &&
               bounded.omitted_variables != 0,
           "variable count budget reports deterministic omission");
}

void test_register_identity_and_unknown_width() {
    ModuleOwner owner;
    xair_block_id first = XAIR_INVALID_ID;
    xair_block_id second = XAIR_INVALID_ID;
    require_xair(xair_block_create(owner.module, "first", &first), "first block");
    require_xair(xair_block_create(owner.module, "second", &second), "second block");

    xair_value_id first_rax = XAIR_INVALID_ID;
    xair_value_id second_rax = XAIR_INVALID_ID;
    xair_value_id unusual = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, first, xair_type_i(64), "rax", &first_rax), "first rax");
    require_xair(xair_block_add_param(
        owner.module, second, xair_type_i(64), "rax", &second_rax), "second rax");
    require_xair(xair_block_add_param(
        owner.module, first, xair_type_i(17), "odd", &unusual), "odd width");

    const auto add_two_uses = [&](const xair_block_id block,
                                  const xair_value_id value,
                                  const xair_type type,
                                  const char* prefix) {
        xair_value_id one = XAIR_INVALID_ID;
        xair_value_id first_use = XAIR_INVALID_ID;
        xair_value_id second_use = XAIR_INVALID_ID;
        require_xair(xair_build_const_u64(
            owner.module, block, type, 1, "one", &one), std::string(prefix) + " constant");
        require_xair(xair_build_binary(
            owner.module, block, XAIR_OP_ADD, type,
            value, one, "use_one", &first_use), std::string(prefix) + " use one");
        require_xair(xair_build_binary(
            owner.module, block, XAIR_OP_SUB, type,
            value, one, "use_two", &second_use), std::string(prefix) + " use two");
    };
    add_two_uses(first, first_rax, xair_type_i(64), "first rax");
    add_two_uses(second, second_rax, xair_type_i(64), "second rax");
    xair_value_id odd_one = XAIR_INVALID_ID;
    xair_value_id odd_use_one = XAIR_INVALID_ID;
    xair_value_id odd_use_two = XAIR_INVALID_ID;
    require_xair(xair_build_const_u64(
        owner.module, first, xair_type_i(17), 1, "odd_one", &odd_one), "odd one");
    require_xair(xair_build_binary(
        owner.module, first, XAIR_OP_ADD, xair_type_i(17),
        unusual, odd_one, "odd_use_one", &odd_use_one), "odd use one");
    require_xair(xair_build_binary(
        owner.module, first, XAIR_OP_SUB, xair_type_i(17),
        unusual, odd_one, "odd_use_two", &odd_use_two), "odd use two");

    airece::VariableContext context;
    context.symbols.push_back({first_rax, 0, 0, "register_value",
                               airece::VariableSymbolOrigin::user,
                               XAIR_CONFIDENCE_EXACT, {}});
    context.symbols.push_back({second_rax, 0, 0, "register_value",
                               airece::VariableSymbolOrigin::user,
                               XAIR_CONFIDENCE_EXACT, {}});
    airece::VariableRecovery recovery(*owner.module, std::move(context));
    airece::VariableScope scope;
    scope.entry_block = first;
    scope.blocks = {first, second};
    const airece::VariableView view = recovery.build(scope);
    const airece::PresentationVariable* first_variable = find_value(view, first_rax);
    const airece::PresentationVariable* second_variable = find_value(view, second_rax);
    expect(first_variable != nullptr && second_variable != nullptr,
           "both live values sharing a register name remain represented");
    expect(first_variable != nullptr && second_variable != nullptr &&
               first_variable->stable_id != second_variable->stable_id &&
               first_variable->name.text != second_variable->name.text &&
               first_variable->values.size() == 1 && second_variable->values.size() == 1,
           "same register spelling never merges distinct XAIR values");
    expect(first_variable != nullptr && second_variable != nullptr &&
               first_variable->name.text == "register_value" &&
               second_variable->name.text ==
                   "register_value_v" + std::to_string(second_rax),
           "colliding user names receive deterministic unique suffixes");
    expect(first_variable != nullptr && second_variable != nullptr &&
               first_variable->type.text == "unknown<64>" &&
               second_variable->type.text == "unknown<64>",
           "neutral arithmetic does not invent integer signedness");

    const airece::PresentationVariable* odd_variable = find_value(view, unusual);
    expect(odd_variable != nullptr && odd_variable->type.text == "unknown<17>" &&
               odd_variable->type.exact_bits == 17,
           "unsupported scalar type retains exact width");
}

void test_indirect_function_pointer() {
    ModuleOwner owner;
    xair_block_id entry = XAIR_INVALID_ID;
    require_xair(xair_block_create(owner.module, "entry", &entry), "indirect entry");
    xair_value_id memory = XAIR_INVALID_ID;
    xair_value_id target = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, entry, xair_type_mem(0, 64), "memory", &memory),
        "indirect memory");
    require_xair(xair_block_add_param(
        owner.module, entry, xair_type_addr(64), "target", &target),
        "indirect target");
    const xair_value_id inputs[2]{memory, target};
    const xair_type result_types[2]{xair_type_i(64), xair_type_mem(0, 64)};
    const char* const result_names[2]{"call_rax", "call_memory"};
    xair_value_id results[2]{XAIR_INVALID_ID, XAIR_INVALID_ID};
    xair_op_attributes attributes{};
    attributes.kind = XAIR_ATTR_CALL;
    attributes.call_kind = XAIR_CALL_INDIRECT;
    attributes.effects = XAIR_EFFECT_READ_MEMORY | XAIR_EFFECT_WRITE_MEMORY;
    require_xair(xair_build_call(
        owner.module, entry, inputs, 2, result_types, result_names, 2,
        &attributes, results), "indirect call");
    require_xair(xair_set_return(owner.module, entry, &results[0], 1), "indirect return");

    airece::VariableRecovery recovery(*owner.module);
    airece::VariableScope scope;
    scope.entry_block = entry;
    scope.blocks.push_back(entry);
    const airece::VariableView view = recovery.build(scope);
    const airece::PresentationVariable* target_variable = find_value(view, target);
    expect(target_variable != nullptr && target_variable->type.text == "function_ptr" &&
               target_variable->type.exact_bits == 64,
           "indirect call target receives function-pointer presentation type");
}

} // namespace

int main() {
    test_function_variables();
    test_register_identity_and_unknown_width();
    test_indirect_function_pointer();
    return failures == 0 ? 0 : 1;
}
