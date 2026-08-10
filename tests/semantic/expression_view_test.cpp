#include <airece/semantic/expression_view.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
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
    xair_block_id block{XAIR_INVALID_ID};

    ModuleOwner() {
        require_xair(xair_module_create(&module), "create module");
        if (module != nullptr) require_xair(xair_block_create(module, "entry", &block), "create block");
    }
    ~ModuleOwner() { xair_module_destroy(module); }
    ModuleOwner(const ModuleOwner&) = delete;
    ModuleOwner& operator=(const ModuleOwner&) = delete;
};

void add_source(ModuleOwner& owner, const std::uint64_t address) {
    xair_source_record record{};
    record.kind = XAIR_SOURCE_MACHINE;
    record.confidence = XAIR_CONFIDENCE_EXACT;
    record.location.instruction_va = address;
    record.location.instruction_length = 5;
    record.decoder_name = "test";
    record.decoder_version = "1";
    record.semantic_id = "test.expression";
    xair_source_id source = XAIR_INVALID_SOURCE_ID;
    require_xair(xair_module_add_source(owner.module, &record, &source), "add source");
    require_xair(xair_module_set_current_source(owner.module, source), "set source");
}

std::string read_golden(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
    return text;
}

std::size_t occurrences(const std::string_view text, const std::string_view needle) {
    std::size_t count = 0;
    std::size_t position = 0;
    while ((position = text.find(needle, position)) != std::string_view::npos) {
        ++count;
        position += needle.size();
    }
    return count;
}

void test_basic_expression(const std::filesystem::path& golden_path) {
    ModuleOwner owner;
    add_source(owner, UINT64_C(0x140001034));
    xair_value_id argument = XAIR_INVALID_ID;
    xair_value_id memory = XAIR_INVALID_ID;
    xair_value_id offset = XAIR_INVALID_ID;
    xair_value_id address = XAIR_INVALID_ID;
    xair_value_id loaded = XAIR_INVALID_ID;
    xair_value_id zero = XAIR_INVALID_ID;
    xair_value_id condition = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_addr(64), "arg0", &argument), "add argument");
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_mem(0, 64), "mem0", &memory), "add memory");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(64), 0x18, "offset", &offset), "offset");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_ADDR_ADD, xair_type_addr(64),
        argument, offset, "field_address", &address), "address add");
    require_xair(xair_build_load(
        owner.module, owner.block, xair_type_i(64), memory, address,
        XAIR_ENDIAN_LE, "loaded", &loaded), "load");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(64), 0, "zero", &zero), "zero");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_EQ, xair_type_i(1),
        loaded, zero, "is_empty", &condition), "compare");
    require_xair(xair_set_return(owner.module, owner.block, &condition, 1), "return");

    airece::ExpressionRecovery recovery(*owner.module);
    expect(recovery.cache_size() == 0, "expression cache starts empty");
    const airece::SemanticExpression expression = recovery.build(condition);
    expect(static_cast<bool>(expression), "basic expression builds");
    expect(expression.text == read_golden(golden_path), "basic expression matches golden output");
    expect(expression.value == condition, "root XAIR value is retained");
    expect(expression.root_op != XAIR_INVALID_ID, "root XAIR operation is retained");
    expect(expression.type.kind == XAIR_TYPE_INT && expression.type.bits == 1,
           "exact result width is retained");
    expect(expression.display == airece::ExpressionDisplayKind::comparison,
           "comparison display kind is retained");
    expect(expression.source.begin == UINT64_C(0x140001034) &&
               expression.source.end == UINT64_C(0x140001039),
           "source span is recovered from XAIR records");
    expect(expression.source.confidence == XAIR_CONFIDENCE_EXACT,
           "source confidence is retained");
    expect(expression.operations.size() == 5, "all displayed XAIR operations are referenced");
    expect(std::find(expression.referenced_values.begin(), expression.referenced_values.end(), memory) !=
               expression.referenced_values.end(),
           "hidden memory SSA dependency remains referenced");
    expect(recovery.cache_size() == 1, "first expression is cached");
    expect(recovery.build(condition).text == expression.text, "cached output is deterministic");
    expect(recovery.cache_size() == 1, "identical request reuses cache entry");
    airece::ExpressionOptions alternate;
    alternate.max_depth = 2;
    (void)recovery.build(condition, alternate);
    expect(recovery.cache_size() == 2, "options participate in the cache key");
}

void test_effect_boundaries() {
    ModuleOwner owner;
    xair_value_id argument = XAIR_INVALID_ID;
    xair_value_id memory = XAIR_INVALID_ID;
    xair_value_id loaded = XAIR_INVALID_ID;
    xair_value_id call_results[2]{XAIR_INVALID_ID, XAIR_INVALID_ID};
    xair_value_id zero = XAIR_INVALID_ID;
    xair_value_id one = XAIR_INVALID_ID;
    xair_value_id condition = XAIR_INVALID_ID;
    xair_value_id sum = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_addr(64), "address", &argument), "address param");
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_mem(0, 64), "memory", &memory), "memory param");
    require_xair(xair_build_load(
        owner.module, owner.block, xair_type_i(32), memory, argument,
        XAIR_ENDIAN_LE, "loaded_before_call", &loaded), "load before call");
    const xair_value_id call_inputs[2]{argument, memory};
    const xair_type call_types[2]{xair_type_i(64), xair_type_mem(0, 64)};
    const char* const call_names[2]{"call_result", "call_memory"};
    xair_op_attributes call_attributes{};
    call_attributes.kind = XAIR_ATTR_CALL;
    call_attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL;
    call_attributes.direct_target = UINT64_C(0x401000);
    call_attributes.effects = XAIR_EFFECT_READ_MEMORY | XAIR_EFFECT_WRITE_MEMORY;
    require_xair(xair_build_call(
        owner.module, owner.block, call_inputs, 2, call_types, call_names, 2,
        &call_attributes, call_results), "call");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(32), 0, "zero", &zero), "zero");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_EQ, xair_type_i(1),
        loaded, zero, "condition", &condition), "comparison after call");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(64), 1, "one", &one), "one");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_ADD, xair_type_i(64),
        call_results[0], one, "sum", &sum), "call result sum");
    require_xair(xair_set_return(owner.module, owner.block, &condition, 1), "return");

    airece::ExpressionRecovery recovery(*owner.module);
    const airece::SemanticExpression after_call = recovery.build(condition);
    expect(after_call.text == "loaded_before_call == 0x0:bits32",
           "load is not moved across an intervening call");
    expect(occurrences(after_call.text, "load32(") == 0,
           "unsafe load is not duplicated into the consumer");
    expect(occurrences(after_call.text, "sub_401000") == 0,
           "unrelated call does not appear in comparison text");

    const airece::SemanticExpression call_use = recovery.build(sum);
    expect(call_use.text == "call_result + 0x1:bits64",
           "call results bind to a stable value instead of duplicating the call");
    expect(occurrences(call_use.text, "sub_401000") == 0,
           "effectful call is never inlined");
    const airece::SemanticExpression call_root = recovery.build(call_results[0]);
    expect(call_root.text == "sub_401000(address)", "root call result remains renderable");
    expect(call_root.display == airece::ExpressionDisplayKind::call_result,
           "call result display kind is explicit");
}

void test_repeated_load_and_opaque() {
    ModuleOwner owner;
    xair_value_id address = XAIR_INVALID_ID;
    xair_value_id memory = XAIR_INVALID_ID;
    xair_value_id loaded = XAIR_INVALID_ID;
    xair_value_id one = XAIR_INVALID_ID;
    xair_value_id two = XAIR_INVALID_ID;
    xair_value_id first = XAIR_INVALID_ID;
    xair_value_id second = XAIR_INVALID_ID;
    xair_value_id multiplied = XAIR_INVALID_ID;
    xair_value_id multiply_first = XAIR_INVALID_ID;
    xair_value_id multiply_second = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_addr(64), "address", &address), "address param");
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_mem(0, 64), "memory", &memory), "memory param");
    require_xair(xair_build_load(
        owner.module, owner.block, xair_type_i(32), memory, address,
        XAIR_ENDIAN_LE, "shared_load", &loaded), "shared load");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(32), 1, "one", &one), "one");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(32), 2, "two", &two), "two");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_ADD, xair_type_i(32),
        loaded, one, "first", &first), "first load use");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_ADD, xair_type_i(32),
        loaded, two, "second", &second), "second load use");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_MUL, xair_type_i(32),
        one, two, "shared_multiply", &multiplied), "shared multiply");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_ADD, xair_type_i(32),
        multiplied, one, "multiply_first", &multiply_first), "first multiply use");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_ADD, xair_type_i(32),
        multiplied, two, "multiply_second", &multiply_second), "second multiply use");
    require_xair(xair_set_return(owner.module, owner.block, &first, 1), "return");
    airece::ExpressionRecovery recovery(*owner.module);
    expect(recovery.build(first).text == "shared_load + 0x1:bits32",
           "repeated load degrades to a named value");
    expect(recovery.build(multiply_first).text == "shared_multiply + 0x1:bits32",
           "repeated expensive expression degrades to a named value");

    ModuleOwner opaque_owner;
    xair_value_id input = XAIR_INVALID_ID;
    xair_value_id opaque = XAIR_INVALID_ID;
    xair_value_id addend = XAIR_INVALID_ID;
    xair_value_id use = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        opaque_owner.module, opaque_owner.block, xair_type_i(32), "input", &input), "opaque input");
    const xair_value_id opaque_inputs[1]{input};
    const xair_type opaque_types[1]{xair_type_i(32)};
    const char* const opaque_names[1]{"opaque_value"};
    xair_op_attributes opaque_attributes{};
    opaque_attributes.kind = XAIR_ATTR_OPAQUE;
    opaque_attributes.semantic_id = "unsupported.test";
    require_xair(xair_build_opaque(
        opaque_owner.module, opaque_owner.block, 0, opaque_inputs, 1,
        opaque_types, opaque_names, 1, &opaque_attributes, &opaque), "opaque op");
    require_xair(xair_build_const_u64(
        opaque_owner.module, opaque_owner.block, xair_type_i(32), 1,
        "one", &addend), "opaque addend");
    require_xair(xair_build_binary(
        opaque_owner.module, opaque_owner.block, XAIR_OP_ADD, xair_type_i(32),
        opaque, addend, "opaque_use", &use), "opaque use");
    airece::ExpressionRecovery opaque_recovery(*opaque_owner.module);
    expect(opaque_recovery.build(use).text == "opaque_value + 0x1:bits32",
           "opaque operations are not inlined");
    const airece::SemanticExpression opaque_root = opaque_recovery.build(opaque);
    expect(opaque_root.text.find("opaque_pure<unsupported.test:bits32>(") == 0,
           "queried opaque operation renders explicitly");
    expect(opaque_root.display == airece::ExpressionDisplayKind::opaque,
           "opaque display kind is explicit");

    xair_value_id intrinsic = XAIR_INVALID_ID;
    const xair_type intrinsic_type = xair_type_i(32);
    const char* const intrinsic_name = "intrinsic_value";
    xair_op_attributes intrinsic_attributes{};
    intrinsic_attributes.kind = XAIR_ATTR_INTRINSIC;
    intrinsic_attributes.semantic_id = "crypto.test";
    xair_op_spec_v3 intrinsic_spec{};
    intrinsic_spec.opcode = XAIR_OP_INTRINSIC;
    intrinsic_spec.inputs = &input;
    intrinsic_spec.input_count = 1;
    intrinsic_spec.result_types = &intrinsic_type;
    intrinsic_spec.result_names = &intrinsic_name;
    intrinsic_spec.result_count = 1;
    intrinsic_spec.attributes = &intrinsic_attributes;
    intrinsic_spec.source = XAIR_INVALID_SOURCE_ID;
    require_xair(xair_build_op_v3(
        opaque_owner.module, opaque_owner.block, &intrinsic_spec, &intrinsic),
        "intrinsic op");
    airece::ExpressionRecovery intrinsic_recovery(*opaque_owner.module);
    const airece::SemanticExpression intrinsic_root = intrinsic_recovery.build(intrinsic);
    expect(intrinsic_root.text == "intrinsic<crypto.test:bits32>(input)",
           "unsupported intrinsic remains explicit with its semantic id");
    expect(intrinsic_root.display == airece::ExpressionDisplayKind::intrinsic,
           "intrinsic display kind is explicit");

    xair_value_id effectful_intrinsic = XAIR_INVALID_ID;
    xair_value_id effectful_use = XAIR_INVALID_ID;
    const char* const effectful_name = "effectful_intrinsic";
    xair_op_attributes effectful_attributes{};
    effectful_attributes.kind = XAIR_ATTR_INTRINSIC;
    effectful_attributes.effects = XAIR_EFFECT_READ_MEMORY | XAIR_EFFECT_MAY_FAULT;
    effectful_attributes.semantic_id = "device.read";
    xair_op_spec_v3 effectful_spec = intrinsic_spec;
    effectful_spec.result_names = &effectful_name;
    effectful_spec.attributes = &effectful_attributes;
    require_xair(xair_build_op_v3(
        opaque_owner.module, opaque_owner.block, &effectful_spec, &effectful_intrinsic),
        "effectful intrinsic");
    require_xair(xair_build_binary(
        opaque_owner.module, opaque_owner.block, XAIR_OP_ADD, xair_type_i(32),
        effectful_intrinsic, addend, "effectful_use", &effectful_use),
        "effectful intrinsic use");
    airece::ExpressionRecovery effectful_recovery(*opaque_owner.module);
    expect(effectful_recovery.build(effectful_use).text ==
               "effectful_intrinsic + 0x1:bits32",
           "effectful intrinsic is never inlined");
}

void test_store_and_barrier_boundaries() {
    ModuleOwner store_owner;
    xair_value_id address = XAIR_INVALID_ID;
    xair_value_id memory = XAIR_INVALID_ID;
    xair_value_id loaded = XAIR_INVALID_ID;
    xair_value_id data = XAIR_INVALID_ID;
    xair_value_id stored_memory = XAIR_INVALID_ID;
    xair_value_id zero = XAIR_INVALID_ID;
    xair_value_id condition = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        store_owner.module, store_owner.block, xair_type_addr(64),
        "address", &address), "store address");
    require_xair(xair_block_add_param(
        store_owner.module, store_owner.block, xair_type_mem(0, 64),
        "memory", &memory), "store memory");
    require_xair(xair_build_load(
        store_owner.module, store_owner.block, xair_type_i(32), memory, address,
        XAIR_ENDIAN_LE, "loaded_before_store", &loaded), "load before store");
    require_xair(xair_build_const_u64(
        store_owner.module, store_owner.block, xair_type_i(32), 7,
        "data", &data), "store data");
    require_xair(xair_build_store(
        store_owner.module, store_owner.block, memory, address, data,
        XAIR_ENDIAN_LE, "stored_memory", &stored_memory), "intervening store");
    require_xair(xair_build_const_u64(
        store_owner.module, store_owner.block, xair_type_i(32), 0,
        "zero", &zero), "store zero");
    require_xair(xair_build_binary(
        store_owner.module, store_owner.block, XAIR_OP_EQ, xair_type_i(1),
        loaded, zero, "condition", &condition), "comparison after store");
    airece::ExpressionRecovery store_recovery(*store_owner.module);
    expect(store_recovery.build(condition).text == "loaded_before_store == 0x0:bits32",
           "load is not moved across an intervening store");
    const airece::SemanticExpression store_root = store_recovery.build(stored_memory);
    expect(store_root.text == "store32(address, 0x7:bits32)",
           "queried store renders exactly once");
    expect(occurrences(store_root.text, "store32(") == 1,
           "store operation is never duplicated");

    ModuleOwner barrier_owner;
    xair_value_id barrier_address = XAIR_INVALID_ID;
    xair_value_id barrier_memory = XAIR_INVALID_ID;
    xair_value_id barrier_load = XAIR_INVALID_ID;
    xair_value_id barrier_zero = XAIR_INVALID_ID;
    xair_value_id barrier_condition = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        barrier_owner.module, barrier_owner.block, xair_type_addr(64),
        "address", &barrier_address), "barrier address");
    require_xair(xair_block_add_param(
        barrier_owner.module, barrier_owner.block, xair_type_mem(0, 64),
        "memory", &barrier_memory), "barrier memory");
    require_xair(xair_build_load(
        barrier_owner.module, barrier_owner.block, xair_type_i(32),
        barrier_memory, barrier_address, XAIR_ENDIAN_LE,
        "loaded_before_barrier", &barrier_load), "load before barrier");
    xair_op_attributes barrier_attributes{};
    barrier_attributes.kind = XAIR_ATTR_INTRINSIC;
    barrier_attributes.effects = XAIR_EFFECT_BARRIER | XAIR_EFFECT_ATOMIC;
    barrier_attributes.semantic_id = "test.barrier";
    xair_op_spec_v3 barrier_spec{};
    barrier_spec.opcode = XAIR_OP_MEMORY_BARRIER;
    barrier_spec.attributes = &barrier_attributes;
    barrier_spec.source = XAIR_INVALID_SOURCE_ID;
    require_xair(xair_build_op_v3(
        barrier_owner.module, barrier_owner.block, &barrier_spec, nullptr),
        "intervening barrier");
    require_xair(xair_build_const_u64(
        barrier_owner.module, barrier_owner.block, xair_type_i(32), 0,
        "zero", &barrier_zero), "barrier zero");
    require_xair(xair_build_binary(
        barrier_owner.module, barrier_owner.block, XAIR_OP_EQ, xair_type_i(1),
        barrier_load, barrier_zero, "condition", &barrier_condition),
        "comparison after barrier");
    airece::ExpressionRecovery barrier_recovery(*barrier_owner.module);
    expect(barrier_recovery.build(barrier_condition).text ==
               "loaded_before_barrier == 0x0:bits32",
           "load is not moved across an intervening barrier");
}

void test_cleanup_boolean_flags_and_unknown() {
    ModuleOwner owner;
    xair_value_id byte = XAIR_INVALID_ID;
    xair_value_id wide = XAIR_INVALID_ID;
    xair_value_id narrowed = XAIR_INVALID_ID;
    xair_value_id boolean = XAIR_INVALID_ID;
    xair_value_id false_value = XAIR_INVALID_ID;
    xair_value_id negated = XAIR_INVALID_ID;
    xair_value_id lhs = XAIR_INVALID_ID;
    xair_value_id rhs = XAIR_INVALID_ID;
    xair_value_id flags = XAIR_INVALID_ID;
    xair_value_id zero_flag = XAIR_INVALID_ID;
    xair_value_id true_value = XAIR_INVALID_ID;
    xair_value_id nonzero_flag = XAIR_INVALID_ID;
    xair_value_id unknown = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_i(8), "byte", &byte), "byte param");
    require_xair(xair_build_unary(
        owner.module, owner.block, XAIR_OP_ZEXT, xair_type_i(64),
        byte, "wide", &wide), "zext");
    require_xair(xair_build_unary(
        owner.module, owner.block, XAIR_OP_TRUNC, xair_type_i(8),
        wide, "narrowed", &narrowed), "trunc");
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_i(1), "condition", &boolean), "bool param");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(1), 0, "false", &false_value), "false");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_EQ, xair_type_i(1),
        boolean, false_value, "negated", &negated), "bool negation");
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_i(32), "lhs", &lhs), "lhs");
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_i(32), "rhs", &rhs), "rhs");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_FLAGS_SUB, xair_type_flags(6),
        lhs, rhs, "flags", &flags), "sub flags");
    require_xair(xair_build_unary(
        owner.module, owner.block, XAIR_OP_FLAG_ZF, xair_type_i(1),
        flags, "zf", &zero_flag), "zero flag");
    require_xair(xair_build_const_u64(
        owner.module, owner.block, xair_type_i(1), 1, "true", &true_value), "true");
    require_xair(xair_build_binary(
        owner.module, owner.block, XAIR_OP_XOR, xair_type_i(1),
        zero_flag, true_value, "not_zf", &nonzero_flag), "invert zero flag");
    require_xair(xair_build_unknown(
        owner.module, owner.block, xair_type_i(17),
        "unsupported.opcode", "unknown17", &unknown), "unknown");

    airece::ExpressionRecovery recovery(*owner.module);
    expect(recovery.build(narrowed).text == "byte",
           "truncation of a matching extension is cleaned up");
    expect(recovery.build(negated).text == "!condition",
           "comparison against false becomes boolean negation");
    expect(recovery.build(zero_flag).text == "lhs == rhs",
           "subtraction zero flag becomes a direct equality");
    expect(recovery.build(nonzero_flag).text == "lhs != rhs",
           "boolean inversion produces the inverse direct comparison");
    const airece::SemanticExpression unknown_expression = recovery.build(unknown);
    expect(unknown_expression.text == "unknown<bits17>(unsupported.opcode)",
           "unknown operation remains explicit with exact width");
    expect(unknown_expression.display == airece::ExpressionDisplayKind::unknown,
           "unknown display kind is explicit");
}

void test_depth_and_character_budgets() {
    ModuleOwner owner;
    xair_value_id value = XAIR_INVALID_ID;
    require_xair(xair_block_add_param(
        owner.module, owner.block, xair_type_i(64), "seed", &value), "seed");
    for (std::size_t index = 0; index < 256; ++index) {
        xair_value_id constant = XAIR_INVALID_ID;
        xair_value_id next = XAIR_INVALID_ID;
        const std::string constant_name = "constant_" + std::to_string(index);
        const std::string value_name = "temporary_" + std::to_string(index);
        require_xair(xair_build_const_u64(
            owner.module, owner.block, xair_type_i(64), index,
            constant_name.c_str(), &constant), "deep constant");
        require_xair(xair_build_binary(
            owner.module, owner.block, XAIR_OP_ADD, xair_type_i(64),
            value, constant, value_name.c_str(), &next), "deep add");
        value = next;
    }
    require_xair(xair_set_return(owner.module, owner.block, &value, 1), "deep return");
    airece::ExpressionRecovery recovery(*owner.module);
    airece::ExpressionOptions depth_options;
    depth_options.max_depth = 4;
    depth_options.max_nodes = 16;
    const airece::SemanticExpression bounded = recovery.build(value, depth_options);
    expect(bounded.truncated, "deep graph reports truncation");
    expect(bounded.omitted_nodes != 0, "deep graph reports omitted nodes");
    expect(bounded.text.find("temporary_") != std::string::npos,
           "deep graph degrades to a named temporary");

    airece::ExpressionOptions token_options;
    token_options.max_tokens = 3;
    const airece::SemanticExpression token_bounded =
        recovery.build(value, token_options);
    expect(token_bounded.truncated &&
               token_bounded.text.find("temporary_") != std::string::npos,
           "semantic token budget degrades to a named temporary");

    airece::ExpressionOptions character_options;
    character_options.max_characters = 24;
    const airece::SemanticExpression character_bounded =
        recovery.build(value, character_options);
    expect(character_bounded.truncated, "character limit reports truncation");
    expect(character_bounded.text.size() <= 24, "character limit is enforced");

    const airece::SemanticExpression invalid = recovery.build(XAIR_INVALID_ID);
    expect(!invalid && invalid.status == XAIR_ERR_BAD_ARG,
           "invalid root value is reported without recursion");
}

} // namespace

int main(const int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: expression_view_test <basic-golden>\n";
        return 2;
    }
    test_basic_expression(argv[1]);
    test_effect_boundaries();
    test_repeated_load_and_opaque();
    test_store_and_barrier_boundaries();
    test_cleanup_boolean_flags_and_unknown();
    test_depth_and_character_budgets();
    return failures == 0 ? 0 : 1;
}
