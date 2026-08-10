#include <xair_cfg/xair_cfg.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

constexpr std::uint64_t base = 0x140001000;

struct BinaryFixture {
    explicit BinaryFixture(std::vector<std::uint8_t> input)
        : bytes(std::move(input)) {
        segment.va = base;
        segment.mem_size = bytes.size();
        segment.file_size = bytes.size();
        segment.perms = XAIR_BINARY_PERM_READ | XAIR_BINARY_PERM_EXEC;
        segment.bytes = bytes.data();
        binary.arch = XAIR_ARCH_X86_64;
        binary.entry = base;
        binary.segments = &segment;
        binary.segment_count = 1;
    }

    std::vector<std::uint8_t> bytes;
    xair_binary_segment segment{};
    xair_binary_view binary{};
};

void require_lifter_boundary(
    const BinaryFixture& fixture,
    const xair_x86_decoded_inst& decoded,
    const xair_lift_end_kind expected_end) {
    xair_module* module = nullptr;
    assert(xair_module_create(&module) == XAIR_OK);
    xair_image image{};
    assert(xair_image_init(
        &image, fixture.bytes.data(), fixture.bytes.size(), base) == XAIR_OK);
    xair_lift_options options{};
    options.arch = XAIR_ARCH_X86_64;
    options.address = base;
    options.max_instructions = 1;
    options.block_name = "decoder_boundary";
    xair_lift_result result{};
    assert(xair_lift_basic_block(module, &image, &options, &result) == XAIR_OK);
    assert(result.instructions == 1);
    assert(result.bytes_read == decoded.length);
    assert(result.next == decoded.fallthrough);
    assert(result.end_kind == expected_end);
    xair_module_destroy(module);
}
void require_cfg_boundary(
    const BinaryFixture& fixture,
    const xair_x86_decoded_inst& decoded) {
    xair_cfg_options options{};
    xair_cfg_options_init(&options, XAIR_CFG_PROFILE_FAST);
    options.flags |= XAIR_CFG_BUILD_SKIP_IR |
        XAIR_CFG_BUILD_SKIP_INDIRECT_EXPANSION |
        XAIR_CFG_BUILD_SKIP_INDIRECT_ANALYSIS;
    options.max_blocks = 16;
    options.max_block_bytes = 64;

    xair_cfg_builder* builder = nullptr;
    assert(xair_cfg_builder_create(&fixture.binary, &options, &builder) == XAIR_OK);
    assert(xair_cfg_add_root(builder, base) == XAIR_OK);
    xair_cfg* cfg = nullptr;
    xair_cfg_stats stats{};
    xair_error error{};
    assert(xair_cfg_build(builder, &cfg, &stats, &error) == XAIR_OK);
    const auto node_id = xair_cfg_find_node_start(cfg, base);
    assert(node_id != XAIR_CFG_INVALID_ID);
    const auto* node = xair_cfg_get_node(cfg, node_id);
    assert(node != nullptr);
    assert(node->instruction_count == 1);
    assert(node->end == decoded.fallthrough);
    xair_cfg_destroy(cfg);
    xair_cfg_builder_destroy(builder);
}

void test_boundary(
    std::vector<std::uint8_t> bytes,
    const xair_x86_flow_kind flow,
    const xair_lift_end_kind lift_end) {
    const BinaryFixture fixture{std::move(bytes)};
    xair_x86_decoded_inst decoded{};
    assert(xair_decode_instruction(&fixture.binary, base, &decoded) == XAIR_OK);
    assert(decoded.flow == flow);
    assert(decoded.address == base);
    assert(decoded.length > 0);
    assert(decoded.fallthrough == base + decoded.length);
    require_lifter_boundary(fixture, decoded, lift_end);
    require_cfg_boundary(fixture, decoded);
}

} // namespace

int main() {
    // Each target lands on a return inside the same executable segment.
    test_boundary({0xeb, 0x00, 0xc3}, XAIR_X86_FLOW_DIRECT_JUMP,
                  XAIR_LIFT_END_DIRECT_JUMP);
    test_boundary({0x75, 0x00, 0xc3}, XAIR_X86_FLOW_CONDITIONAL_JUMP,
                  XAIR_LIFT_END_DIRECT_CBRANCH);
    test_boundary({0xc3}, XAIR_X86_FLOW_RETURN, XAIR_LIFT_END_RETURN);
    test_boundary({0xff, 0xe0}, XAIR_X86_FLOW_INDIRECT_JUMP,
                  XAIR_LIFT_END_INDIRECT_JUMP);
    test_boundary({0xcc}, XAIR_X86_FLOW_TRAP, XAIR_LIFT_END_TRAP);

    BinaryFixture call{{0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3}};
    xair_x86_decoded_inst decoded{};
    assert(xair_decode_instruction(&call.binary, base, &decoded) == XAIR_OK);
    assert(decoded.flow == XAIR_X86_FLOW_DIRECT_CALL);
    assert((decoded.control_flags & XAIR_X86_CONTROL_CALL) != 0);
    require_lifter_boundary(call, decoded, XAIR_LIFT_END_FALLTHROUGH);
    require_cfg_boundary(call, decoded);

    BinaryFixture memory_indirect{{0xff, 0x24, 0xc5, 0x00, 0x20, 0x00, 0x00}};
    assert(xair_decode_instruction(&memory_indirect.binary, base, &decoded) == XAIR_OK);
    assert(decoded.flow == XAIR_X86_FLOW_INDIRECT_JUMP);
    assert(decoded.has_modrm != 0);
    assert(decoded.has_sib != 0);
    assert(decoded.modrm == 0x24);
    assert(decoded.sib == 0xc5);
    assert(decoded.displacement_size == 4);

    BinaryFixture malformed{{0x0f}};
    assert(xair_decode_instruction(&malformed.binary, base, &decoded) == XAIR_ERR_RANGE);
    assert(decoded.error == XAIR_X86_DECODE_TRUNCATED);
    return 0;
}
