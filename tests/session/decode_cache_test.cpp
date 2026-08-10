#include <airece/session/decode_cache.hpp>

#include <cassert>
#include <cstdint>

int main() {
    // call +5; conditional branch -2; return; malformed 0F tail
    std::uint8_t bytes[] = {
        0xe8, 0x05, 0x00, 0x00, 0x00,
        0x75, 0xfe,
        0xc3,
        0x0f
    };
    xair_binary_segment segment{};
    segment.va = 0x140001000;
    segment.mem_size = sizeof(bytes);
    segment.file_size = sizeof(bytes);
    segment.perms = XAIR_BINARY_PERM_READ | XAIR_BINARY_PERM_EXEC;
    segment.bytes = bytes;

    xair_binary_view binary{};
    binary.arch = XAIR_ARCH_X86_64;
    binary.entry = segment.va;
    binary.segments = &segment;
    binary.segment_count = 1;

    airece::DecodeCache cache{binary};
    const xair_x86_decoded_inst* instruction = nullptr;

    assert(cache.decode(segment.va, instruction) == XAIR_OK);
    assert(instruction != nullptr);
    assert(instruction->address == segment.va);
    assert(instruction->length == 5);
    assert(instruction->fallthrough == segment.va + 5);
    assert(instruction->branch_target_valid != 0);
    assert(instruction->branch_target == segment.va + 10);
    assert((instruction->control_flags & XAIR_X86_CONTROL_CALL) != 0);
    assert((instruction->control_flags & XAIR_X86_CONTROL_DIRECT) != 0);

    const auto* first = instruction;
    assert(cache.decode(segment.va, instruction) == XAIR_OK);
    assert(instruction == first);
    assert(cache.stats().requests == 2);
    assert(cache.stats().hits == 1);
    assert(cache.stats().entries == 1);

    assert(cache.decode(segment.va + 5, instruction) == XAIR_OK);
    assert(instruction->flow == XAIR_X86_FLOW_CONDITIONAL_JUMP);
    assert((instruction->control_flags & XAIR_X86_CONTROL_CONDITIONAL) != 0);
    assert(instruction->branch_target == segment.va + 5);

    assert(cache.decode(segment.va + 7, instruction) == XAIR_OK);
    assert(instruction->flow == XAIR_X86_FLOW_RETURN);
    assert((instruction->control_flags & XAIR_X86_CONTROL_RETURN) != 0);

    assert(cache.decode(segment.va + 8, instruction) == XAIR_ERR_RANGE);
    assert(instruction == nullptr);
    assert(cache.decode(segment.va + 8, instruction) == XAIR_ERR_RANGE);
    assert(cache.stats().hits == 2);
    return 0;
}
