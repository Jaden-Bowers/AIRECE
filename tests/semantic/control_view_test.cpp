#include <airece/semantic/control_view.hpp>
#include <airece/emit/semantic_text.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
    if (condition) return;
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
}

struct GraphFixture {
    std::vector<std::uint8_t> bytes;
    xair_binary_segment segment{};
    xair_binary_view binary{};
    xair_cfg* cfg{};
    xair_function_id function{XAIR_CFG_INVALID_ID};

    explicit GraphFixture(std::vector<std::uint8_t> code, const std::uint64_t base)
        : bytes(std::move(code)) {
        segment.va = base;
        segment.mem_size = bytes.size();
        segment.file_size = bytes.size();
        segment.perms = XAIR_BINARY_PERM_READ | XAIR_BINARY_PERM_EXEC;
        segment.bytes = bytes.data();
        binary.format = XAIR_BINARY_FORMAT_ELF;
        binary.arch = XAIR_ARCH_X86_64;
        binary.entry = base;
        binary.image_base = base;
        binary.segments = &segment;
        binary.segment_count = 1;

        xair_cfg_options options{};
        xair_cfg_options_init(&options, XAIR_CFG_PROFILE_BALANCED);
        options.arch = binary.arch;
        options.entry = base;
        options.max_block_bytes = 64;
        options.flags = XAIR_CFG_BUILD_FAST_DIRECT;
        options.decoder = XAIR_CFG_DECODER_ZYDIS;
        xair_cfg_builder* builder = nullptr;
        xair_status status = xair_cfg_builder_create(&binary, &options, &builder);
        if (status == XAIR_OK) status = xair_cfg_add_root(builder, base);
        xair_cfg_stats stats{};
        xair_error error{};
        if (status == XAIR_OK) status = xair_cfg_build(builder, &cfg, &stats, &error);
        xair_cfg_builder_destroy(builder);
        expect(status == XAIR_OK, "synthetic CFG builds");
        if (status != XAIR_OK || cfg == nullptr) return;
        for (std::size_t index = 0; index < xair_cfg_function_count(cfg); ++index) {
            const xair_function* candidate = xair_cfg_get_function(
                cfg, static_cast<xair_function_id>(index));
            if (candidate != nullptr && candidate->entry == base) {
                function = static_cast<xair_function_id>(index);
                break;
            }
        }
        expect(function != XAIR_CFG_INVALID_ID, "synthetic entry function is discovered");
    }

    ~GraphFixture() { xair_cfg_destroy(cfg); }
    GraphFixture(const GraphFixture&) = delete;
    GraphFixture& operator=(const GraphFixture&) = delete;
};

bool has_region(
    const airece::ControlView& view,
    const airece::ControlRegionKind kind) {
    return std::any_of(view.regions.begin(), view.regions.end(),
        [kind](const airece::ControlRegion& region) { return region.kind == kind; });
}

const airece::ControlRegion* find_region(
    const airece::ControlView& view,
    const airece::ControlRegionKind kind) {
    const auto found = std::find_if(view.regions.begin(), view.regions.end(),
        [kind](const airece::ControlRegion& region) { return region.kind == kind; });
    return found == view.regions.end() ? nullptr : &*found;
}

airece::CompactFunctionView pseudo_fixture(const airece::ControlView& control) {
    airece::CompactFunctionView view;
    view.function.entry = UINT64_C(0x12340000);
    view.function.name = "semantic_test";
    view.control = control;
    return view;
}

std::size_t expected_transfer_count(
    const GraphFixture& fixture,
    const std::vector<xair_cfg_node_id>& nodes) {
    std::size_t result = 0;
    for (const xair_cfg_node_id node_id : nodes) {
        const xair_cfg_node* node = xair_cfg_get_node(fixture.cfg, node_id);
        if (node == nullptr) continue;
        for (std::uint16_t edge_index = 0; edge_index < node->edge_count; ++edge_index) {
            const xair_cfg_edge* edge = xair_cfg_get_edge(
                fixture.cfg, node->edge_offset + edge_index);
            if (edge != nullptr) ++result;
        }
    }
    return result;
}

airece::ControlView recover(GraphFixture& fixture) {
    expect(fixture.cfg != nullptr && fixture.function != XAIR_CFG_INVALID_ID,
           "fixture is usable");
    if (fixture.cfg == nullptr || fixture.function == XAIR_CFG_INVALID_ID) return {};
    const xair_module* module = xair_cfg_module(fixture.cfg);
    expect(module != nullptr, "synthetic CFG retains XAIR");
    if (module == nullptr) return {};
    airece::ControlRecovery recovery(*fixture.cfg, *module);
    const airece::ControlView first = recovery.build(fixture.function);
    const airece::ControlView second = recovery.build(fixture.function);
    expect(first.regions.size() == second.regions.size() &&
               first.transfers.size() == second.transfers.size() &&
               recovery.cache_size() == 1,
           "control structuring is deterministic and cached");
    expect(first.transfers.size() + first.omitted_transfers ==
               expected_transfer_count(fixture, first.block_order),
           "every function CFG transfer is represented or explicitly omitted");
    for (const airece::ControlRegion& region : first.regions) {
        expect(!region.nodes.empty() && region.evidence.begin != 0,
               "synthetic regions retain CFG nodes and address evidence");
    }
    return first;
}

void put_le64(std::vector<std::uint8_t>& bytes,
              const std::size_t offset,
              const std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void test_linear_and_conditionals() {
    GraphFixture linear({0x90, 0x90, 0xc3}, UINT64_C(0x1000));
    expect(has_region(recover(linear), airece::ControlRegionKind::sequence),
           "linear sequence is recognized");

    GraphFixture if_else({
        0x85, 0xc0,       // test eax,eax
        0x74, 0x04,       // jz else
        0xff, 0xc0,       // inc eax
        0xeb, 0x02,       // jmp join
        0xff, 0xc8,       // else: dec eax
        0xc3              // join: ret
    }, UINT64_C(0x2000));
    expect(has_region(recover(if_else), airece::ControlRegionKind::if_else),
           "if/else with a postdominating join is recognized");

    GraphFixture terminal_if({
        0x85, 0xc0,       // test eax,eax
        0x74, 0x01,       // jz second return
        0xc3,
        0xc3
    }, UINT64_C(0x2800));
    expect(has_region(recover(terminal_if), airece::ControlRegionKind::terminal_if),
           "terminal conditional is recognized without inventing a join");

    GraphFixture early_return({
        0x85, 0xc0,       // test eax,eax
        0x74, 0x02,       // jz continue
        0xc3,             // return
        0x90,             // padding
        0xff, 0xc0,       // continue: inc eax
        0xeb, 0x00,       // jump to tail
        0xff, 0xc8,       // tail: dec eax
        0xc3
    }, UINT64_C(0x3000));
    expect(has_region(recover(early_return), airece::ControlRegionKind::early_return),
           "one terminal branch is recognized as an early return");
}

void test_loops() {
    GraphFixture while_loop({
        0x85, 0xc0,       // header: test eax,eax
        0x74, 0x04,       // jz exit
        0xff, 0xc8,       // dec eax
        0xeb, 0xf8,       // back to header
        0xc3
    }, UINT64_C(0x4000));
    const airece::ControlView while_view = recover(while_loop);
    expect(has_region(while_view, airece::ControlRegionKind::while_loop),
           "natural header-tested loop is recognized as while");
    expect(std::any_of(while_view.transfers.begin(), while_view.transfers.end(),
               [](const airece::ControlTransfer& transfer) {
                   return transfer.kind == airece::ControlTransferKind::continue_loop;
               }) &&
               std::any_of(while_view.transfers.begin(), while_view.transfers.end(),
               [](const airece::ControlTransfer& transfer) {
                   return transfer.kind == airece::ControlTransferKind::break_loop;
               }),
           "natural-loop transfers identify continue and break edges");
    if (const airece::ControlRegion* region = find_region(
            while_view, airece::ControlRegionKind::while_loop)) {
        airece::CompactFunctionView semantic = pseudo_fixture(while_view);
        semantic.statements.push_back({
            .kind = airece::SemanticStatementKind::branch,
            .text = "if counter != 0 -> body else exit",
            .node = region->condition_node});
        for (const xair_cfg_node_id node : region->nodes) {
            if (node != region->header) {
                semantic.statements.push_back({
                    .kind = airece::SemanticStatementKind::effect,
                    .text = "counter = counter - 1",
                    .node = node});
            }
        }
        const std::string pseudo = airece::render_pseudo(semantic).text;
        expect(pseudo.find("while (counter != 0)") != std::string::npos,
               "two-node header-tested loop passes the structured certificate");
    }

    GraphFixture do_while({
        0xff, 0xc8,       // body: dec eax
        0xeb, 0x00,       // jump to latch
        0xff, 0xc1,       // latch: inc ecx
        0x85, 0xc0,       // test eax,eax
        0x75, 0xf6,       // back to body
        0xc3
    }, UINT64_C(0x5000));
    const airece::ControlView do_view = recover(do_while);
    expect(has_region(do_view, airece::ControlRegionKind::do_while_loop),
           "latch-tested natural loop is recognized as do/while");
    if (const airece::ControlRegion* region = find_region(
            do_view, airece::ControlRegionKind::do_while_loop)) {
        airece::CompactFunctionView semantic = pseudo_fixture(do_view);
        semantic.statements.push_back({
            .kind = airece::SemanticStatementKind::effect,
            .text = "counter = counter - 1",
            .node = region->header});
        semantic.statements.push_back({
            .kind = airece::SemanticStatementKind::branch,
            .text = "if counter != 0 -> body else exit",
            .node = region->condition_node});
        const std::string pseudo = airece::render_pseudo(semantic).text;
        expect(pseudo.find("do {") != std::string::npos &&
                   pseudo.find("} while (counter != 0);") != std::string::npos,
               "two-node latch-tested loop passes the structured certificate");
    }
}

void test_switch_and_irreducible_fallback() {
    std::vector<std::uint8_t> switch_bytes(0x140, 0xcc);
    switch_bytes[0] = 0xff;
    switch_bytes[1] = 0x24;
    switch_bytes[2] = 0xc5;
    switch_bytes[3] = 0x40;
    switch_bytes[4] = 0x60;
    switch_bytes[5] = 0x00;
    switch_bytes[6] = 0x00;
    put_le64(switch_bytes, 0x40, UINT64_C(0x6100));
    put_le64(switch_bytes, 0x48, UINT64_C(0x6110));
    put_le64(switch_bytes, 0x50, UINT64_C(0x6120));
    put_le64(switch_bytes, 0x58, 0);
    switch_bytes[0x100] = 0xc3;
    switch_bytes[0x110] = 0xc3;
    switch_bytes[0x120] = 0xc3;
    GraphFixture switch_graph(std::move(switch_bytes), UINT64_C(0x6000));
    expect(has_region(recover(switch_graph), airece::ControlRegionKind::switch_region),
           "bounded indirect target set is recognized as a simple switch");

    std::vector<std::uint8_t> bounded_switch(0x60, 0xcc);
    bounded_switch[0x00] = 0x83; bounded_switch[0x01] = 0xf8;
    bounded_switch[0x02] = 0x01; bounded_switch[0x03] = 0x77;
    bounded_switch[0x04] = 0x13; bounded_switch[0x05] = 0xff;
    bounded_switch[0x06] = 0x24; bounded_switch[0x07] = 0xc5;
    const std::uint32_t table = 0xd020;
    for (std::size_t byte = 0; byte < 4; ++byte) {
        bounded_switch[0x08 + byte] =
            static_cast<std::uint8_t>(table >> (byte * 8U));
    }
    bounded_switch[0x18] = 0xc3;
    put_le64(bounded_switch, 0x20, UINT64_C(0xd040));
    put_le64(bounded_switch, 0x28, UINT64_C(0xd044));
    put_le64(bounded_switch, 0x30, UINT64_C(0xd048));
    bounded_switch[0x40] = 0xc3;
    bounded_switch[0x44] = 0xc3;
    bounded_switch[0x48] = 0xc3;
    GraphFixture exact_switch(std::move(bounded_switch), UINT64_C(0xd000));
    const airece::ControlView switch_view = recover(exact_switch);
    const airece::ControlRegion* switch_region = find_region(
        switch_view, airece::ControlRegionKind::switch_region);
    expect(switch_region != nullptr && switch_region->switch_mapping_complete &&
               switch_region->switch_cases.size() == 2 &&
               switch_region->switch_cases[0].value == 0 &&
               switch_region->switch_cases[1].value == 1 &&
               switch_region->switch_default_raw == UINT64_C(0xd018),
           "bounded switch preserves exact values, targets, and default");
    if (switch_region != nullptr && switch_region->switch_mapping_complete) {
        airece::CompactFunctionView semantic = pseudo_fixture(switch_view);
        semantic.statements.push_back({
            .kind = airece::SemanticStatementKind::indirect_target,
            .text = "switch selector targets: 0xd040, 0xd044",
            .node = switch_region->header});
        for (const airece::ControlSwitchCase& item : switch_region->switch_cases) {
            semantic.statements.push_back({
                .kind = airece::SemanticStatementKind::return_value,
                .text = "return",
                .node = item.target});
        }
        semantic.statements.push_back({
            .kind = airece::SemanticStatementKind::return_value,
            .text = "return",
            .node = switch_region->switch_default});
        const std::string pseudo = airece::render_pseudo(semantic).text;
        expect(pseudo.find("switch (selector)") != std::string::npos &&
                   pseudo.find("case 0:") != std::string::npos &&
                   pseudo.find("case 1:") != std::string::npos &&
                   pseudo.find("case 532") == std::string::npos,
               "structured switch uses recovered index values, never destinations");
    }

    GraphFixture irreducible({
        0x85, 0xc0,       // entry condition
        0x74, 0x04,       // enter right arm
        0xeb, 0x04,       // left arm -> latch
        0xcc, 0xcc,
        0xeb, 0x00,       // right arm -> latch
        0x85, 0xc9,       // latch condition
        0x74, 0xf6,       // back to left arm
        0xeb, 0xf8        // back to right arm
    }, UINT64_C(0x7000));
    const airece::ControlView irreducible_view = recover(irreducible);
    expect(irreducible_view.irreducible && irreducible_view.fallback &&
               has_region(irreducible_view, airece::ControlRegionKind::irreducible),
           "irreducible graph terminates in explicit fallback mode");
    expect(std::all_of(
               irreducible_view.transfers.begin(), irreducible_view.transfers.end(),
               [](const airece::ControlTransfer& transfer) {
                   return transfer.kind ==
                              airece::ControlTransferKind::return_from_function ||
                       transfer.explicit_goto;
               }),
           "irreducible transfers remain explicit gotos");
}

} // namespace

int main() {
    test_linear_and_conditionals();
    test_loops();
    test_switch_and_irreducible_fallback();
    return failures == 0 ? 0 : 1;
}
