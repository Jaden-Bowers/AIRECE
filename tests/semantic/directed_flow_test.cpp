#include <airece/semantic/directed_flow.hpp>

#include <cassert>
#include <string>

int main() {
    airece::FlowOptions defaults;
    assert(defaults.function_depth == 3);
    assert(defaults.mode == airece::FlowMode::taint);

    airece::FlowPointSelector selector;
    std::string diagnostic;
    assert(airece::parse_flow_point(
        "input=buffer(rcx,64)@0x140001000:before", false, selector, diagnostic));
    assert(selector.name == "input");
    assert(selector.kind == airece::FlowPointKind::buffer);
    assert(selector.register_name == "rcx");
    assert(selector.length == 64);
    assert(selector.address == UINT64_C(0x140001000));
    assert(selector.when == airece::FlowWhen::before);

    assert(airece::parse_flow_point(
        "sink=funcarg(2)@0x140002000", true, selector, diagnostic));
    assert(selector.kind == airece::FlowPointKind::function_argument);
    assert(selector.index == 2);

    assert(airece::parse_flow_point(
        "arg=callarg(0)@0x140003000", false, selector, diagnostic));
    assert(selector.kind == airece::FlowPointKind::call_argument);
    assert(airece::parse_flow_point(
        "result=callresult@0x140003000", true, selector, diagnostic));
    assert(selector.kind == airece::FlowPointKind::call_result);
    assert(selector.when == airece::FlowWhen::after);

    assert(airece::parse_flow_point(
        "bytes=memory(0x180000000,32)@0x140004000", false, selector, diagnostic));
    assert(selector.kind == airece::FlowPointKind::memory);
    assert(selector.memory_address == UINT64_C(0x180000000));
    assert(selector.length == 32);

    assert(airece::parse_flow_point("state=reach@0x140005000", true,
        selector, diagnostic));
    assert(selector.kind == airece::FlowPointKind::reach);
    assert(!airece::parse_flow_point("reach@0x140005000", false,
        selector, diagnostic));
    assert(!diagnostic.empty());
    assert(!airece::parse_flow_point("buffer(rcx,0)@0x140001000", false,
        selector, diagnostic));
    return 0;
}
