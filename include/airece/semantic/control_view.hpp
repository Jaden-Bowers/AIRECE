#pragma once

#include <airece/semantic/expression_view.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

extern "C" {
#include <xair_cfg/xair_cfg.h>
}

namespace airece {

enum class ControlRegionKind {
    sequence,
    terminal_if,
    if_else,
    early_return,
    while_loop,
    do_while_loop,
    switch_region,
    irreducible,
    block
};

enum class ControlTransferKind {
    fallthrough,
    branch_true,
    branch_false,
    switch_case,
    call_target,
    goto_label,
    break_loop,
    continue_loop,
    return_from_function,
    trap,
    fault,
    unresolved
};

struct ControlEvidence {
    std::uint64_t begin{};
    std::uint64_t end{};
    std::vector<xair_cfg_node_id> nodes;
    std::vector<xair_cfg_edge_id> edges;
    std::vector<xair_op_id> operations;
    xair_confidence confidence{XAIR_CONFIDENCE_UNKNOWN};
    bool synthetic{true};
};

struct ControlRegion {
    std::string stable_id;
    ControlRegionKind kind{ControlRegionKind::block};
    xair_cfg_node_id header{XAIR_CFG_INVALID_ID};
    xair_cfg_node_id join{XAIR_CFG_INVALID_ID};
    xair_value_id condition{XAIR_INVALID_ID};
    std::vector<xair_cfg_node_id> nodes;
    ControlEvidence evidence;
};

struct ControlTransfer {
    xair_cfg_edge_id edge{XAIR_CFG_INVALID_ID};
    ControlTransferKind kind{ControlTransferKind::unresolved};
    xair_cfg_node_id source{XAIR_CFG_INVALID_ID};
    xair_cfg_node_id target{XAIR_CFG_INVALID_ID};
    xair_value_id condition{XAIR_INVALID_ID};
    std::uint64_t raw_target{};
    bool explicit_goto{};
    ControlEvidence evidence;
};

struct ControlOptions {
    std::size_t max_regions{256};
    std::size_t max_transfers{1'024};
    std::size_t max_expression_depth{6};

    [[nodiscard]] bool operator==(const ControlOptions&) const = default;
};

struct ControlView {
    xair_status status{XAIR_OK};
    xair_function_id function{XAIR_CFG_INVALID_ID};
    xair_cfg_node_id entry{XAIR_CFG_INVALID_ID};
    std::vector<xair_cfg_node_id> block_order;
    std::vector<ControlRegion> regions;
    std::vector<ControlTransfer> transfers;
    bool irreducible{};
    bool fallback{};
    bool truncated{};
    std::size_t omitted_regions{};
    std::size_t omitted_transfers{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == XAIR_OK;
    }
};

class ControlRecovery final {
public:
    ControlRecovery(const xair_cfg& cfg, const xair_module& module);
    ~ControlRecovery();
    ControlRecovery(const ControlRecovery&) = delete;
    ControlRecovery& operator=(const ControlRecovery&) = delete;
    ControlRecovery(ControlRecovery&&) noexcept;
    ControlRecovery& operator=(ControlRecovery&&) noexcept;

    [[nodiscard]] ControlView build(
        xair_function_id function,
        const ControlOptions& options = {}) const;
    [[nodiscard]] std::size_t cache_size() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] const char* control_region_kind_name(ControlRegionKind kind) noexcept;
[[nodiscard]] const char* control_transfer_kind_name(ControlTransferKind kind) noexcept;

} // namespace airece
