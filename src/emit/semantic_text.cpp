#include <airece/emit/semantic_text.hpp>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace airece {
namespace {

const char* confidence_name(const xair_confidence confidence) {
    switch (confidence) {
    case XAIR_CONFIDENCE_LOW: return "low";
    case XAIR_CONFIDENCE_MEDIUM: return "medium";
    case XAIR_CONFIDENCE_HIGH: return "high";
    case XAIR_CONFIDENCE_EXACT: return "exact";
    case XAIR_CONFIDENCE_UNKNOWN:
    default: return "unknown";
    }
}

std::string hex_value(const std::uint64_t value) {
    std::ostringstream stream;
    stream << std::hex << value;
    return stream.str();
}

std::string function_signature(const CompactFunctionView& view) {
    std::string result = "fn 0x" + hex_value(view.function.entry) + ' ' +
        view.function.name + '(';
    for (std::size_t index = 0; index < view.parameters.size(); ++index) {
        if (index != 0) result += ", ";
        result += view.parameters[index].name.text + ':' +
            view.parameters[index].type.text;
    }
    result += ") -> ";
    result += view.returns.empty() ? "void" : view.returns.front().type.text;
    return result;
}

class BudgetWriter {
public:
    explicit BudgetWriter(const std::size_t limit) : limit_(limit) {}

    void line(const std::string_view value) {
        const std::size_t required = value.size() + 1;
        if (limit_ != 0 && text_.size() + required > limit_) {
            ++omitted_;
            return;
        }
        text_.append(value);
        text_.push_back('\n');
    }

    [[nodiscard]] const std::string& text() const noexcept { return text_; }
    [[nodiscard]] std::size_t omitted() const noexcept { return omitted_; }

private:
    std::size_t limit_{};
    std::string text_;
    std::size_t omitted_{};
};

std::string statement_line(const SemanticStatement& statement) {
    std::string result = "  " + statement.stable_id + ": " + statement.text;
    if (!statement.evidence_id.empty()) result += " [" + statement.evidence_id + ']';
    else if (statement.address != 0) result += " [0x" + hex_value(statement.address) + ']';
    return result;
}

void render_statement_section(
    BudgetWriter& writer,
    const CompactFunctionView& view,
    const std::string_view title,
    const std::initializer_list<SemanticStatementKind> kinds) {
    bool heading = false;
    for (const SemanticStatement& statement : view.statements) {
        if (std::find(kinds.begin(), kinds.end(), statement.kind) == kinds.end()) {
            continue;
        }
        if (!heading) {
            writer.line(std::string(title) + ':');
            heading = true;
        }
        writer.line(statement_line(statement));
    }
}

std::string omitted_footer(
    const CompactFunctionView& view,
    const std::size_t render_omitted,
    const std::size_t call_offset) {
    OmittedSemanticItems omitted = view.omitted;
    omitted.statements += render_omitted;
    if (!omitted.any()) return {};
    std::string result = "omitted:\n";
    if (omitted.calls != 0) {
        result += "  calls: " + std::to_string(omitted.calls) + '\n';
    }
    if (omitted.branches != 0) {
        result += "  branches: " + std::to_string(omitted.branches) + '\n';
    }
    if (omitted.statements != 0) {
        result += "  statements: " + std::to_string(omitted.statements) + '\n';
    }
    if (omitted.evidence != 0) {
        result += "  evidence: " + std::to_string(omitted.evidence) + '\n';
    }
    if (omitted.regions != 0) {
        result += "  regions: " + std::to_string(omitted.regions) + '\n';
    }
    if (omitted.transfers != 0) {
        result += "  transfers: " + std::to_string(omitted.transfers) + '\n';
    }
    const std::size_t visible_calls = view.total_calls > omitted.calls
        ? view.total_calls - omitted.calls : 0;
    result += "continue-with:\n  airece fn <binary> 0x" +
        hex_value(view.function.entry) + " --view compact --calls --offset " +
        std::to_string(call_offset + visible_calls) + '\n';
    return result;
}

std::string region_condition(
    const CompactFunctionView& view,
    const ControlRegion& region) {
    for (const SemanticStatement& statement : view.statements) {
        if (statement.node != region.header ||
            statement.kind != SemanticStatementKind::branch ||
            !statement.text.starts_with("if ")) {
            continue;
        }
        const std::size_t end = statement.text.find(" -> ", 3);
        if (end != std::string::npos) return statement.text.substr(3, end - 3);
    }
    return region.condition == XAIR_INVALID_ID
        ? "unknown_condition" : "v" + std::to_string(region.condition);
}

bool render_pseudo_node(
    BudgetWriter& writer,
    const CompactFunctionView& view,
    const xair_cfg_node_id node,
    const std::string& indent) {
    bool emitted = false;
    for (const SemanticStatement& statement : view.statements) {
        if (statement.node != node || statement.kind == SemanticStatementKind::branch) {
            continue;
        }
        writer.line(indent + statement.text + ";  // " + statement.stable_id +
            (statement.evidence_id.empty()
                ? " @0x" + hex_value(statement.address)
                : " " + statement.evidence_id));
        emitted = true;
        if (statement.kind == SemanticStatementKind::return_value ||
            statement.kind == SemanticStatementKind::trap ||
            statement.kind == SemanticStatementKind::fault ||
            (statement.kind == SemanticStatementKind::call && statement.no_return)) {
            break;
        }
    }
    return emitted;
}

std::string qualified_label(
    const CompactFunctionView& view,
    const xair_cfg_node_id node) {
    return "F" + hex_value(view.function.entry) + "_L" + std::to_string(node);
}

bool node_is_terminal(
    const CompactFunctionView& view,
    const xair_cfg_node_id node) {
    return std::any_of(view.statements.begin(), view.statements.end(),
        [node](const SemanticStatement& statement) {
            return statement.node == node &&
                (statement.kind == SemanticStatementKind::return_value ||
                 statement.kind == SemanticStatementKind::trap ||
                 statement.kind == SemanticStatementKind::fault ||
                 (statement.kind == SemanticStatementKind::call &&
                  statement.no_return));
        });
}

const ControlTransfer* transfer_of_kind(
    const CompactFunctionView& view,
    const xair_cfg_node_id source,
    const ControlTransferKind kind) {
    const auto found = std::find_if(
        view.control.transfers.begin(), view.control.transfers.end(),
        [&](const ControlTransfer& transfer) {
            return transfer.source == source && transfer.kind == kind;
        });
    return found == view.control.transfers.end() ? nullptr : &*found;
}

bool direct_arm_to_join(
    const CompactFunctionView& view,
    const xair_cfg_node_id arm,
    const xair_cfg_node_id join) {
    if (node_is_terminal(view, arm)) return false;
    std::size_t outgoing = 0;
    for (const ControlTransfer& transfer : view.control.transfers) {
        if (transfer.source != arm ||
            transfer.kind == ControlTransferKind::call_target) {
            continue;
        }
        ++outgoing;
        if (transfer.target != join) return false;
    }
    return outgoing == 1;
}

bool uniquely_entered_from(
    const CompactFunctionView& view,
    const xair_cfg_node_id node,
    const xair_cfg_node_id source) {
    std::size_t incoming = 0;
    for (const ControlTransfer& transfer : view.control.transfers) {
        if (transfer.target != node ||
            transfer.kind == ControlTransferKind::call_target) {
            continue;
        }
        ++incoming;
        if (transfer.source != source) return false;
    }
    return incoming == 1;
}

bool certified_if_region(
    const CompactFunctionView& view,
    const ControlRegion& region,
    const ControlTransfer*& true_transfer,
    const ControlTransfer*& false_transfer) {
    if (region.kind != ControlRegionKind::if_else &&
        region.kind != ControlRegionKind::terminal_if) {
        return false;
    }
    true_transfer = transfer_of_kind(
        view, region.header, ControlTransferKind::branch_true);
    false_transfer = transfer_of_kind(
        view, region.header, ControlTransferKind::branch_false);
    if (true_transfer == nullptr || false_transfer == nullptr ||
        true_transfer->target == false_transfer->target ||
        !uniquely_entered_from(view, true_transfer->target, region.header) ||
        !uniquely_entered_from(view, false_transfer->target, region.header)) {
        return false;
    }
    if (region.kind == ControlRegionKind::terminal_if) {
        return node_is_terminal(view, true_transfer->target) &&
            node_is_terminal(view, false_transfer->target);
    }
    return region.join != XAIR_CFG_INVALID_ID &&
        direct_arm_to_join(view, true_transfer->target, region.join) &&
        direct_arm_to_join(view, false_transfer->target, region.join);
}

bool render_fallback_transfers(
    BudgetWriter& writer,
    const CompactFunctionView& view,
    const xair_cfg_node_id node,
    const std::unordered_set<xair_cfg_node_id>& local_nodes) {
    if (node_is_terminal(view, node)) return false;
    const ControlTransfer* true_transfer = transfer_of_kind(
        view, node, ControlTransferKind::branch_true);
    const ControlTransfer* false_transfer = transfer_of_kind(
        view, node, ControlTransferKind::branch_false);
    if (true_transfer != nullptr && false_transfer != nullptr &&
        local_nodes.contains(true_transfer->target) &&
        local_nodes.contains(false_transfer->target)) {
        ControlRegion condition_region;
        condition_region.header = node;
        condition_region.condition = true_transfer->condition;
        writer.line("    if (" + region_condition(view, condition_region) + ") goto " +
            qualified_label(view, true_transfer->target) + "; else goto " +
            qualified_label(view, false_transfer->target) + ";");
        return true;
    }

    std::vector<xair_cfg_node_id> indirect_targets;
    bool emitted = false;
    for (const ControlTransfer& transfer : view.control.transfers) {
        if (transfer.source != node ||
            transfer.kind == ControlTransferKind::call_target ||
            transfer.kind == ControlTransferKind::return_from_function) {
            continue;
        }
        if (transfer.kind == ControlTransferKind::switch_case) {
            if (local_nodes.contains(transfer.target)) {
                indirect_targets.push_back(transfer.target);
            }
            continue;
        }
        if (local_nodes.contains(transfer.target)) {
            writer.line("    goto " + qualified_label(view, transfer.target) + ";");
            emitted = true;
        } else {
            writer.line("    /* control leaves function at 0x" +
                hex_value(transfer.raw_target) + " */");
            emitted = true;
        }
    }
    if (!indirect_targets.empty()) {
        std::sort(indirect_targets.begin(), indirect_targets.end());
        indirect_targets.erase(
            std::unique(indirect_targets.begin(), indirect_targets.end()),
            indirect_targets.end());
        std::string line = "    goto_one_of(";
        for (std::size_t index = 0; index < indirect_targets.size(); ++index) {
            if (index != 0) line += ", ";
            line += qualified_label(view, indirect_targets[index]);
        }
        line += "); /* switch case values unresolved */";
        writer.line(line);
        emitted = true;
    }
    return emitted;
}

} // namespace

RenderedSemanticText render_compact(
    const CompactFunctionView& view,
    const CompactOptions& options) {
    RenderedSemanticText result;
    if (!view) return result;
    BudgetWriter writer(options.max_bytes);
    writer.line(function_signature(view));
    writer.line("range: 0x" + hex_value(view.function.range_start) + "-0x" +
        hex_value(view.function.range_end));
    writer.line("coverage: exact=" + std::to_string(view.coverage.exact_percent) +
        "% partial-blocks=" + std::to_string(view.coverage.partial_blocks) +
        " opaque-blocks=" + std::to_string(view.coverage.opaque_blocks) +
        " exact-instructions=" + std::to_string(view.coverage.exact_instructions) +
        "/" + std::to_string(view.coverage.total_instructions) +
        " unresolved=" + std::to_string(view.coverage.unresolved_operations));
    writer.line(std::string("completeness: ") + (view.complete ? "complete" : "partial"));

    render_statement_section(writer, view, "calls", {SemanticStatementKind::call});

    writer.line("control:");
    for (const ControlRegion& region : view.control.regions) {
        if (region.kind == ControlRegionKind::block) continue;
        std::string line = "  " + region.stable_id + ": " +
            control_region_kind_name(region.kind) + " header=n" +
            std::to_string(region.header);
        if (region.condition != XAIR_INVALID_ID) {
            line += " condition=v" + std::to_string(region.condition);
        }
        if (region.join != XAIR_CFG_INVALID_ID) {
            line += " join=n" + std::to_string(region.join);
        }
        line += " [0x" + hex_value(region.evidence.begin) + ']';
        writer.line(line);
    }
    for (const ControlTransfer& transfer : view.control.transfers) {
        std::string line = "  edge" + std::to_string(transfer.edge) + ": n" +
            std::to_string(transfer.source) + " -" +
            control_transfer_kind_name(transfer.kind) + "-> ";
        line += transfer.target == XAIR_CFG_INVALID_ID
            ? "external" : "n" + std::to_string(transfer.target);
        if (transfer.condition != XAIR_INVALID_ID) {
            line += " condition=v" + std::to_string(transfer.condition);
        }
        if (transfer.explicit_goto) line += " explicit";
        line += " [0x" + hex_value(transfer.evidence.begin) + ']';
        writer.line(line);
    }

    render_statement_section(writer, view, "branches", {
        SemanticStatementKind::branch, SemanticStatementKind::return_value,
        SemanticStatementKind::trap, SemanticStatementKind::fault});
    render_statement_section(writer, view, "memory", {
        SemanticStatementKind::memory_read, SemanticStatementKind::memory_write,
        SemanticStatementKind::effect});
    render_statement_section(writer, view, "references", {
        SemanticStatementKind::global_reference,
        SemanticStatementKind::string_reference,
        SemanticStatementKind::constant,
        SemanticStatementKind::import_reference,
        SemanticStatementKind::indirect_target});
    render_statement_section(writer, view, "unresolved", {
        SemanticStatementKind::unresolved});
    writer.line("taint: " + view.taint_status);

    if (!view.evidence.empty()) writer.line("evidence:");
    for (const SemanticEvidence& evidence : view.evidence) {
        std::string line = "  " + evidence.stable_id + ": 0x" +
            hex_value(evidence.begin);
        if (evidence.end > evidence.begin) line += "-0x" + hex_value(evidence.end);
        if (!evidence.operations.empty()) {
            line += " ops=";
            for (std::size_t index = 0; index < evidence.operations.size(); ++index) {
                if (index != 0) line += ',';
                line += std::to_string(evidence.operations[index]);
            }
        }
        line += " confidence=";
        line += confidence_name(evidence.confidence);
        if (evidence.synthetic) line += " synthetic";
        writer.line(line);
    }

    result.text = writer.text();
    result.omitted_lines = writer.omitted();
    const std::string footer = omitted_footer(
        view, writer.omitted(), options.call_offset);
    result.text += footer;
    result.truncated = view.truncated || writer.omitted() != 0 || !footer.empty();
    return result;
}

RenderedSemanticText render_pseudo(
    const CompactFunctionView& view,
    const CompactOptions& options) {
    RenderedSemanticText result;
    if (!view) return result;
    BudgetWriter writer(options.max_bytes);
    writer.line(function_signature(view));
    writer.line("{");
    std::unordered_set<xair_cfg_node_id> local_nodes(
        view.control.block_order.begin(), view.control.block_order.end());
    std::unordered_set<xair_cfg_node_id> consumed;
    std::unordered_map<xair_cfg_node_id, const ControlRegion*> structured;
    for (const ControlRegion& region : view.control.regions) {
        const ControlTransfer* true_transfer = nullptr;
        const ControlTransfer* false_transfer = nullptr;
        if (certified_if_region(view, region, true_transfer, false_transfer)) {
            structured.emplace(region.header, &region);
        }
    }
    for (const xair_cfg_node_id node : view.control.block_order) {
        if (consumed.contains(node)) continue;
        writer.line(qualified_label(view, node) + ":");
        const auto region_entry = structured.find(node);
        if (region_entry != structured.end()) {
            const ControlRegion& region = *region_entry->second;
            const std::string condition = region_condition(view, region);
            const ControlTransfer* true_transfer = transfer_of_kind(
                view, node, ControlTransferKind::branch_true);
            const ControlTransfer* false_transfer = transfer_of_kind(
                view, node, ControlTransferKind::branch_false);
            (void)render_pseudo_node(writer, view, node, "    ");
            writer.line("    if (" + condition + ") {");
            (void)render_pseudo_node(
                writer, view, true_transfer->target, "        ");
            writer.line("    } else {");
            (void)render_pseudo_node(
                writer, view, false_transfer->target, "        ");
            writer.line("    }");
            consumed.insert(node);
            consumed.insert(true_transfer->target);
            consumed.insert(false_transfer->target);
            continue;
        }
        bool emitted = render_pseudo_node(writer, view, node, "    ");
        emitted = render_fallback_transfers(writer, view, node, local_nodes) || emitted;
        if (!emitted) writer.line("    /* no recovered XAIR statements */");
        consumed.insert(node);
    }
    writer.line("}");
    result.text = writer.text();
    result.omitted_lines = writer.omitted();
    const std::string footer = omitted_footer(
        view, writer.omitted(), options.call_offset);
    result.text += footer;
    result.truncated = view.truncated || writer.omitted() != 0 || !footer.empty();
    return result;
}

} // namespace airece
