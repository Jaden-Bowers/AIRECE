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
    }
    return emitted;
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

void render_pseudo_target(
    BudgetWriter& writer,
    const CompactFunctionView& view,
    const ControlTransfer* transfer,
    const xair_cfg_node_id join,
    const std::unordered_set<xair_cfg_node_id>& local_nodes,
    const std::unordered_set<xair_cfg_node_id>& label_targets,
    std::unordered_set<xair_cfg_node_id>& defined_labels,
    std::unordered_set<xair_cfg_node_id>& consumed,
    const std::string& indent) {
    if (transfer == nullptr) {
        writer.line(indent + "/* unresolved control target */");
        return;
    }
    if (transfer->kind == ControlTransferKind::break_loop) {
        writer.line(indent + "break;");
        return;
    }
    if (transfer->kind == ControlTransferKind::continue_loop) {
        writer.line(indent + "continue;");
        return;
    }
    if (transfer->target == join) {
        writer.line(indent + "/* join n" + std::to_string(join) + " */");
        return;
    }
    if (!local_nodes.contains(transfer->target)) {
        writer.line(indent + "/* control leaves function at 0x" +
            hex_value(transfer->raw_target) + " */");
        return;
    }
    if (label_targets.contains(transfer->target) &&
        defined_labels.insert(transfer->target).second) {
        writer.line("label_n" + std::to_string(transfer->target) + ":");
    }
    if (!render_pseudo_node(writer, view, transfer->target, indent)) {
        writer.line(indent + "/* block n" + std::to_string(transfer->target) + " */");
    }
    consumed.insert(transfer->target);
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
    std::unordered_set<xair_cfg_node_id> label_targets;
    std::unordered_set<xair_cfg_node_id> defined_labels;
    for (const ControlTransfer& transfer : view.control.transfers) {
        if (transfer.explicit_goto && local_nodes.contains(transfer.target)) {
            label_targets.insert(transfer.target);
        }
    }
    std::unordered_map<xair_cfg_node_id, const ControlRegion*> structured;
    for (const ControlRegion& region : view.control.regions) {
        if (region.kind != ControlRegionKind::sequence &&
            region.kind != ControlRegionKind::block &&
            region.kind != ControlRegionKind::irreducible) {
            structured.emplace(region.header, &region);
        }
    }
    for (const xair_cfg_node_id node : view.control.block_order) {
        if (consumed.contains(node)) continue;
        const auto region_entry = structured.find(node);
        if (region_entry != structured.end()) {
            const ControlRegion& region = *region_entry->second;
            const std::string condition = region_condition(view, region);
            if (label_targets.contains(node) && defined_labels.insert(node).second) {
                writer.line("label_n" + std::to_string(node) + ":");
            }
            if (region.kind == ControlRegionKind::if_else ||
                region.kind == ControlRegionKind::terminal_if ||
                region.kind == ControlRegionKind::early_return) {
                (void)render_pseudo_node(writer, view, node, "    ");
                const ControlTransfer* true_transfer = transfer_of_kind(
                    view, node, ControlTransferKind::branch_true);
                const ControlTransfer* false_transfer = transfer_of_kind(
                    view, node, ControlTransferKind::branch_false);
                writer.line("    if (" + condition + ") {");
                render_pseudo_target(writer, view, true_transfer, region.join,
                                     local_nodes, label_targets, defined_labels,
                                     consumed, "        ");
                writer.line("    }");
                if (false_transfer != nullptr) {
                    writer.line("    else {");
                    render_pseudo_target(writer, view, false_transfer, region.join,
                                         local_nodes, label_targets, defined_labels,
                                         consumed, "        ");
                    writer.line("    }");
                }
                consumed.insert(node);
                continue;
            }
            if (region.kind == ControlRegionKind::while_loop ||
                region.kind == ControlRegionKind::do_while_loop) {
                if (region.kind == ControlRegionKind::while_loop) {
                    writer.line("    while (" + condition + ") {");
                } else {
                    writer.line("    do {");
                }
                for (const xair_cfg_node_id member : region.nodes) {
                    if (label_targets.contains(member) &&
                        defined_labels.insert(member).second) {
                        writer.line("label_n" + std::to_string(member) + ":");
                    }
                    (void)render_pseudo_node(writer, view, member, "        ");
                    for (const ControlTransfer& transfer : view.control.transfers) {
                        if (transfer.source != member) continue;
                        if (transfer.kind == ControlTransferKind::break_loop) {
                            writer.line("        break;");
                        } else if (transfer.kind == ControlTransferKind::continue_loop) {
                            writer.line("        continue;");
                        }
                    }
                    consumed.insert(member);
                }
                writer.line(region.kind == ControlRegionKind::while_loop
                    ? "    }" : "    } while (" + condition + ");");
                continue;
            }
            if (region.kind == ControlRegionKind::switch_region) {
                (void)render_pseudo_node(writer, view, node, "    ");
                writer.line("    switch (" + condition + ") {");
                for (const ControlTransfer& transfer : view.control.transfers) {
                    if (transfer.source != node ||
                        transfer.kind == ControlTransferKind::call_target) continue;
                    writer.line("    case 0x" + hex_value(transfer.raw_target) + ":");
                    render_pseudo_target(writer, view, &transfer,
                                         XAIR_CFG_INVALID_ID, local_nodes,
                                         label_targets, defined_labels, consumed,
                                         "        ");
                    writer.line("        break;");
                }
                writer.line("    }");
                consumed.insert(node);
                continue;
            }
        }
        bool needs_label = view.control.irreducible;
        for (const ControlTransfer& transfer : view.control.transfers) {
            needs_label = needs_label ||
                (transfer.target == node && transfer.explicit_goto);
        }
        if (needs_label && defined_labels.insert(node).second) {
            writer.line("label_n" + std::to_string(node) + ":");
        }
        bool emitted = render_pseudo_node(writer, view, node, "    ");
        for (const ControlTransfer& transfer : view.control.transfers) {
            if (transfer.source != node || !transfer.explicit_goto) continue;
            if (local_nodes.contains(transfer.target)) {
                writer.line("    goto label_n" + std::to_string(transfer.target) + ";");
            } else {
                writer.line("    /* unresolved transfer outside function */");
            }
            emitted = true;
        }
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
