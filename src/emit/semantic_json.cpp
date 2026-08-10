#include <airece/emit/semantic_json.hpp>

#include <iomanip>
#include <sstream>

namespace airece {
namespace {

std::string escape(const std::string_view value) {
    std::ostringstream out;
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') <<
                static_cast<unsigned>(c) << std::dec;
            else out << static_cast<char>(c);
        }
    }
    return out.str();
}

void quoted(std::ostringstream& out, const std::string_view value) {
    out << '"' << escape(value) << '"';
}

} // namespace

std::string render_semantic_json(
    const CompactFunctionView& view,
    const EnrichmentResult* enrichment,
    const std::size_t max_bytes) {
    std::ostringstream out;
    out << "{\"schema\":\"" << semantic_json_schema << "\",\"function\":{";
    out << "\"id\":" << view.function.id << ",\"entry\":\"0x" << std::hex <<
        view.function.entry << "\",\"range_start\":\"0x" << view.function.range_start <<
        "\",\"range_end\":\"0x" << view.function.range_end << std::dec << "\",\"name\":";
    quoted(out, view.function.name);
    out << "},\"complete\":" << (view.complete ? "true" : "false") <<
        ",\"truncated\":" << (view.truncated ? "true" : "false") <<
        ",\"completeness_reason\":";
    quoted(out, view.complete ? "complete" : view.truncated
        ? "bounded-output" : view.function.session_complete
        ? "semantic-analysis-incomplete" : "analysis-session-partial");
    const auto variables = [&](const char* key,
                               const std::vector<PresentationVariable>& items) {
        out << ",\"" << key << "\":[";
        for (std::size_t index = 0; index < items.size(); ++index) {
            if (index != 0) out << ',';
            const PresentationVariable& variable = items[index];
            out << "{\"id\":"; quoted(out, variable.stable_id);
            out << ",\"name\":"; quoted(out, variable.name.text);
            out << ",\"kind\":"; quoted(out, variable_kind_name(variable.kind));
            out << ",\"type\":"; quoted(out, variable.type.text);
            out << ",\"type_kind\":";
            quoted(out, presentation_type_kind_name(variable.type.kind));
            out << ",\"roles\":" << variable.roles <<
                ",\"argument_index\":";
            if (variable.argument_index == static_cast<std::size_t>(-1)) out << "null";
            else out << variable.argument_index;
            out << ",\"values\":[";
            for (std::size_t value = 0; value < variable.values.size(); ++value) {
                if (value != 0) out << ',';
                out << variable.values[value];
            }
            out << "],\"address_values\":[";
            for (std::size_t value = 0; value < variable.address_values.size(); ++value) {
                if (value != 0) out << ',';
                out << variable.address_values[value];
            }
            out << "],\"data_values\":[";
            for (std::size_t value = 0; value < variable.data_values.size(); ++value) {
                if (value != 0) out << ',';
                out << variable.data_values[value];
            }
            out << "]}";
        }
        out << ']';
    };
    variables("parameters", view.parameters);
    variables("returns", view.returns);
    out << ",\"coverage\":{\"exact_blocks\":" << view.coverage.exact_blocks <<
        ",\"partial_blocks\":" << view.coverage.partial_blocks <<
        ",\"opaque_blocks\":" << view.coverage.opaque_blocks <<
        ",\"exact_instructions\":" << view.coverage.exact_instructions <<
        ",\"nonexact_instructions\":" << view.coverage.nonexact_instructions <<
        ",\"total_instructions\":" << view.coverage.total_instructions <<
        ",\"unresolved_operations\":" << view.coverage.unresolved_operations <<
        ",\"exact_percent\":" << view.coverage.exact_percent <<
        ",\"exact_instruction_percent\":" <<
            view.coverage.exact_instruction_percent <<
        ",\"nonexact_mnemonics\":{";
    for (std::size_t index = 0;
         index < view.coverage.nonexact_mnemonics.size(); ++index) {
        if (index != 0) out << ',';
        quoted(out, view.coverage.nonexact_mnemonics[index].first);
        out << ':' << view.coverage.nonexact_mnemonics[index].second;
    }
    out << "}}";
    out << ",\"omitted\":{\"calls\":" << view.omitted.calls <<
        ",\"branches\":" << view.omitted.branches <<
        ",\"statements\":" << view.omitted.statements <<
        ",\"evidence\":" << view.omitted.evidence <<
        ",\"regions\":" << view.omitted.regions <<
        ",\"transfers\":" << view.omitted.transfers << "}";
    out << ",\"totals\":{\"calls\":" << view.total_calls <<
        ",\"branches\":" << view.total_branches << "},\"statements\":[";
    for (std::size_t index = 0; index < view.statements.size(); ++index) {
        const SemanticStatement& statement = view.statements[index];
        if (index != 0) out << ',';
        out << "{\"id\":"; quoted(out, statement.stable_id);
        out << ",\"kind\":"; quoted(out, semantic_statement_kind_name(statement.kind));
        out << ",\"text\":"; quoted(out, statement.text);
        out << ",\"semantic_id\":"; quoted(out, statement.semantic_id);
        out << ",\"address\":\"0x" << std::hex << statement.address << std::dec <<
            "\",\"node\":" << statement.node << ",\"block\":" << statement.block <<
            ",\"evidence\":"; quoted(out, statement.evidence_id);
        out << ",\"confidence\":" << static_cast<unsigned>(statement.confidence) <<
            ",\"synthetic\":" << (statement.synthetic ? "true" : "false");
        out << ",\"api_model\":"; quoted(out, statement.api_model);
        out << ",\"api_arguments\":[";
        for (std::size_t argument = 0; argument < statement.api_arguments.size(); ++argument) {
            if (argument != 0) out << ',';
            quoted(out, statement.api_arguments[argument]);
        }
        out << "],\"return_role\":"; quoted(out, statement.return_role);
        out << ",\"constants\":"; quoted(out, statement.constant_summary);
        out << ",\"handle_relationship\":"; quoted(out, statement.handle_relationship);
        out << ",\"effects\":"; quoted(out, statement.effect_summary);
        out << ",\"taint_role\":"; quoted(out, statement.taint_role);
        out << ",\"no_return\":" << (statement.no_return ? "true" : "false");
        out << ",\"operations\":[";
        for (std::size_t op = 0; op < statement.operations.size(); ++op) {
            if (op != 0) out << ',';
            out << statement.operations[op];
        }
        out << "],\"values\":[";
        for (std::size_t value = 0; value < statement.values.size(); ++value) {
            if (value != 0) out << ',';
            out << statement.values[value];
        }
        out << "],\"dependencies\":[";
        for (std::size_t value = 0; value < statement.dependencies.size(); ++value) {
            if (value != 0) out << ',';
            out << statement.dependencies[value];
        }
        out << "]}";
    }
    out << "],\"evidence\":[";
    for (std::size_t index = 0; index < view.evidence.size(); ++index) {
        const SemanticEvidence& evidence = view.evidence[index];
        if (index != 0) out << ',';
        out << "{\"id\":"; quoted(out, evidence.stable_id);
        out << ",\"begin\":\"0x" << std::hex << evidence.begin <<
            "\",\"end\":\"0x" << evidence.end << std::dec <<
            "\",\"node\":" << evidence.node << ",\"block\":" << evidence.block <<
            ",\"confidence\":" << static_cast<unsigned>(evidence.confidence) <<
            ",\"synthetic\":" << (evidence.synthetic ? "true" : "false") <<
            ",\"operations\":[";
        for (std::size_t op = 0; op < evidence.operations.size(); ++op) {
            if (op != 0) out << ',';
            out << evidence.operations[op];
        }
        out << "],\"edges\":[";
        for (std::size_t edge = 0; edge < evidence.edges.size(); ++edge) {
            if (edge != 0) out << ',';
            out << evidence.edges[edge];
        }
        out << "]}";
    }
    out << "],\"control\":{\"entry\":" << view.control.entry <<
        ",\"irreducible\":" << (view.control.irreducible ? "true" : "false") <<
        ",\"fallback\":" << (view.control.fallback ? "true" : "false") <<
        ",\"regions\":[";
    for (std::size_t index = 0; index < view.control.regions.size(); ++index) {
        if (index != 0) out << ',';
        const ControlRegion& region = view.control.regions[index];
        out << "{\"id\":"; quoted(out, region.stable_id);
        out << ",\"kind\":"; quoted(out, control_region_kind_name(region.kind));
        out << ",\"header\":" << region.header << ",\"join\":" << region.join <<
            ",\"condition_node\":" << region.condition_node <<
            ",\"condition\":" << region.condition <<
            ",\"switch_mapping_complete\":" <<
                (region.switch_mapping_complete ? "true" : "false") <<
            ",\"switch_values_complete\":" <<
                (region.switch_values_complete ? "true" : "false") <<
            ",\"induction\":{\"recovered\":" <<
                (region.induction.recovered ? "true" : "false") <<
            ",\"variable\":" << region.induction.variable <<
            ",\"initial\":" << region.induction.initial <<
            ",\"bound\":" << region.induction.bound <<
            ",\"step\":" << region.induction.step <<
            ",\"comparison\":";
        quoted(out, region.induction.comparison);
        out << "},\"switch_cases\":[";
        for (std::size_t item = 0; item < region.switch_cases.size(); ++item) {
            if (item != 0) out << ',';
            out << "{\"value\":" << region.switch_cases[item].value <<
                ",\"target\":" << region.switch_cases[item].target <<
                ",\"raw_target\":\"0x" << std::hex <<
                region.switch_cases[item].raw_target << std::dec << "\"}";
        }
        out << "],\"switch_default\":" << region.switch_default <<
            ",\"switch_default_raw\":\"0x" << std::hex <<
                region.switch_default_raw << std::dec << "\",\"nodes\":[";
        for (std::size_t node = 0; node < region.nodes.size(); ++node) {
            if (node != 0) out << ',';
            out << region.nodes[node];
        }
        out << "]}";
    }
    out << "],\"transfers\":[";
    for (std::size_t index = 0; index < view.control.transfers.size(); ++index) {
        if (index != 0) out << ',';
        const ControlTransfer& transfer = view.control.transfers[index];
        out << "{\"edge\":" << transfer.edge << ",\"kind\":";
        quoted(out, control_transfer_kind_name(transfer.kind));
        out << ",\"source\":" << transfer.source << ",\"target\":" <<
            transfer.target << ",\"condition\":" << transfer.condition <<
            ",\"raw_target\":\"0x" << std::hex << transfer.raw_target << std::dec <<
            "\",\"conditional\":" << (transfer.conditional ? "true" : "false") <<
            ",\"condition_when_true\":" <<
                (transfer.condition_when_true ? "true" : "false") <<
            ",\"explicit_goto\":" <<
            (transfer.explicit_goto ? "true" : "false") << "}";
    }
    out << "]}";
    if (enrichment != nullptr) {
        out << ",\"enrichment\":{\"completion\":";
        quoted(out, enrichment_completion_name(enrichment->completion));
        out << ",\"queries\":" << enrichment->queries <<
            ",\"states\":" << enrichment->states <<
            ",\"solver_initialized\":" <<
            (enrichment->solver_initialized ? "true" : "false") <<
            ",\"symbolic\":[";
        for (std::size_t index = 0; index < enrichment->symbolic.size(); ++index) {
            if (index != 0) out << ',';
            const SymbolicFinding& finding = enrichment->symbolic[index];
            out << "{\"question\":"; quoted(out, finding.question);
            out << ",\"answer\":"; quoted(out, finding.answer);
            out << ",\"evidence\":"; quoted(out, finding.evidence_id);
            out << ",\"value\":" << finding.value << ",\"status\":" <<
                static_cast<unsigned>(finding.status) << ",\"inferred\":" <<
                (finding.inferred ? "true" : "false") << "}";
        }
        out << "],\"taint\":[";
        for (std::size_t index = 0; index < enrichment->taint.size(); ++index) {
            if (index != 0) out << ',';
            const TaintFinding& finding = enrichment->taint[index];
            out << "{\"kind\":"; quoted(out, finding.kind);
            out << ",\"source\":"; quoted(out, finding.source);
            out << ",\"sink\":"; quoted(out, finding.sink);
            out << ",\"transform\":"; quoted(out, finding.transform);
            out << ",\"guard\":"; quoted(out, finding.guard);
            out << ",\"evidence\":"; quoted(out, finding.evidence_id);
            out << ",\"taint_id\":" << finding.taint << "}";
        }
        out << "]}";
    }
    out << "}\n";
    std::string result = out.str();
    if (max_bytes != 0 && result.size() > max_bytes) {
        CompactFunctionView bounded_view = view;
        EnrichmentResult bounded_enrichment;
        EnrichmentResult* bounded_enrichment_ptr = nullptr;
        if (enrichment != nullptr) {
            bounded_enrichment = *enrichment;
            bounded_enrichment.completion = EnrichmentCompletion::limited;
            bounded_enrichment_ptr = &bounded_enrichment;
        }
        bounded_view.complete = false;
        bounded_view.truncated = true;
        for (;;) {
            result = render_semantic_json(
                bounded_view, bounded_enrichment_ptr, 0);
            if (result.size() <= max_bytes) return result;
            if (!bounded_view.evidence.empty()) {
                bounded_view.evidence.pop_back();
                ++bounded_view.omitted.evidence;
                continue;
            }
            if (!bounded_view.control.transfers.empty()) {
                bounded_view.control.transfers.pop_back();
                ++bounded_view.omitted.transfers;
                continue;
            }
            if (!bounded_view.control.regions.empty()) {
                bounded_view.control.regions.pop_back();
                ++bounded_view.omitted.regions;
                continue;
            }
            if (!bounded_view.statements.empty()) {
                bounded_view.statements.pop_back();
                ++bounded_view.omitted.statements;
                continue;
            }
            if (bounded_enrichment_ptr != nullptr &&
                !bounded_enrichment.taint.empty()) {
                bounded_enrichment.taint.pop_back();
                continue;
            }
            if (bounded_enrichment_ptr != nullptr &&
                !bounded_enrichment.symbolic.empty()) {
                bounded_enrichment.symbolic.pop_back();
                continue;
            }
            break;
        }
        std::ostringstream bounded;
        bounded << "{\"schema\":\"" << semantic_json_schema <<
            "\",\"function\":{\"id\":" << view.function.id <<
            ",\"entry\":\"0x" << std::hex << view.function.entry << std::dec <<
            "\"},\"complete\":false,\"truncated\":true,\"completeness_reason\":"
            "\"max-bytes\",\"required_bytes\":" << result.size() << "}\n";
        result = bounded.str();
        if (result.size() > max_bytes) {
            /* A byte budget is never permission to emit malformed JSON.  Keep
             * the smallest valid document when possible; budgets below two
             * bytes are reported as an explicit CLI failure. */
            if (max_bytes >= 3) result = "{}\n";
            else if (max_bytes == 2) result = "{}";
            else result.clear();
        }
    }
    return result;
}

std::string render_function_ir(
    const xair_cfg& cfg,
    const xair_module& module,
    const xair_function_id function) {
    std::ostringstream out;
    std::size_t node_count = 0;
    const xair_cfg_node_id* nodes = xair_cfg_function_nodes(&cfg, function, &node_count);
    out << "xair-function " << function << " {\n";
    for (std::size_t node_index = 0; node_index < node_count; ++node_index) {
        const xair_cfg_node* node = xair_cfg_get_node(&cfg, nodes[node_index]);
        if (node == nullptr) continue;
        out << "  node n" << nodes[node_index] << " [0x" << std::hex << node->start <<
            ",0x" << node->end << std::dec << ") block=" << node->ir_block << "\n";
        if (node->ir_block == XAIR_INVALID_ID) { out << "    opaque\n"; continue; }
        const xair_op_id* operations = nullptr;
        std::size_t operation_count = 0;
        if (xair_block_ops(&module, node->ir_block, &operations, &operation_count) != XAIR_OK) continue;
        for (std::size_t operation_index = 0; operation_index < operation_count; ++operation_index) {
            xair_op_view_v3 op{};
            const xair_value_id* inputs = nullptr;
            const xair_value_id* results = nullptr;
            std::size_t input_count = 0, result_count = 0;
            if (xair_module_get_op_v3(&module, operations[operation_index], &op) != XAIR_OK) continue;
            (void)xair_op_inputs(&module, operations[operation_index], &inputs, &input_count);
            (void)xair_op_results(&module, operations[operation_index], &results, &result_count);
            out << "    op" << operations[operation_index] << ' ' << xair_opcode_name(op.opcode) << " in=[";
            for (std::size_t index = 0; index < input_count; ++index) {
                if (index != 0) out << ',';
                out << 'v' << inputs[index];
            }
            out << "] out=[";
            for (std::size_t index = 0; index < result_count; ++index) {
                if (index != 0) out << ',';
                out << 'v' << results[index];
            }
            xair_op_attributes attributes{};
            if (xair_op_attributes_get(&module, operations[operation_index], &attributes) == XAIR_OK &&
                attributes.kind != XAIR_ATTR_NONE) {
                out << "] attr={kind=" << attributes.kind << ",effects=0x" << std::hex <<
                    attributes.effects << std::dec;
                if (attributes.import_name != nullptr) out << ",import=" <<
                    (attributes.import_module != nullptr ? attributes.import_module : "") << '!' <<
                    attributes.import_name;
                if (attributes.direct_target != 0) out << ",target=0x" << std::hex <<
                    attributes.direct_target << std::dec;
                out << '}';
            } else out << ']';
            out << '\n';
        }
        xair_term_view term{};
        if (xair_block_terminator(&module, node->ir_block, &term) == XAIR_OK) {
            out << "    term kind=" << term.kind;
            if (term.condition != XAIR_INVALID_ID) out << " condition=v" << term.condition;
            if (term.true_target != XAIR_INVALID_ID) out << " true=b" << term.true_target;
            if (term.false_target != XAIR_INVALID_ID) out << " false=b" << term.false_target;
            out << '\n';
        }
    }
    out << "}\n";
    return out.str();
}

} // namespace airece
