#include <airece/session/analysis_session.hpp>
#include <airece/emit/semantic_text.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
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

std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    const std::vector<char> chars{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    std::vector<std::byte> bytes;
    bytes.reserve(chars.size());
    for (const char value : chars) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return bytes;
}

void test_basic_session(const std::filesystem::path& fixture) {
    airece::AnalysisOptions options;
    options.profile = airece::AnalysisProfile::fast;
    options.max_wall_time_ms = 5'000;
    const airece::SessionOpenResult opened =
        airece::AnalysisSession::open(fixture, options);
    expect(static_cast<bool>(opened), "fixture opens through AnalysisSession");
    if (!opened) return;

    const airece::AnalysisSession& session = *opened.session;
    expect(session.binary().entry != 0, "loader metadata remains available");
    expect(xair_cfg_is_frozen(&session.cfg()) != 0, "CFG is frozen");
    expect(session.module() != nullptr, "XAIR module is owned by the session");
    expect(!session.functions().empty(), "function inventory is populated");
    expect(!session.symbolic_context_initialized(),
           "opening a binary does not create a symbolic context");
    expect(!session.solver_initialized(),
           "opening a binary does not initialize Z3");
    expect(session.cached_expression_count() == 0,
           "semantic expression cache starts empty");
    expect(session.cached_variable_view_count() == 0,
           "presentation variable cache starts empty");
    expect(session.cached_control_view_count() == 0 &&
               session.cached_compact_view_count() == 0,
           "function semantic-view caches start empty");
    if (session.module() != nullptr && xair_module_value_count(session.module()) != 0) {
        const xair_value_id root = static_cast<xair_value_id>(
            xair_module_value_count(session.module()) - 1);
        const airece::SemanticExpression expression = session.expression_view(root);
        expect(static_cast<bool>(expression),
               "session recovers an expression directly from its XAIR module");
        expect(expression.value == root && !expression.text.empty(),
               "session expression retains the requested XAIR root");
        expect(session.cached_expression_count() == 1,
               "session caches its first semantic expression view");
        expect(session.expression_view(root).text == expression.text,
               "session expression cache is deterministic");
        expect(session.cached_expression_count() == 1,
               "identical session expression request reuses the cache");
        expect(!session.symbolic_context_initialized() && !session.solver_initialized(),
               "expression recovery does not create symbolic or solver state");
    }
    if (!session.functions().empty()) {
        const airece::VariableView variables =
            session.variable_view(session.functions().front().id);
        expect(static_cast<bool>(variables),
               "session recovers function-local presentation variables");
        expect(variables.function_address == session.functions().front().entry,
               "variable view retains its function identity");
        expect(session.cached_variable_view_count() == 1,
               "session caches its first variable view");
        expect(session.variable_view(session.functions().front().id).variables.size() ==
                   variables.variables.size(),
               "session variable cache is deterministic");
        expect(session.cached_variable_view_count() == 1,
               "identical session variable request reuses the cache");
        expect(!session.symbolic_context_initialized() && !session.solver_initialized(),
               "variable recovery does not create symbolic or solver state");

        const airece::ControlView control =
            session.control_view(session.functions().front().id);
        expect(static_cast<bool>(control) && !control.block_order.empty(),
               "session builds a display-only control-region view");
        expect(session.cached_control_view_count() == 1,
               "session caches control structuring");
        const airece::CompactFunctionView compact =
            session.compact_view(session.functions().front().id);
        expect(static_cast<bool>(compact) && !compact.statements.empty(),
               "session builds the compact function semantic view");
        expect(session.cached_compact_view_count() == 1,
               "session caches compact semantic views");
        for (const airece::SemanticStatement& statement : compact.statements) {
            expect(statement.address != 0 || !statement.operations.empty(),
                   "every material semantic statement retains address or XAIR evidence");
        }
        std::unordered_set<xair_op_id> displayed_operations;
        for (const airece::SemanticStatement& statement : compact.statements) {
            displayed_operations.insert(
                statement.operations.begin(), statement.operations.end());
        }
        std::size_t function_node_count = 0;
        const xair_cfg_node_id* function_nodes = xair_cfg_function_nodes(
            &session.cfg(), session.functions().front().id, &function_node_count);
        for (std::size_t node_index = 0; node_index < function_node_count; ++node_index) {
            const xair_cfg_node* node = xair_cfg_get_node(
                &session.cfg(), function_nodes[node_index]);
            if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
            const xair_op_id* operations = nullptr;
            std::size_t operation_count = 0;
            if (xair_block_ops(
                    session.module(), node->ir_block,
                    &operations, &operation_count) != XAIR_OK) {
                continue;
            }
            for (std::size_t operation_index = 0;
                 operation_index < operation_count; ++operation_index) {
                xair_op_view_v3 operation{};
                xair_op_attributes attributes{};
                if (xair_module_get_op_v3(
                        session.module(), operations[operation_index],
                        &operation) != XAIR_OK) {
                    continue;
                }
                (void)xair_op_attributes_get(
                    session.module(), operations[operation_index], &attributes);
                const bool material = operation.opcode == XAIR_OP_CALL ||
                    operation.opcode == XAIR_OP_LOAD ||
                    operation.opcode == XAIR_OP_STORE ||
                    operation.opcode == XAIR_OP_UNKNOWN ||
                    operation.opcode == XAIR_OP_UNDEF ||
                    operation.opcode == XAIR_OP_OPAQUE_PURE ||
                    operation.opcode == XAIR_OP_OPAQUE_EFFECT ||
                    operation.opcode == XAIR_OP_MEMORY_BARRIER ||
                    operation.opcode == XAIR_OP_INTRINSIC || attributes.effects != 0;
                if (material) {
                    expect(displayed_operations.contains(operations[operation_index]),
                           "no side-effecting or unresolved XAIR operation disappears");
                }
            }
        }
        const airece::RenderedSemanticText rendered =
            airece::render_compact(compact);
        expect(rendered.text.find("fn 0x") == 0 &&
                   rendered.text.find("coverage:") != std::string::npos &&
                   rendered.text.find("control:") != std::string::npos,
               "compact output exposes identity, coverage, and control facts");
        expect(rendered.text.size() <= 4'608,
               "default compact output stays under 4 KB plus a small footer");
        const airece::RenderedSemanticText repeated = airece::render_compact(
            session.compact_view(session.functions().front().id));
        expect(repeated.text == rendered.text &&
                   session.cached_compact_view_count() == 1,
               "byte-identical compact requests render byte-identically");

        airece::CompactOptions bounded;
        bounded.max_bytes = 256;
        bounded.max_statements = 2;
        bounded.max_evidence = 1;
        const airece::CompactFunctionView limited_view =
            session.compact_view(session.functions().front().id, bounded);
        for (std::size_t index = 0;
             index < limited_view.statements.size() && index < compact.statements.size();
             ++index) {
            expect(limited_view.statements[index].stable_id ==
                       compact.statements[index].stable_id,
                   "statement IDs do not change when output budgets change");
        }
        if (!limited_view.evidence.empty() && !compact.evidence.empty()) {
            expect(limited_view.evidence.front().stable_id ==
                       compact.evidence.front().stable_id,
                   "evidence IDs do not change when evidence budgets change");
        }
        const std::string expected_id_prefix = "F" + [&] {
            std::ostringstream value;
            value << std::hex << session.functions().front().entry;
            return value.str();
        }();
        expect(compact.statements.front().stable_id.starts_with(
                   expected_id_prefix + ":S:"),
               "statement IDs are function-qualified");
        const airece::RenderedSemanticText limited =
            airece::render_compact(limited_view, bounded);
        expect(limited.truncated && limited.text.find("omitted:") != std::string::npos &&
                   limited.text.find("continue-with:") != std::string::npos,
               "hard semantic budgets produce an explicit continuation footer");
        expect(limited.text.size() <= 768,
               "byte budget is exceeded only by the bounded truncation footer");
        expect(!session.symbolic_context_initialized() && !session.solver_initialized(),
               "ordinary control and compact rendering remain solver-free");
    }

    if (!session.functions().empty()) {
        const airece::FunctionInfo& first = session.functions().front();
        expect(session.function_by_address(first.entry) == &first,
               "function lookup by entry address is stable");
        expect(session.function_by_name(first.name) == &first,
               "function lookup by name is stable");
        expect(session.function_by_address(first.range_start) != nullptr,
               "function lookup accepts an address inside its range");
    }
    expect(session.function_by_name("not_a_real_function") == nullptr,
           "unknown function names are rejected");
    expect(session.function_by_call_site(UINT64_C(0xffffffffffffffff)) == nullptr,
           "unknown call sites are rejected");

    bool checked_call_site = false;
    for (const airece::CallSiteInfo& call : session.call_sites()) {
        if (call.address == 0 || call.owner >= session.functions().size()) continue;
        const airece::FunctionInfo* owner = session.function_by_call_site(call.address);
        expect(owner != nullptr && owner->id == call.owner,
               "call-site lookup returns the owning function");
        checked_call_site = true;
        break;
    }
    expect(checked_call_site, "fixture exposes a recoverable call-site address");

    const std::vector<std::byte> bytes = read_bytes(fixture);
    expect(!bytes.empty(), "fixture bytes were read");
    const airece::SessionOpenResult memory_opened =
        airece::AnalysisSession::open_bytes(bytes, "memory-fixture", options);
    expect(static_cast<bool>(memory_opened), "in-memory binary opens once into a session");
    if (memory_opened) {
        expect(memory_opened.session->functions().size() == session.functions().size(),
               "path and memory loading produce the same function count");
        expect(!memory_opened.session->solver_initialized(),
               "in-memory import does not initialize Z3");
    }

    airece::SessionDiagnostic diagnostic;
    xair_sym_context* symbolic = opened.session->symbolic_context(&diagnostic);
    expect(symbolic != nullptr, "symbolic context can be requested lazily");
    expect(opened.session->symbolic_context_initialized(),
           "lazy symbolic context reports initialized after access");
    expect(!opened.session->solver_initialized(),
           "creating the symbolic context still does not initialize Z3");
}

void test_limits_and_cancellation(const std::filesystem::path& fixture) {
    airece::AnalysisOptions limited_options;
    limited_options.profile = airece::AnalysisProfile::fast;
    limited_options.max_blocks = 1;
    const airece::SessionOpenResult limited =
        airece::AnalysisSession::open(fixture, limited_options);
    expect(static_cast<bool>(limited), "block limit preserves a usable session");
    if (limited) {
        expect(!limited.session->completeness().complete,
               "block-limited session is explicitly incomplete");
        expect(limited.session->completeness().cfg_state == XAIR_ANALYSIS_LIMITED,
               "block limit propagates into CFG completeness");
        expect(!limited.session->functions().empty(),
               "block-limited session retains useful function results");
    }

    airece::AnalysisOptions input_limited_options;
    input_limited_options.max_input_bytes = 1;
    const airece::SessionOpenResult input_limited =
        airece::AnalysisSession::open(fixture, input_limited_options);
    expect(!input_limited, "input byte limit rejects oversized input");
    expect(input_limited.diagnostic.status == XAIR_ERR_RESOURCE_LIMIT,
           "input byte limit returns the resource-limit status");

    xair_cancel_token* token = nullptr;
    expect(xair_cancel_token_create(&token) == XAIR_OK,
           "cancellation token is created");
    if (token != nullptr) {
        xair_cancel_token_request(token);
        airece::AnalysisOptions canceled_options;
        canceled_options.cancellation = token;
        const airece::SessionOpenResult canceled =
            airece::AnalysisSession::open(fixture, canceled_options);
        expect(!canceled, "pre-canceled analysis does not produce a session");
        expect(canceled.diagnostic.status == XAIR_ERR_CANCELED,
               "cancellation status propagates from the loader");
        xair_cancel_token_destroy(token);
    }
}

void test_import_lookup(const std::filesystem::path& executable) {
    airece::AnalysisOptions options;
    options.profile = airece::AnalysisProfile::fast;
    options.max_blocks = 3'000;
    options.max_wall_time_ms = 60'000;
    options.build_ir = false;
    options.expand_indirects = false;
    const airece::SessionOpenResult opened =
        airece::AnalysisSession::open(executable, options);
    expect(static_cast<bool>(opened), "AIRECE executable opens for import lookup");
    if (!opened) return;
    expect(!opened.session->solver_initialized(),
           "listing a real executable's functions does not initialize Z3");
    const airece::SemanticExpression unavailable =
        opened.session->expression_view(0);
    expect(!unavailable && unavailable.status == XAIR_ERR_INCOMPLETE,
           "session without IR reports expression recovery as unavailable");
    const airece::VariableView unavailable_variables =
        opened.session->variable_view(0);
    expect(!unavailable_variables &&
               unavailable_variables.status == XAIR_ERR_INCOMPLETE,
           "session without IR reports variable recovery as unavailable");
    const airece::ControlView unavailable_control = opened.session->control_view(0);
    const airece::CompactFunctionView unavailable_compact =
        opened.session->compact_view(0);
    expect(!unavailable_control && unavailable_control.status == XAIR_ERR_INCOMPLETE &&
               !unavailable_compact && unavailable_compact.status == XAIR_ERR_INCOMPLETE,
           "session without IR reports control and compact views as unavailable");

    bool checked_name = false;
    bool checked_ordinal = false;
    for (const airece::CallSiteInfo& call : opened.session->call_sites()) {
        if (call.owner >= opened.session->functions().size() ||
            call.import_module.empty()) {
            continue;
        }
        if (!checked_name && !call.import_name.empty()) {
            const airece::FunctionInfo* function = opened.session->function_by_import(
                call.import_module, call.import_name);
            const std::vector<const airece::FunctionInfo*> all =
                opened.session->functions_referencing_import(
                    call.import_module, call.import_name);
            expect(function != nullptr, "function lookup by import name succeeds");
            expect(!all.empty(), "all import references can be enumerated");
            checked_name = true;
        }
        if (!checked_ordinal && call.import_ordinal != 0) {
            expect(opened.session->function_by_import(
                       call.import_module, call.import_ordinal) != nullptr,
                   "function lookup by import ordinal succeeds");
            checked_ordinal = true;
        }
    }
    if (opened.session->binary().format == XAIR_BINARY_FORMAT_PE) {
        expect(checked_name, "real PE provides at least one named import call reference");
    } else {
        expect(opened.session->binary().format == XAIR_BINARY_FORMAT_ELF,
               "native non-PE executable is recognized as ELF");
    }
    // Ordinal-only imports are optional in normal PE files; exercise the miss path too.
    expect(opened.session->function_by_import("missing.dll", UINT32_C(1)) == nullptr,
           "unknown import ordinals are rejected");
}

} // namespace

int main(const int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: analysis_session_test <fixture> <airece-executable>\n";
        return 2;
    }
    test_basic_session(argv[1]);
    test_limits_and_cancellation(argv[1]);
    test_import_lookup(argv[2]);
    return failures == 0 ? 0 : 1;
}
