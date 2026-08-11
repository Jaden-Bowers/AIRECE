#include <airece/session/analysis_session.hpp>
#include <airece/emit/agent_json.hpp>
#include <airece/emit/semantic_json.hpp>
#include <airece/emit/semantic_text.hpp>
#include <airece/semantic/api_model.hpp>
#include <airece/semantic/directed_flow.hpp>
#include <airece/semantic/enrichment.hpp>
#include <airece/version.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <queue>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr int exit_success = 0;
constexpr int exit_failure = 1;
constexpr int exit_usage = 2;
constexpr int exit_partial = 3;
xair_cancel_token* global_cancel_token = nullptr;

void request_cancellation(int) {
    if (global_cancel_token != nullptr) xair_cancel_token_request(global_cancel_token);
}

class CancelTokenGuard {
public:
    CancelTokenGuard() {
        if (xair_cancel_token_create(&global_cancel_token) == XAIR_OK) {
            previous_ = std::signal(SIGINT, request_cancellation);
        }
    }
    ~CancelTokenGuard() {
        if (global_cancel_token != nullptr) {
            xair_cancel_token_destroy(global_cancel_token);
            global_cancel_token = nullptr;
        }
        if (previous_ != SIG_ERR) (void)std::signal(SIGINT, previous_);
    }
private:
    using Handler = void (*)(int);
    Handler previous_{SIG_ERR};
};

void print_help() {
    std::cout
        << "AIRECE - AI reverse-engineering context engine\n\n"
        << "Usage:\n"
        << "  airece inspect <binary> [analysis options]\n"
        << "  airece functions <binary> [analysis options]\n"
        << "  airece expr <binary> <value-id> [expression and analysis options]\n"
        << "  airece vars <binary> <function-address> [variable and analysis options]\n"
        << "  airece fn <binary> <function-address> [semantic and analysis options]\n"
        << "  airece calls <binary> [function-address] [analysis options]\n"
        << "  airece xrefs <binary> <address> [analysis options]\n"
        << "  airece slice <binary> <address-or-statement> [analysis options]\n"
        << "  airece taint <binary> <function-address> [enrichment options]\n"
        << "  airece flow <binary> --source <point> --target <point> [flow options]\n"
        << "  airece path <binary> --from <address> --to <address> [enrichment options]\n"
        << "  airece evidence <binary> <statement-id> [analysis options]\n"
        << "  airece --version\n"
        << "  airece --help\n\n"
        << "Analysis options:\n"
        << "  --profile <fast|balanced|exhaustive>\n"
        << "  --max-input-bytes <count>\n"
        << "  --max-functions <count>\n"
        << "  --max-blocks <count>\n"
        << "  --max-edges <count>\n"
        << "  --max-ir-values <count>\n"
        << "  --max-memory-bytes <count>\n"
        << "  --max-wall-time-ms <count>\n"
        << "  --no-ir\n"
        << "  --no-indirects\n\n"
        << "Expression options:\n"
        << "  --max-expression-depth <count>\n"
        << "  --max-expression-nodes <count>\n"
        << "  --max-expression-tokens <count>\n"
        << "  --max-expression-characters <count>\n"
        << "  --no-inline-loads\n"
        << "  --no-inline-single-use\n\n"
        << "Variable options:\n"
        << "  --max-variables <count>\n"
        << "  --repeated-use-threshold <count>\n"
        << "  --no-repeated-values\n"
        << "  --no-buffers\n\n"
        << "Semantic function options:\n"
        << "  --view <agent|compact|pseudo|ir|json>\n"
        << "  --json (alias for --view json)\n"
        << "  --max-bytes <count>\n"
        << "  --max-statements <count>\n"
        << "  --max-calls <count>\n"
        << "  --max-evidence <count>\n"
        << "  --max-expression-depth <count>\n"
        << "  --offset <call-index>\n"
        << "  --calls\n\n"
        << "Enrichment options (opt-in; compact rendering never invokes a solver):\n"
        << "  --symbolic\n"
        << "  --taint\n"
        << "  --max-queries <count>\n"
        << "  --max-states <count>\n"
        << "  --symbolic-timeout-ms <count>\n\n"
        << "Directed flow options:\n"
        << "  --source <selector> (repeatable)\n"
        << "  --target <selector> (repeatable)\n"
        << "  --mode <taint|taint-symbolic|symbolic>\n"
        << "  --function-depth <count> (default: 3; 0 is intra-function)\n"
        << "  --max-states <count>\n"
        << "  --max-queries <count>\n"
        << "  --max-paths <count>\n"
        << "  --max-taint-bytes <count>\n"
        << "  --max-symbolic-bytes <count>\n"
        << "  --symbolic-timeout-ms <count>\n"
        << "  --json\n"
        << "  selectors: register(rcx)@0xADDR[:before|after],\n"
        << "             buffer(rcx,64)@0xADDR[:before|after],\n"
        << "             memory(0xADDR,64)@0xINSTRUCTION, value(v42),\n"
        << "             funcarg(0)@0xFUNCTION, callarg(0)@0xCALL,\n"
        << "             callresult@0xCALL, reach@0xADDR, memory-write@0xADDR\n"
        << "  Prefix a selector with a name and '=' (for example input=buffer(...)).\n"
        << "  Argument indexes are zero-based.\n\n"
        << "Exit codes: 0 complete, 1 analysis failure, 2 usage error, "
           "3 useful partial result.\n";
}

bool parse_unsigned(const std::string_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    value = 0;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, value, 10);
    return parsed.ec == std::errc{} && parsed.ptr == end;
}

bool parse_value_id(const std::string_view text, xair_value_id& value) {
    if (text.empty()) return false;
    int base = 10;
    std::string_view digits = text;
    if (digits.size() > 2 && digits[0] == '0' &&
        (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.remove_prefix(2);
    }
    if (digits.empty()) return false;
    std::uint64_t parsed_value = 0;
    const auto parsed = std::from_chars(
        digits.data(), digits.data() + digits.size(), parsed_value, base);
    if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size() ||
        parsed_value >= static_cast<std::uint64_t>(XAIR_INVALID_ID)) {
        return false;
    }
    value = static_cast<xair_value_id>(parsed_value);
    return true;
}

bool parse_address(const std::string_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    int base = 10;
    std::string_view digits = text;
    if (digits.size() > 2 && digits[0] == '0' &&
        (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.remove_prefix(2);
    }
    if (digits.empty()) return false;
    value = 0;
    const auto parsed = std::from_chars(
        digits.data(), digits.data() + digits.size(), value, base);
    return parsed.ec == std::errc{} && parsed.ptr == digits.data() + digits.size();
}

bool assign_size(
    const std::string_view option,
    const std::string_view text,
    std::size_t& target) {
    std::uint64_t value = 0;
    if (!parse_unsigned(text, value) ||
        value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        std::cerr << "airece: invalid value for " << option << ": " << text << '\n';
        return false;
    }
    target = static_cast<std::size_t>(value);
    return true;
}

bool assign_u64(
    const std::string_view option,
    const std::string_view text,
    std::uint64_t& target) {
    if (!parse_unsigned(text, target)) {
        std::cerr << "airece: invalid value for " << option << ": " << text << '\n';
        return false;
    }
    return true;
}

bool parse_analysis_options(
    const int argc,
    char** argv,
    const int first,
    airece::AnalysisOptions& options,
    airece::ExpressionOptions* expression_options = nullptr,
    airece::VariableOptions* variable_options = nullptr,
    airece::CompactOptions* compact_options = nullptr,
    std::string* semantic_view = nullptr,
    airece::EnrichmentOptions* enrichment_options = nullptr) {
    options.cancellation = global_cancel_token;
    if (enrichment_options != nullptr) {
        enrichment_options->cancellation = global_cancel_token;
    }
    for (int index = first; index < argc; ++index) {
        const std::string_view option{argv[index]};
        if (option == "--no-ir") {
            options.build_ir = false;
            continue;
        }
        if (option == "--no-indirects") {
            options.expand_indirects = false;
            options.analyze_indirects = false;
            continue;
        }
        if (expression_options != nullptr && option == "--no-inline-loads") {
            expression_options->inline_loads = false;
            continue;
        }
        if (expression_options != nullptr && option == "--no-inline-single-use") {
            expression_options->inline_single_use = false;
            continue;
        }
        if (variable_options != nullptr && option == "--no-repeated-values") {
            variable_options->include_repeated_values = false;
            continue;
        }
        if (variable_options != nullptr && option == "--no-buffers") {
            variable_options->include_buffers = false;
            continue;
        }
        if (compact_options != nullptr && option == "--calls") continue;
        if (semantic_view != nullptr && option == "--json") {
            *semantic_view = "json";
            continue;
        }
        if (enrichment_options != nullptr && option == "--symbolic") {
            enrichment_options->symbolic = true;
            continue;
        }
        if (enrichment_options != nullptr && option == "--taint") {
            enrichment_options->taint = true;
            continue;
        }
        if (index + 1 >= argc) {
            std::cerr << "airece: missing value for " << option << '\n';
            return false;
        }
        const std::string_view value{argv[++index]};
        if (option == "--profile") {
            if (value == "fast") options.profile = airece::AnalysisProfile::fast;
            else if (value == "balanced") {
                options.profile = airece::AnalysisProfile::balanced;
            } else if (value == "exhaustive") {
                options.profile = airece::AnalysisProfile::exhaustive;
            } else {
                std::cerr << "airece: invalid profile: " << value << '\n';
                return false;
            }
        } else if (option == "--max-input-bytes") {
            if (!assign_u64(option, value, options.max_input_bytes)) return false;
        } else if (option == "--max-functions") {
            if (!assign_size(option, value, options.max_functions)) return false;
        } else if (option == "--max-blocks") {
            if (!assign_size(option, value, options.max_blocks)) return false;
        } else if (option == "--max-edges") {
            if (!assign_size(option, value, options.max_edges)) return false;
        } else if (option == "--max-ir-values") {
            if (!assign_size(option, value, options.max_ir_values)) return false;
        } else if (option == "--max-memory-bytes") {
            if (!assign_size(option, value, options.max_memory_bytes)) return false;
        } else if (option == "--max-wall-time-ms") {
            if (!assign_u64(option, value, options.max_wall_time_ms)) return false;
        } else if (expression_options != nullptr && option == "--max-expression-depth") {
            if (!assign_size(option, value, expression_options->max_depth)) return false;
        } else if (compact_options != nullptr && option == "--max-expression-depth") {
            if (!assign_size(option, value, compact_options->max_expression_depth)) {
                return false;
            }
        } else if (expression_options != nullptr && option == "--max-expression-nodes") {
            if (!assign_size(option, value, expression_options->max_nodes)) return false;
        } else if (expression_options != nullptr && option == "--max-expression-tokens") {
            if (!assign_size(option, value, expression_options->max_tokens)) return false;
        } else if (expression_options != nullptr && option == "--max-expression-characters") {
            if (!assign_size(option, value, expression_options->max_characters)) return false;
        } else if (variable_options != nullptr && option == "--max-variables") {
            if (!assign_size(option, value, variable_options->max_variables)) return false;
        } else if (variable_options != nullptr && option == "--repeated-use-threshold") {
            if (!assign_size(
                    option, value, variable_options->repeated_use_threshold)) return false;
        } else if (compact_options != nullptr && option == "--max-bytes") {
            if (!assign_size(option, value, compact_options->max_bytes)) return false;
        } else if (compact_options != nullptr && option == "--max-statements") {
            if (!assign_size(option, value, compact_options->max_statements)) return false;
        } else if (compact_options != nullptr && option == "--max-calls") {
            if (!assign_size(option, value, compact_options->max_calls)) return false;
        } else if (compact_options != nullptr && option == "--max-evidence") {
            if (!assign_size(option, value, compact_options->max_evidence)) return false;
        } else if (compact_options != nullptr && option == "--offset") {
            if (!assign_size(option, value, compact_options->call_offset)) return false;
        } else if (semantic_view != nullptr && option == "--view") {
            if (value != "agent" && value != "compact" && value != "pseudo" &&
                value != "ir" && value != "json") {
                std::cerr << "airece: unsupported function view: " << value << '\n';
                return false;
            }
            *semantic_view = std::string(value);
        } else if (enrichment_options != nullptr && option == "--max-queries") {
            if (!assign_size(option, value, enrichment_options->max_queries)) return false;
        } else if (enrichment_options != nullptr && option == "--max-states") {
            if (!assign_size(option, value, enrichment_options->max_states)) return false;
        } else if (enrichment_options != nullptr && option == "--symbolic-timeout-ms") {
            if (!assign_u64(option, value, enrichment_options->max_time_ms)) return false;
        } else {
            std::cerr << "airece: unknown option: " << option << '\n';
            return false;
        }
    }
    return true;
}

const char* completeness_name(const airece::SessionCompleteness& completeness) {
    if (completeness.complete &&
        completeness.loader_state == XAIR_ANALYSIS_COMPLETE &&
        completeness.cfg_state == XAIR_ANALYSIS_COMPLETE) {
        return "complete";
    }
    if (completeness.loader_state == XAIR_ANALYSIS_LIMITED ||
        completeness.cfg_state == XAIR_ANALYSIS_LIMITED) {
        return "limited";
    }
    return "partial";
}

bool is_complete(const airece::AnalysisSession& session) {
    return std::string_view(completeness_name(session.completeness())) == "complete";
}

void print_hex(const std::uint64_t value) {
    std::cout << "0x" << std::hex << value << std::dec;
}

int report_open_failure(const airece::SessionDiagnostic& diagnostic) {
    std::cerr << "airece: " << diagnostic.message
              << " (" << xair_status_name(diagnostic.status) << ')';
    if (diagnostic.address != 0) {
        std::cerr << " at 0x" << std::hex << diagnostic.address << std::dec;
    }
    std::cerr << '\n';
    return exit_failure;
}

int inspect_binary(airece::AnalysisSession& session) {
    const xair_binary_view& binary = session.binary();
    const xair_cfg_stats& stats = session.cfg_stats();
    const airece::SessionCompleteness& completeness = session.completeness();
    std::cout << "file: " << session.path().string() << '\n'
              << "format: " << xair_binary_format_name(binary.format) << '\n'
              << "arch: " << xair_arch_name(binary.arch) << '\n'
              << "image-base: ";
    print_hex(binary.image_base);
    std::cout << "\nentry: ";
    print_hex(binary.entry);
    std::cout << "\nsegments: " << binary.segment_count
              << "\nsymbols: " << binary.symbol_count
              << "\nfunctions: " << session.functions().size()
              << "\ncfg:\n"
              << "  blocks: " << stats.final_blocks << '\n'
              << "  edges: " << stats.final_edges << '\n'
              << "  calls: " << stats.call_sites << '\n'
              << "completeness: " << completeness_name(completeness) << '\n'
              << "  loader: " << xair_analysis_state_name(completeness.loader_state) << '\n'
              << "  cfg: " << xair_analysis_state_name(completeness.cfg_state) << '\n'
              << "  skipped: " << completeness.skipped_items << '\n'
              << "  unresolved-indirects: " << completeness.unresolved_indirects << '\n'
              << "symbolic-context: "
              << (session.symbolic_context_initialized() ? "initialized" : "not-initialized")
              << "\nsolver: "
              << (session.solver_initialized() ? "initialized" : "not-initialized")
              << '\n';
    return is_complete(session) ? exit_success : exit_partial;
}

int list_functions(airece::AnalysisSession& session) {
    std::vector<const airece::FunctionInfo*> functions;
    functions.reserve(session.functions().size());
    for (const airece::FunctionInfo& function : session.functions()) {
        functions.push_back(&function);
    }
    std::sort(functions.begin(), functions.end(),
        [](const airece::FunctionInfo* left, const airece::FunctionInfo* right) {
            if (left->entry != right->entry) return left->entry < right->entry;
            return left->name < right->name;
        });
    for (const airece::FunctionInfo* function : functions) {
        print_hex(function->entry);
        std::cout << ' ' << function->name
                  << " coverage="
                  << airece::semantic_coverage_name(function->semantic_coverage)
                  << " blocks=" << function->node_count
                  << " calls=" << function->call_edge_count << '\n';
    }
    return is_complete(session) ? exit_success : exit_partial;
}

int analyze_command(const int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "airece: command requires a binary path\n";
        return exit_usage;
    }
    airece::AnalysisOptions options;
    if (!parse_analysis_options(argc, argv, 3, options)) return exit_usage;
    airece::SessionOpenResult opened = airece::AnalysisSession::open(
        std::filesystem::path(argv[2]), options);
    const std::string_view command{argv[1]};
    if (!opened) {
        if (command == "inspect" && opened.partial_session != nullptr) {
            std::cerr << "airece: partial inspection: " << opened.diagnostic.message
                      << " (" << xair_status_name(opened.diagnostic.status) << ")\n";
            return inspect_binary(*opened.partial_session);
        }
        return report_open_failure(opened.diagnostic);
    }
    if (command == "inspect") return inspect_binary(*opened.session);
    return list_functions(*opened.session);
}

int expression_command(const int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "airece: expr requires a binary path and XAIR value id\n";
        return exit_usage;
    }
    xair_value_id value = XAIR_INVALID_ID;
    if (!parse_value_id(argv[3], value)) {
        std::cerr << "airece: invalid XAIR value id: " << argv[3] << '\n';
        return exit_usage;
    }
    airece::AnalysisOptions analysis_options;
    airece::ExpressionOptions expression_options;
    if (!parse_analysis_options(
            argc, argv, 4, analysis_options, &expression_options)) {
        return exit_usage;
    }
    if (!analysis_options.build_ir) {
        std::cerr << "airece: expr requires IR construction; remove --no-ir\n";
        return exit_usage;
    }
    airece::SessionOpenResult opened = airece::AnalysisSession::open(
        std::filesystem::path(argv[2]), analysis_options);
    if (!opened) return report_open_failure(opened.diagnostic);
    const airece::SemanticExpression expression =
        opened.session->expression_view(value, expression_options);
    if (!expression) {
        std::cerr << "airece: cannot recover expression for value " << value
                  << " (" << xair_status_name(expression.status) << ")\n";
        return exit_failure;
    }
    std::cout << expression.text << '\n';
    return is_complete(*opened.session) && !expression.truncated
        ? exit_success : exit_partial;
}

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

int variables_command(const int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "airece: vars requires a binary path and function address\n";
        return exit_usage;
    }
    std::uint64_t address = 0;
    if (!parse_address(argv[3], address)) {
        std::cerr << "airece: invalid function address: " << argv[3] << '\n';
        return exit_usage;
    }
    airece::AnalysisOptions analysis_options;
    airece::VariableOptions variable_options;
    if (!parse_analysis_options(
            argc, argv, 4, analysis_options, nullptr, &variable_options)) {
        return exit_usage;
    }
    if (!analysis_options.build_ir) {
        std::cerr << "airece: vars requires IR construction; remove --no-ir\n";
        return exit_usage;
    }
    analysis_options.manual_roots.push_back(address);
    airece::SessionOpenResult opened = airece::AnalysisSession::open(
        std::filesystem::path(argv[2]), analysis_options);
    if (!opened) return report_open_failure(opened.diagnostic);
    const airece::FunctionInfo* function =
        opened.session->function_by_address(address);
    if (function == nullptr) {
        std::cerr << "airece: no function contains address 0x" << std::hex
                  << address << std::dec << '\n';
        return exit_failure;
    }
    const airece::VariableView view =
        opened.session->variable_view(function->id, variable_options);
    if (!view) {
        std::cerr << "airece: cannot recover variables for function 0x" << std::hex
                  << function->entry << std::dec << " ("
                  << xair_status_name(view.status) << ")\n";
        return exit_failure;
    }
    for (const airece::PresentationVariable& variable : view.variables) {
        std::cout << variable.name.text << ':' << variable.type.text
                  << " kind=" << airece::variable_kind_name(variable.kind)
                  << " id=" << variable.stable_id;
        if (variable.primary_value != XAIR_INVALID_ID) {
            std::cout << " xair=v" << variable.primary_value;
        }
        if (variable.address != 0) {
            std::cout << " address=0x" << std::hex << variable.address << std::dec;
        }
        if (variable.kind == airece::VariableKind::stack_slot) {
            std::cout << " stack-offset=" << variable.stack_offset;
        }
        if (variable.storage_bits != 0) {
            std::cout << " access-bits=" << variable.storage_bits;
        }
        if (variable.overlaps_uncertain) std::cout << " overlap=uncertain";
        std::cout << " confidence="
                  << confidence_name(variable.evidence.confidence) << '\n';
    }
    return is_complete(*opened.session) && !view.truncated
        ? exit_success : exit_partial;
}

int function_command(const int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "airece: fn requires a binary path and function address\n";
        return exit_usage;
    }
    std::uint64_t address = 0;
    if (!parse_address(argv[3], address)) {
        std::cerr << "airece: invalid function address: " << argv[3] << '\n';
        return exit_usage;
    }
    airece::AnalysisOptions analysis_options;
    airece::CompactOptions compact_options;
    airece::EnrichmentOptions enrichment_options;
    std::string view_name = "compact";
    if (!parse_analysis_options(
            argc, argv, 4, analysis_options, nullptr, nullptr,
            &compact_options, &view_name, &enrichment_options)) {
        return exit_usage;
    }
    if (!analysis_options.build_ir) {
        std::cerr << "airece: fn requires IR construction; remove --no-ir\n";
        return exit_usage;
    }
    analysis_options.manual_roots.push_back(address);
    airece::SessionOpenResult opened = airece::AnalysisSession::open(
        std::filesystem::path(argv[2]), analysis_options);
    if (!opened) return report_open_failure(opened.diagnostic);
    const airece::FunctionInfo* function =
        opened.session->function_by_address(address);
    if (function == nullptr) {
        std::cerr << "airece: no function contains address 0x" << std::hex
                  << address << std::dec << '\n';
        return exit_failure;
    }
    airece::CompactFunctionView semantic =
        opened.session->compact_view(function->id, compact_options);
    if (!semantic) {
        std::cerr << "airece: cannot build semantic view for function 0x"
                  << std::hex << function->entry << std::dec << " ("
                  << xair_status_name(semantic.status) << ")\n";
        return exit_failure;
    }
    airece::EnrichmentResult enrichment;
    const bool enrich = enrichment_options.symbolic || enrichment_options.taint;
    if (enrich) {
        airece::SessionDiagnostic diagnostic;
        xair_sym_context* context = opened.session->symbolic_context(&diagnostic);
        if (context == nullptr) {
            std::cerr << "airece: cannot initialize symbolic context: " <<
                diagnostic.message << '\n';
            return exit_failure;
        }
        enrichment = airece::enrich_function(opened.session->cfg(),
            *opened.session->module(), opened.session->binary(), function->id,
            *context, semantic,
            enrichment_options);
        airece::append_enrichment(semantic, enrichment);
    }
    if (view_name == "ir") {
        std::cout << airece::render_function_ir(opened.session->cfg(),
            *opened.session->module(), function->id);
        return is_complete(*opened.session) ? exit_success : exit_partial;
    }
    if (view_name == "agent") {
        std::cout << airece::render_agent_json(
            *opened.session, *function, semantic, compact_options.max_bytes);
        return is_complete(*opened.session) && semantic.complete
            ? exit_success : exit_partial;
    }
    if (view_name == "json") {
        const std::string rendered = airece::render_semantic_json(
            semantic, enrich ? &enrichment : nullptr, compact_options.max_bytes);
        if (rendered.empty()) {
            std::cerr << "airece: JSON byte budget is too small; at least 2 bytes "
                         "are required for a valid document\n";
            return exit_failure;
        }
        std::cout << rendered;
        const bool minimal_budget_document = rendered == "{}" || rendered == "{}\n";
        return !minimal_budget_document && is_complete(*opened.session) && semantic.complete &&
            (!enrich || enrichment.completion == airece::EnrichmentCompletion::complete)
            ? exit_success : exit_partial;
    }
    const airece::RenderedSemanticText rendered = view_name == "pseudo"
        ? airece::render_pseudo(semantic, compact_options)
        : airece::render_compact(semantic, compact_options);
    std::cout << rendered.text;
    return is_complete(*opened.session) && semantic.complete && !rendered.truncated &&
        (!enrich || enrichment.completion == airece::EnrichmentCompletion::complete)
        ? exit_success : exit_partial;
}

int calls_command(const int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "airece: calls requires a binary path\n";
        return exit_usage;
    }
    std::uint64_t address = 0;
    int first_option = 3;
    bool filtered = false;
    if (argc > 3 && std::string_view(argv[3]).starts_with("--") == false) {
        if (!parse_address(argv[3], address)) {
            std::cerr << "airece: invalid function address: " << argv[3] << '\n';
            return exit_usage;
        }
        filtered = true;
        first_option = 4;
    }
    airece::AnalysisOptions options;
    if (!parse_analysis_options(argc, argv, first_option, options)) return exit_usage;
    if (filtered) options.manual_roots.push_back(address);
    const auto opened = airece::AnalysisSession::open(argv[2], options);
    if (!opened) return report_open_failure(opened.diagnostic);
    const airece::FunctionInfo* owner = filtered
        ? opened.session->function_by_address(address) : nullptr;
    if (filtered && owner == nullptr) {
        std::cerr << "airece: no function contains requested address\n";
        return exit_failure;
    }
    for (const airece::CallSiteInfo& call : opened.session->call_sites()) {
        if (owner != nullptr && call.owner != owner->id) continue;
        print_hex(call.address);
        std::cout << " owner=" << call.owner << " target=";
        if (!call.import_name.empty()) std::cout << call.import_module << '!' << call.import_name;
        else if (call.import_ordinal != 0) std::cout << call.import_module << "!#" << call.import_ordinal;
        else { print_hex(call.target); }
        if (const airece::ApiModel* model = airece::find_api_model(
                call.import_module, call.import_name, call.import_ordinal)) {
            std::cout << " model=" << model->module << '!' << model->name
                      << '@' << airece::api_model_set_version
                      << " effects=" << airece::describe_api_effects(*model)
                      << " taint=" << airece::api_taint_role_name(model->taint);
        }
        std::cout << '\n';
    }
    return is_complete(*opened.session) ? exit_success : exit_partial;
}

int xrefs_command(const int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "airece: xrefs requires a binary path and address\n";
        return exit_usage;
    }
    std::uint64_t address = 0;
    if (!parse_address(argv[3], address)) return exit_usage;
    airece::AnalysisOptions options;
    if (!parse_analysis_options(argc, argv, 4, options)) return exit_usage;
    const auto opened = airece::AnalysisSession::open(argv[2], options);
    if (!opened) return report_open_failure(opened.diagnostic);
    std::size_t found = 0;
    std::set<std::string> emitted_keys;
    for (const airece::CallSiteInfo& call : opened.session->call_sites()) {
        if (call.target != address) continue;
        std::cout << "call 0x" << std::hex << call.address << std::dec
                  << " owner=" << call.owner << " -> 0x" << std::hex << address << std::dec << '\n';
        ++found;
        emitted_keys.insert("call:" + std::to_string(call.address));
    }
    for (std::size_t edge_index = 0;
         edge_index < xair_cfg_edge_count(&opened.session->cfg()); ++edge_index) {
        const xair_cfg_edge* edge = xair_cfg_get_edge(
            &opened.session->cfg(), static_cast<xair_cfg_edge_id>(edge_index));
        if (edge == nullptr || edge->raw_target != address ||
            edge->kind == XAIR_EDGE_CALL || edge->kind == XAIR_EDGE_CALL_RETURN) continue;
        const xair_cfg_node* source = xair_cfg_get_node(&opened.session->cfg(), edge->src);
        if (source == nullptr) continue;
        const std::string key = "code:" + std::to_string(source->start) + ':' +
            std::to_string(edge->kind);
        if (!emitted_keys.insert(key).second) continue;
        std::cout << "code 0x" << std::hex << source->start << std::dec <<
            " edge=" << edge_index << " kind=" << xair_cfg_edge_kind_name(edge->kind) <<
            " -> 0x" << std::hex << address << std::dec << '\n';
        ++found;
    }
    struct OperationContext {
        std::uint64_t function{};
        std::uint64_t address{};
    };
    std::unordered_map<xair_op_id, OperationContext> operation_context;
    for (const airece::FunctionInfo& function : opened.session->functions()) {
        std::size_t node_count = 0;
        const xair_cfg_node_id* nodes = xair_cfg_function_nodes(
            &opened.session->cfg(), function.id, &node_count);
        for (std::size_t node_index = 0; node_index < node_count; ++node_index) {
            const xair_cfg_node* node = xair_cfg_get_node(
                &opened.session->cfg(), nodes[node_index]);
            if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
            const xair_op_id* operations = nullptr;
            std::size_t operation_count = 0;
            if (xair_block_ops(opened.session->module(), node->ir_block,
                    &operations, &operation_count) != XAIR_OK) continue;
            for (std::size_t operation_index = 0;
                 operation_index < operation_count; ++operation_index) {
                std::uint64_t operation_va = node->start;
                const xair_source_id* sources = nullptr;
                std::size_t source_count = 0;
                if (xair_op_sources(opened.session->module(), operations[operation_index],
                        &sources, &source_count) == XAIR_OK) {
                    for (std::size_t source_index = 0;
                         source_index < source_count; ++source_index) {
                        xair_source_record source{};
                        if (xair_module_get_source(opened.session->module(),
                                sources[source_index], &source) == XAIR_OK &&
                            source.location.instruction_va != 0) {
                            operation_va = source.location.instruction_va;
                            break;
                        }
                    }
                }
                operation_context.emplace(
                    operations[operation_index], OperationContext{function.entry, operation_va});
            }
        }
    }
    for (xair_value_id value = 0;
         value < xair_module_value_count(opened.session->module()); ++value) {
        xair_op_id definition = XAIR_INVALID_ID;
        std::uint64_t low = 0;
        std::uint64_t high = 0;
        if (xair_value_definition(opened.session->module(), value, &definition) != XAIR_OK ||
            definition == XAIR_INVALID_ID ||
            xair_op_immediate_wide(opened.session->module(), definition, &low, &high) != XAIR_OK ||
            high != 0 || low != address) continue;
        std::size_t use_count = 0;
        (void)xair_value_uses(opened.session->module(), value, nullptr, 0, &use_count);
        std::vector<xair_op_id> uses(use_count);
        if (use_count != 0 && xair_value_uses(opened.session->module(), value,
                uses.data(), uses.size(), &use_count) != XAIR_OK) continue;
        for (const xair_op_id use : uses) {
            const auto context = operation_context.find(use);
            if (context == operation_context.end()) continue;
            const std::string key = "data:" + std::to_string(use) + ':' +
                std::to_string(value);
            if (!emitted_keys.insert(key).second) continue;
            xair_op_view_v3 operation{};
            if (xair_module_get_op_v3(opened.session->module(), use, &operation) != XAIR_OK) {
                continue;
            }
            std::cout << "data 0x" << std::hex << context->second.address << std::dec <<
                " fn=0x" << std::hex << context->second.function << std::dec <<
                " op" << use << ' ' << xair_opcode_name(operation.opcode) <<
                " uses=v" << value << " -> 0x" << std::hex << address << std::dec << '\n';
            ++found;
        }
    }
    if (found == 0) std::cout << "no-xrefs 0x" << std::hex << address << std::dec << '\n';
    return is_complete(*opened.session) ? exit_success : exit_partial;
}

int evidence_command(const int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "airece: evidence requires a binary path and statement id\n";
        return exit_usage;
    }
    const std::string wanted = argv[3];
    airece::AnalysisOptions options;
    if (!parse_analysis_options(argc, argv, 4, options)) return exit_usage;
    const auto opened = airece::AnalysisSession::open(argv[2], options);
    if (!opened) return report_open_failure(opened.diagnostic);
    std::size_t matches = 0;
    airece::CompactOptions compact;
    compact.max_statements = 0;
    compact.max_evidence = 0;
    for (const airece::FunctionInfo& function : opened.session->functions()) {
        const auto view = opened.session->compact_view(function.id, compact);
        for (const auto& statement : view.statements) {
            if (statement.stable_id != wanted) continue;
            const auto evidence = std::find_if(view.evidence.begin(), view.evidence.end(),
                [&](const airece::SemanticEvidence& item) { return item.stable_id == statement.evidence_id; });
            std::cout << "fn=0x" << std::hex << function.entry << std::dec
                      << " statement=" << statement.stable_id << " kind="
                      << airece::semantic_statement_kind_name(statement.kind)
                      << " address=0x" << std::hex << statement.address << std::dec;
            if (evidence != view.evidence.end()) {
                std::cout << " evidence=" << evidence->stable_id << " range=0x" << std::hex
                          << evidence->begin << "-0x" << evidence->end << std::dec << " ops=";
                for (std::size_t index = 0; index < evidence->operations.size(); ++index) {
                    if (index != 0) std::cout << ',';
                    std::cout << evidence->operations[index];
                }
            }
            std::cout << " text=" << statement.text << '\n';
            ++matches;
        }
    }
    if (matches == 0) {
        std::cerr << "airece: statement id not found: " << wanted << '\n';
        return exit_failure;
    }
    return is_complete(*opened.session) ? exit_success : exit_partial;
}

int slice_command(const int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "airece: slice requires a binary path and address or statement id\n";
        return exit_usage;
    }
    const std::string target = argv[3];
    std::uint64_t address = 0;
    const bool by_statement = target.find(":S:") != std::string::npos ||
        (!target.empty() && (target[0] == 'S' || target[0] == 's'));
    if (!by_statement && !parse_address(target, address)) return exit_usage;
    airece::AnalysisOptions options;
    if (!parse_analysis_options(argc, argv, 4, options)) return exit_usage;
    const auto opened = airece::AnalysisSession::open(argv[2], options);
    if (!opened) return report_open_failure(opened.diagnostic);
    airece::CompactOptions compact;
    compact.max_statements = 0;
    compact.max_evidence = 0;
    std::size_t emitted = 0;
    for (const auto& function : opened.session->functions()) {
        if (!by_statement && (address < function.range_start || address >= function.range_end)) continue;
        const auto view = opened.session->compact_view(function.id, compact);
        const auto seed = std::find_if(view.statements.begin(), view.statements.end(),
            [&](const airece::SemanticStatement& statement) {
                return by_statement ? statement.stable_id == target : statement.address == address;
            });
        if (seed == view.statements.end()) continue;
        struct OrderedOperation {
            xair_op_id id{XAIR_INVALID_ID};
            xair_block_id block{XAIR_INVALID_ID};
            std::uint64_t address{};
        };
        std::vector<OrderedOperation> ordered;
        std::unordered_map<xair_op_id, std::size_t> positions;
        std::unordered_map<xair_block_id, std::size_t> block_last_position;
        std::unordered_set<xair_block_id> function_blocks;
        const auto operation_address = [&](const xair_op_id operation) {
            const xair_source_id* sources = nullptr;
            std::size_t source_count = 0;
            if (xair_op_sources(opened.session->module(), operation,
                    &sources, &source_count) != XAIR_OK) return UINT64_C(0);
            for (std::size_t index = 0; index < source_count; ++index) {
                xair_source_record source{};
                if (xair_module_get_source(opened.session->module(), sources[index],
                        &source) == XAIR_OK && source.location.instruction_va != 0) {
                    return source.location.instruction_va;
                }
            }
            return UINT64_C(0);
        };
        for (const xair_cfg_node_id node_id : view.control.block_order) {
            const xair_cfg_node* node = xair_cfg_get_node(&opened.session->cfg(), node_id);
            if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
            function_blocks.insert(node->ir_block);
            const xair_op_id* operations = nullptr;
            std::size_t operation_count = 0;
            if (xair_block_ops(opened.session->module(), node->ir_block,
                    &operations, &operation_count) != XAIR_OK) continue;
            for (std::size_t index = 0; index < operation_count; ++index) {
                positions[operations[index]] = ordered.size();
                ordered.push_back({operations[index], node->ir_block,
                                   operation_address(operations[index])});
                block_last_position[node->ir_block] = ordered.size() - 1;
            }
        }
        std::size_t seed_position = ordered.empty() ? 0 : ordered.size() - 1;
        bool have_seed_position = false;
        for (const xair_op_id operation : seed->operations) {
            const auto found = positions.find(operation);
            if (found != positions.end()) {
                seed_position = have_seed_position
                    ? std::max(seed_position, found->second) : found->second;
                have_seed_position = true;
            }
        }
        if (!have_seed_position) {
            const auto found = block_last_position.find(seed->block);
            if (found != block_last_position.end()) {
                seed_position = found->second;
                have_seed_position = true;
            }
        }
        if (!by_statement) {
            for (std::size_t index = 0; index < ordered.size(); ++index) {
                if (ordered[index].address == address) {
                    seed_position = index;
                    have_seed_position = true;
                }
            }
        }
        std::unordered_map<xair_value_id, std::vector<xair_value_id>> incoming;
        for (const xair_block_id block : function_blocks) {
            xair_term_view term{};
            if (xair_block_terminator(opened.session->module(), block, &term) != XAIR_OK) {
                continue;
            }
            const auto record_edge = [&](const xair_block_id destination,
                                         const xair_value_id* arguments,
                                         const std::size_t argument_count) {
                if (!function_blocks.contains(destination) || arguments == nullptr) return;
                const std::size_t parameter_count =
                    xair_block_param_count(opened.session->module(), destination);
                const std::size_t count = std::min(parameter_count, argument_count);
                for (std::size_t index = 0; index < count; ++index) {
                    xair_value_id parameter = XAIR_INVALID_ID;
                    if (xair_block_param_value(opened.session->module(), destination,
                            index, &parameter) == XAIR_OK) {
                        incoming[parameter].push_back(arguments[index]);
                    }
                }
            };
            record_edge(term.true_target, term.true_args, term.true_arg_count);
            record_edge(term.false_target, term.false_args, term.false_arg_count);
        }
        std::vector<xair_value_id> worklist(seed->values.begin(), seed->values.end());
        std::unordered_set<xair_value_id> visited_values;
        std::unordered_set<xair_op_id> selected_operations;
        for (const xair_op_id operation : seed->operations) {
            selected_operations.insert(operation);
            const xair_value_id* inputs = nullptr;
            std::size_t input_count = 0;
            if (xair_op_inputs(opened.session->module(), operation,
                    &inputs, &input_count) == XAIR_OK) {
                worklist.insert(worklist.end(), inputs, inputs + input_count);
            }
        }
        while (!worklist.empty()) {
            const xair_value_id value = worklist.back();
            worklist.pop_back();
            if (!visited_values.insert(value).second) continue;
            const auto parameter = incoming.find(value);
            if (parameter != incoming.end()) {
                worklist.insert(worklist.end(), parameter->second.begin(),
                                parameter->second.end());
            }
            xair_op_id definition = XAIR_INVALID_ID;
            if (xair_value_definition(opened.session->module(), value, &definition) != XAIR_OK ||
                definition == XAIR_INVALID_ID) continue;
            const auto position = positions.find(definition);
            if (position == positions.end() ||
                (have_seed_position && position->second > seed_position)) continue;
            if (!selected_operations.insert(definition).second) continue;
            const xair_value_id* inputs = nullptr;
            std::size_t input_count = 0;
            if (xair_op_inputs(opened.session->module(), definition,
                    &inputs, &input_count) == XAIR_OK) {
                worklist.insert(worklist.end(), inputs, inputs + input_count);
            }
        }
        std::cout << "slice fn=0x" << std::hex << function.entry << std::dec <<
            " seed=" << seed->stable_id << " evidence=" << seed->evidence_id << '\n';
        ++emitted;
        for (std::size_t position = 0; position < ordered.size(); ++position) {
            const OrderedOperation& item = ordered[position];
            if (!selected_operations.contains(item.id) ||
                (have_seed_position && position > seed_position)) continue;
            xair_op_view_v3 operation{};
            const xair_value_id* inputs = nullptr;
            const xair_value_id* results = nullptr;
            std::size_t input_count = 0;
            std::size_t result_count = 0;
            if (xair_module_get_op_v3(opened.session->module(), item.id, &operation) != XAIR_OK) {
                continue;
            }
            (void)xair_op_inputs(opened.session->module(), item.id, &inputs, &input_count);
            (void)xair_op_results(opened.session->module(), item.id, &results, &result_count);
            std::cout << "  op" << item.id << ' ' << xair_opcode_name(operation.opcode);
            if (item.address != 0) std::cout << " @0x" << std::hex << item.address << std::dec;
            std::cout << " in=[";
            for (std::size_t index = 0; index < input_count; ++index) {
                if (index != 0) std::cout << ',';
                std::cout << 'v' << inputs[index];
            }
            std::cout << "] out=[";
            for (std::size_t index = 0; index < result_count; ++index) {
                if (index != 0) std::cout << ',';
                std::cout << 'v' << results[index];
            }
            std::cout << "]\n";
            ++emitted;
        }
    }
    if (emitted == 0) {
        std::cerr << "airece: slice target not found\n";
        return exit_failure;
    }
    return is_complete(*opened.session) ? exit_success : exit_partial;
}

int taint_command(const int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "airece: taint requires a binary path and function address\n";
        return exit_usage;
    }
    std::uint64_t address = 0;
    if (!parse_address(argv[3], address)) return exit_usage;
    airece::AnalysisOptions analysis;
    airece::EnrichmentOptions enrichment;
    enrichment.taint = true;
    if (!parse_analysis_options(argc, argv, 4, analysis, nullptr, nullptr, nullptr, nullptr,
            &enrichment)) return exit_usage;
    analysis.manual_roots.push_back(address);
    const auto opened = airece::AnalysisSession::open(argv[2], analysis);
    if (!opened) return report_open_failure(opened.diagnostic);
    const auto* function = opened.session->function_by_address(address);
    if (function == nullptr) return exit_failure;
    const auto base = opened.session->compact_view(function->id);
    airece::SessionDiagnostic diagnostic;
    auto* context = opened.session->symbolic_context(&diagnostic);
    if (context == nullptr) return report_open_failure(diagnostic);
    const auto result = airece::enrich_function(opened.session->cfg(), *opened.session->module(),
        opened.session->binary(), function->id, *context, base, enrichment);
    std::cout << "completion=" << airece::enrichment_completion_name(result.completion)
              << " states=" << result.states << " solver="
              << (result.solver_initialized ? "initialized" : "not-initialized") << '\n';
    for (const auto& finding : result.taint) {
        std::cout << finding.kind;
        if (!finding.source.empty()) std::cout << " source=" << finding.source;
        if (!finding.sink.empty()) std::cout << " sink=" << finding.sink;
        if (!finding.transform.empty()) std::cout << " transform=" << finding.transform;
        if (!finding.guard.empty()) std::cout << " guard=" << finding.guard;
        std::cout << " evidence=" << finding.evidence_id << " taint=" << finding.taint << '\n';
    }
    return is_complete(*opened.session) && result.completion == airece::EnrichmentCompletion::complete
        ? exit_success : exit_partial;
}

int flow_command(const int argc, char** argv) {
    if (argc < 7) {
        std::cerr << "airece: flow requires a binary, at least one --source, and at least one --target\n";
        return exit_usage;
    }
    airece::AnalysisOptions analysis;
    airece::FlowOptions flow;
    flow.cancellation = global_cancel_token;
    std::vector<airece::FlowPointSelector> sources;
    std::vector<airece::FlowPointSelector> targets;
    std::vector<char*> analysis_arguments{argv[0], argv[1], argv[2]};
    bool json = false;
    for (int index = 3; index < argc; ++index) {
        const std::string_view option{argv[index]};
        if (option == "--json") {
            json = true;
            continue;
        }
        const bool flow_value_option = option == "--source" || option == "--target" ||
            option == "--mode" || option == "--function-depth" ||
            option == "--max-states" || option == "--max-queries" ||
            option == "--max-paths" || option == "--max-taint-bytes" ||
            option == "--max-symbolic-bytes" || option == "--symbolic-timeout-ms";
        if (!flow_value_option) {
            analysis_arguments.push_back(argv[index]);
            if (option != "--no-ir" && option != "--no-indirects") {
                if (index + 1 >= argc) {
                    std::cerr << "airece: missing value for " << option << '\n';
                    return exit_usage;
                }
                analysis_arguments.push_back(argv[++index]);
            }
            continue;
        }
        if (index + 1 >= argc) {
            std::cerr << "airece: missing value for " << option << '\n';
            return exit_usage;
        }
        const std::string_view value{argv[++index]};
        if (option == "--source" || option == "--target") {
            airece::FlowPointSelector selector;
            std::string diagnostic;
            const bool target = option == "--target";
            if (!airece::parse_flow_point(value, target, selector, diagnostic)) {
                std::cerr << "airece: invalid " << option.substr(2) << " selector: "
                          << diagnostic << '\n';
                return exit_usage;
            }
            (target ? targets : sources).push_back(std::move(selector));
        } else if (option == "--mode") {
            if (value == "taint") flow.mode = airece::FlowMode::taint;
            else if (value == "taint-symbolic") {
                flow.mode = airece::FlowMode::taint_symbolic;
            } else if (value == "symbolic") flow.mode = airece::FlowMode::symbolic;
            else {
                std::cerr << "airece: invalid flow mode: " << value << '\n';
                return exit_usage;
            }
        } else if (option == "--function-depth") {
            if (!assign_size(option, value, flow.function_depth)) return exit_usage;
        } else if (option == "--max-states") {
            if (!assign_size(option, value, flow.max_states)) return exit_usage;
        } else if (option == "--max-queries") {
            if (!assign_size(option, value, flow.max_queries)) return exit_usage;
        } else if (option == "--max-paths") {
            if (!assign_size(option, value, flow.max_paths)) return exit_usage;
        } else if (option == "--max-taint-bytes") {
            if (!assign_size(option, value, flow.max_taint_bytes)) return exit_usage;
        } else if (option == "--max-symbolic-bytes") {
            if (!assign_size(option, value, flow.max_symbolic_bytes)) return exit_usage;
        } else if (option == "--symbolic-timeout-ms") {
            if (!assign_u64(option, value, flow.max_time_ms)) return exit_usage;
        }
    }
    if (sources.empty() || targets.empty()) {
        std::cerr << "airece: flow requires at least one --source and --target\n";
        return exit_usage;
    }
    if (!parse_analysis_options(static_cast<int>(analysis_arguments.size()),
            analysis_arguments.data(), 3, analysis)) return exit_usage;
    const auto opened = airece::AnalysisSession::open(argv[2], analysis);
    if (!opened) return report_open_failure(opened.diagnostic);
    const auto result = airece::directed_flow(*opened.session, sources, targets, flow);
    if (json) std::cout << airece::render_flow_json(result);
    else std::cout << airece::render_flow_text(result);
    if (result.completion == airece::FlowCompletion::failed) return exit_failure;
    return result.completion == airece::FlowCompletion::complete
        ? exit_success : exit_partial;
}

int path_command(const int argc, char** argv) {
    if (argc < 7) {
        std::cerr << "airece: path requires --from <address> --to <address>\n";
        return exit_usage;
    }
    std::uint64_t from = 0, to = 0;
    std::vector<char*> filtered{argv[0], argv[1], argv[2]};
    for (int index = 3; index < argc; ++index) {
        const std::string_view option{argv[index]};
        if ((option == "--from" || option == "--to") && index + 1 < argc) {
            std::uint64_t value = 0;
            if (!parse_address(argv[++index], value)) return exit_usage;
            if (option == "--from") from = value; else to = value;
        } else filtered.push_back(argv[index]);
    }
    if (from == 0 || to == 0) return exit_usage;
    airece::AnalysisOptions options;
    airece::EnrichmentOptions enrichment;
    if (!parse_analysis_options(static_cast<int>(filtered.size()), filtered.data(), 3,
            options, nullptr, nullptr, nullptr, nullptr, &enrichment)) return exit_usage;
    const auto opened = airece::AnalysisSession::open(argv[2], options);
    if (!opened) return report_open_failure(opened.diagnostic);
    const xair_cfg_node_id start = xair_cfg_find_node_containing(&opened.session->cfg(), from);
    const xair_cfg_node_id goal = xair_cfg_find_node_containing(&opened.session->cfg(), to);
    if (start == XAIR_CFG_INVALID_ID || goal == XAIR_CFG_INVALID_ID) {
        std::cerr << "airece: path endpoint is outside the recovered CFG\n";
        return exit_failure;
    }
    std::queue<xair_cfg_node_id> queue;
    std::vector<xair_cfg_node_id> parent(xair_cfg_node_count(&opened.session->cfg()), XAIR_CFG_INVALID_ID);
    queue.push(start); parent[start] = start;
    std::size_t visited = 0;
    const auto path_started = std::chrono::steady_clock::now();
    while (!queue.empty() && parent[goal] == XAIR_CFG_INVALID_ID &&
           (enrichment.max_states == 0 || visited < enrichment.max_states) &&
           !xair_cancel_token_requested(global_cancel_token) &&
           (enrichment.max_time_ms == 0 ||
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - path_started).count() <
                static_cast<std::int64_t>(enrichment.max_time_ms))) {
        const auto node = queue.front(); queue.pop(); ++visited;
        std::size_t edge_count = 0;
        const xair_cfg_edge* edges = xair_cfg_node_edges(&opened.session->cfg(), node, &edge_count);
        for (std::size_t index = 0; index < edge_count; ++index) {
            if (edges[index].dst == XAIR_CFG_INVALID_ID || edges[index].dst >= parent.size() ||
                parent[edges[index].dst] != XAIR_CFG_INVALID_ID) continue;
            parent[edges[index].dst] = node;
            queue.push(edges[index].dst);
        }
    }
    if (parent[goal] == XAIR_CFG_INVALID_ID) {
        std::cout << "path unknown from=0x" << std::hex << from << " to=0x" << to << std::dec
                  << " visited=" << visited << " reason="
                  << (enrichment.max_states != 0 && visited >= enrichment.max_states
                        ? "state-budget" :
                     xair_cancel_token_requested(global_cancel_token)
                        ? "canceled" : "unreachable-or-time-budget") << '\n';
        return exit_partial;
    }
    std::vector<xair_cfg_node_id> path;
    for (auto node = goal;; node = parent[node]) {
        path.push_back(node);
        if (node == start) break;
    }
    std::reverse(path.begin(), path.end());
    std::cout << "path";
    for (const auto node : path) {
        const auto* item = xair_cfg_get_node(&opened.session->cfg(), node);
        std::cout << " n" << node;
        if (item != nullptr) std::cout << "@0x" << std::hex << item->start << std::dec;
    }
    std::cout << '\n';
    return is_complete(*opened.session) ? exit_success : exit_partial;
}

} // namespace

int main(const int argc, char** argv) {
    const CancelTokenGuard cancellation;
    if (argc == 1) {
        print_help();
        return exit_success;
    }
    const std::string_view argument{argv[1]};
    if (argument == "--version" || argument == "version") {
        if (argc != 2) {
            std::cerr << "airece: --version does not accept arguments\n";
            return exit_usage;
        }
        std::cout << airece::version_text();
        return exit_success;
    }
    if (argument == "--help" || argument == "-h" || argument == "help") {
        print_help();
        return exit_success;
    }
    if (argument == "inspect" || argument == "functions") {
        return analyze_command(argc, argv);
    }
    if (argument == "expr") return expression_command(argc, argv);
    if (argument == "vars") return variables_command(argc, argv);
    if (argument == "fn") return function_command(argc, argv);
    if (argument == "calls") return calls_command(argc, argv);
    if (argument == "xrefs") return xrefs_command(argc, argv);
    if (argument == "slice") return slice_command(argc, argv);
    if (argument == "taint") return taint_command(argc, argv);
    if (argument == "flow") return flow_command(argc, argv);
    if (argument == "path") return path_command(argc, argv);
    if (argument == "evidence") return evidence_command(argc, argv);
    std::cerr << "airece: unsupported command; use --help\n";
    return exit_usage;
}
