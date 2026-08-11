#include <airece/session/analysis_session.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>

namespace airece {
namespace {

std::string ascii_lower(const std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const unsigned char character : value) {
        result.push_back(static_cast<char>(std::tolower(character)));
    }
    return result;
}

std::string import_key(const std::string_view module, const std::string_view name) {
    return ascii_lower(module) + "!" + ascii_lower(name);
}

std::string ordinal_key(const std::string_view module, const std::uint32_t ordinal) {
    return ascii_lower(module) + "!#" + std::to_string(ordinal);
}

xair_cfg_profile raw_profile(const AnalysisProfile profile) {
    switch (profile) {
    case AnalysisProfile::fast:
        return XAIR_CFG_PROFILE_FAST;
    case AnalysisProfile::exhaustive:
        return XAIR_CFG_PROFILE_EXHAUSTIVE;
    case AnalysisProfile::balanced:
    default:
        return XAIR_CFG_PROFILE_BALANCED;
    }
}

void apply_analysis_options(
    xair_analysis_options& target,
    const AnalysisOptions& source) {
    if (source.max_input_bytes != 0) target.max_bytes = source.max_input_bytes;
    if (source.max_segments != 0) target.max_segments = source.max_segments;
    if (source.max_symbols != 0) target.max_symbols = source.max_symbols;
    if (source.max_functions != 0) target.max_functions = source.max_functions;
    if (source.max_blocks != 0) target.max_blocks = source.max_blocks;
    if (source.max_edges != 0) target.max_edges = source.max_edges;
    if (source.max_ir_values != 0) target.max_ir_values = source.max_ir_values;
    if (source.max_memory_bytes != 0) target.max_memory = source.max_memory_bytes;
    if (source.max_wall_time_ms != 0) target.max_wall_time = source.max_wall_time_ms;
    target.cancel_token = source.cancellation;
    target.progress_callback = source.progress;
    target.progress_user = source.progress_user;
}

SessionDiagnostic copy_diagnostic(
    const xair_status status,
    const xair_diagnostic& diagnostic,
    const std::string_view fallback) {
    SessionDiagnostic result;
    result.status = status;
    result.stage = diagnostic.stage;
    result.address = diagnostic.address;
    if (diagnostic.message != nullptr && diagnostic.message[0] != '\0') {
        result.message = diagnostic.message;
    } else {
        result.message = fallback.empty() ? xair_status_name(status) : std::string(fallback);
    }
    return result;
}

class DeadlineWatchdog {
public:
    DeadlineWatchdog(xair_cancel_token* token, const std::uint64_t timeout_ms)
        : token_(token) {
        if (token_ == nullptr || timeout_ms == 0) return;
        worker_ = std::thread([this, timeout_ms] {
            std::unique_lock lock(mutex_);
            if (!condition_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                     [this] { return finished_; })) {
                xair_cancel_token_request(token_);
            }
        });
    }
    ~DeadlineWatchdog() {
        {
            const std::scoped_lock lock(mutex_);
            finished_ = true;
        }
        condition_.notify_one();
        if (worker_.joinable()) worker_.join();
    }
    DeadlineWatchdog(const DeadlineWatchdog&) = delete;
    DeadlineWatchdog& operator=(const DeadlineWatchdog&) = delete;

private:
    xair_cancel_token* token_{};
    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool finished_{};
};

} // namespace

struct AnalysisSession::Indexes {
    std::unordered_map<std::uint64_t, std::size_t> entries;
    std::unordered_map<std::string, std::vector<std::size_t>> names;
    std::unordered_map<std::uint64_t, std::size_t> call_sites;
    std::unordered_map<std::string, std::vector<std::size_t>> imports;
};

const char* semantic_coverage_name(
    const xair_cfg_semantic_coverage coverage) noexcept {
    switch (coverage) {
    case XAIR_CFG_SEMANTICS_EXACT:
        return "exact";
    case XAIR_CFG_SEMANTICS_PARTIAL:
        return "partial";
    case XAIR_CFG_SEMANTICS_OPAQUE:
    default:
        return "opaque";
    }
}

AnalysisSession::AnalysisSession(
    std::filesystem::path path,
    AnalysisOptions options)
    : path_(std::move(path)), options_(options), indexes_(std::make_unique<Indexes>()) {
    if (options_.max_wall_time_ms != 0 && options_.cancellation == nullptr &&
        xair_cancel_token_create(&owned_cancellation_) == XAIR_OK) {
        options_.cancellation = owned_cancellation_;
    }
}

AnalysisSession::~AnalysisSession() {
    if (symbolic_context_ != nullptr) {
        xair_sym_context_destroy(symbolic_context_);
    }
    compact_recovery_.reset();
    variable_recovery_.reset();
    expression_recovery_.reset();
    if (cfg_ != nullptr) {
        xair_cfg_destroy(cfg_);
    }
    if (binary_loaded_) {
        xair_binary_view_destroy(&binary_);
    }
    if (owned_cancellation_ != nullptr) {
        xair_cancel_token_destroy(owned_cancellation_);
    }
}

SessionOpenResult AnalysisSession::open(
    const std::filesystem::path& path,
    const AnalysisOptions& options) {
    SessionOpenResult result;
    auto session = std::unique_ptr<AnalysisSession>(
        new AnalysisSession(path, options));
    DeadlineWatchdog watchdog(
        const_cast<xair_cancel_token*>(session->options_.cancellation),
        session->options_.max_wall_time_ms);
    xair_binary_load_options load_options{};
    xair_binary_load_options_init(&load_options);
    apply_analysis_options(load_options.analysis, options);
    xair_diagnostic diagnostic{};
    const std::string path_text = path.string();
    const xair_status load_status = xair_binary_view_load_path_ex(
        path_text.c_str(), &load_options, &session->binary_,
        &session->loader_result_, &diagnostic);
    if (load_status != XAIR_OK) {
        result.diagnostic = copy_diagnostic(load_status, diagnostic, "binary loading failed");
        return result;
    }
    session->binary_loaded_ = true;
    session->decode_cache_ = std::make_unique<DecodeCache>(session->binary_);
    xair_status status = session->build_cfg(result.diagnostic);
    if (status != XAIR_OK) {
        session->completeness_.loader_state = session->loader_result_.state;
        session->completeness_.cfg_state = session->cfg_result_.state;
        session->completeness_.reason = status;
        result.partial_session = std::move(session);
        return result;
    }
    status = session->build_inventory(result.diagnostic);
    if (status != XAIR_OK) return result;
    result.session = std::move(session);
    return result;
}

SessionOpenResult AnalysisSession::open_bytes(
    const std::span<const std::byte> bytes,
    std::string source_name,
    const AnalysisOptions& options) {
    SessionOpenResult result;
    auto session = std::unique_ptr<AnalysisSession>(new AnalysisSession(
        std::filesystem::path(std::move(source_name)), options));
    DeadlineWatchdog watchdog(
        const_cast<xair_cancel_token*>(session->options_.cancellation),
        session->options_.max_wall_time_ms);
    xair_binary_load_options load_options{};
    xair_binary_load_options_init(&load_options);
    apply_analysis_options(load_options.analysis, options);
    xair_diagnostic diagnostic{};
    const xair_status load_status = xair_binary_view_load_bytes_ex(
        bytes.data(), bytes.size(), &load_options, &session->binary_,
        &session->loader_result_, &diagnostic);
    if (load_status != XAIR_OK) {
        result.diagnostic = copy_diagnostic(load_status, diagnostic, "binary loading failed");
        return result;
    }
    session->binary_loaded_ = true;
    session->decode_cache_ = std::make_unique<DecodeCache>(session->binary_);
    xair_status status = session->build_cfg(result.diagnostic);
    if (status != XAIR_OK) {
        session->completeness_.loader_state = session->loader_result_.state;
        session->completeness_.cfg_state = session->cfg_result_.state;
        session->completeness_.reason = status;
        result.partial_session = std::move(session);
        return result;
    }
    status = session->build_inventory(result.diagnostic);
    if (status != XAIR_OK) return result;
    result.session = std::move(session);
    return result;
}

xair_status AnalysisSession::build_cfg(SessionDiagnostic& diagnostic) {
    xair_cfg_options cfg_options{};
    xair_cfg_options_init(&cfg_options, raw_profile(options_.profile));
    apply_analysis_options(cfg_options.analysis, options_);
    cfg_options.arch = binary_.arch;
    cfg_options.entry = binary_.entry;
    cfg_options.decoder = XAIR_CFG_DECODER_ZYDIS;
    if (options_.max_blocks != 0) {
        cfg_options.max_blocks = static_cast<std::uint32_t>(std::min<std::size_t>(
            options_.max_blocks, std::numeric_limits<std::uint32_t>::max()));
    }
    if (options_.max_block_bytes != 0) cfg_options.max_block_bytes = options_.max_block_bytes;
    if (options_.max_roots != 0) cfg_options.max_roots = options_.max_roots;
    if (options_.max_indirect_candidates_per_edge != 0) {
        cfg_options.max_indirect_candidates_per_edge =
            options_.max_indirect_candidates_per_edge;
    }
    if (options_.max_indirect_candidate_edges != 0) {
        cfg_options.max_indirect_candidate_edges =
            options_.max_indirect_candidate_edges;
    }
    if (!options_.build_ir) cfg_options.flags |= XAIR_CFG_BUILD_SKIP_IR;
    if (!options_.expand_indirects) {
        cfg_options.flags |= XAIR_CFG_BUILD_SKIP_INDIRECT_EXPANSION;
    }
    if (!options_.analyze_indirects) {
        cfg_options.flags |= XAIR_CFG_BUILD_SKIP_INDIRECT_ANALYSIS;
    }

    xair_cfg_builder* builder = nullptr;
    xair_status status = xair_cfg_builder_create(&binary_, &cfg_options, &builder);
    if (status != XAIR_OK) {
        diagnostic = {status, XAIR_STAGE_CFG, binary_.entry,
                      "CFG builder creation failed"};
        return status;
    }
    status = xair_cfg_add_root(builder, binary_.entry);
    for (const std::uint64_t root : options_.manual_roots) {
        if (status != XAIR_OK) break;
        if (root == 0 || root == binary_.entry) continue;
        status = xair_cfg_add_root(builder, root);
    }
    if (status == XAIR_OK) {
        xair_diagnostic raw_diagnostic{};
        status = xair_cfg_build_ex(
            builder, &cfg_, &cfg_stats_, &cfg_result_, &raw_diagnostic);
        if (status != XAIR_OK) {
            diagnostic = copy_diagnostic(status, raw_diagnostic, "CFG construction failed");
        }
    } else {
        diagnostic = {status, XAIR_STAGE_CFG, binary_.entry,
                      "CFG root creation failed"};
    }
    xair_cfg_builder_destroy(builder);
    if (status != XAIR_OK) return status;

    module_ = xair_cfg_module(cfg_);
    if (options_.build_ir && module_ != nullptr) {
        xair_error verify_error{};
        status = xair_verify_module(module_, &verify_error);
        if (status != XAIR_OK) {
            diagnostic.status = status;
            diagnostic.stage = XAIR_STAGE_VERIFY;
            diagnostic.message = verify_error.message;
            return status;
        }
        expression_recovery_ = std::make_unique<ExpressionRecovery>(*module_);
    }

    const xair_cfg_completeness* raw = xair_cfg_completeness_summary(cfg_);
    completeness_.loader_state = loader_result_.state;
    completeness_.cfg_state = cfg_result_.state;
    completeness_.reason = cfg_result_.state == XAIR_ANALYSIS_COMPLETE
        ? loader_result_.reason : cfg_result_.reason;
    if (raw != nullptr) {
        completeness_.complete = raw->complete != 0 &&
            loader_result_.state == XAIR_ANALYSIS_COMPLETE &&
            cfg_result_.state == XAIR_ANALYSIS_COMPLETE;
        completeness_.nodes_total = raw->nodes_total;
        completeness_.nodes_partial = raw->nodes_partial;
        completeness_.nodes_opaque = raw->nodes_opaque;
        completeness_.functions_total = raw->functions_total;
        completeness_.functions_partial = raw->functions_partial;
        completeness_.unresolved_indirects = raw->unresolved_indirects;
        completeness_.skipped_items = raw->skipped_items;
    }
    return XAIR_OK;
}

xair_status AnalysisSession::build_inventory(SessionDiagnostic& diagnostic) {
    const std::size_t count = xair_cfg_function_count(cfg_);
    functions_.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const xair_function* raw = xair_cfg_get_function(
            cfg_, static_cast<xair_function_id>(index));
        if (raw == nullptr) {
            diagnostic = {XAIR_ERR_INTERNAL, XAIR_STAGE_CFG, 0,
                          "function inventory contains an invalid record"};
            return XAIR_ERR_INTERNAL;
        }
        FunctionInfo info;
        info.id = static_cast<xair_function_id>(index);
        info.entry = raw->entry;
        info.range_start = raw->entry;
        info.range_end = raw->entry;
        info.semantic_coverage = raw->semantic_coverage;
        info.flags = raw->flags;
        info.node_count = raw->node_count;
        info.call_edge_count = raw->call_edge_count;
        if (raw->name != nullptr && raw->name[0] != '\0') info.name = raw->name;
        if (info.name.empty()) {
            for (std::size_t symbol_index = 0;
                 symbol_index < binary_.symbol_count; ++symbol_index) {
                const xair_binary_symbol& symbol = binary_.symbols[symbol_index];
                if (symbol.va == raw->entry && symbol.name != nullptr &&
                    symbol.name[0] != '\0') {
                    info.name = symbol.name;
                    break;
                }
            }
        }
        if (info.name.empty()) {
            std::ostringstream name;
            name << "sub_" << std::hex << raw->entry;
            info.name = name.str();
        }

        std::size_t node_count = 0;
        const xair_cfg_node_id* nodes = xair_cfg_function_nodes(
            cfg_, info.id, &node_count);
        for (std::size_t node_index = 0; node_index < node_count; ++node_index) {
            const xair_cfg_node* node = xair_cfg_get_node(cfg_, nodes[node_index]);
            if (node == nullptr) continue;
            if (node_index == 0 || node->start < info.range_start) {
                info.range_start = node->start;
            }
            if (node->end > info.range_end) info.range_end = node->end;
        }
        indexes_->entries.emplace(info.entry, functions_.size());
        indexes_->names[ascii_lower(info.name)].push_back(functions_.size());
        functions_.push_back(std::move(info));
    }

    const std::size_t call_count = xair_cfg_call_site_count(cfg_);
    call_sites_.reserve(call_count);
    for (std::size_t index = 0; index < call_count; ++index) {
        const xair_cfg_call_site* raw = xair_cfg_get_call_site(cfg_, index);
        if (raw == nullptr) continue;
        CallSiteInfo info;
        info.index = index;
        info.address = recover_call_site_address(*raw);
        info.target = raw->target;
        info.flags = raw->flags;
        info.import_ordinal = raw->import_ordinal;
        if (raw->import_module != nullptr) info.import_module = raw->import_module;
        if (raw->import_name != nullptr) info.import_name = raw->import_name;
        xair_function_id owner = XAIR_CFG_INVALID_ID;
        if (xair_cfg_node_function_owners(cfg_, raw->node, &owner, 1) != 0) {
            info.owner = owner;
        }
        if (info.address != 0 && info.owner < functions_.size()) {
            indexes_->call_sites.emplace(info.address, info.owner);
        }
        if (info.owner < functions_.size() && !info.import_module.empty()) {
            if (!info.import_name.empty()) {
                indexes_->imports[import_key(
                    info.import_module, info.import_name)].push_back(info.owner);
            }
            if (info.import_ordinal != 0) {
                indexes_->imports[ordinal_key(
                    info.import_module, info.import_ordinal)].push_back(info.owner);
            }
        }
        call_sites_.push_back(std::move(info));
    }
    for (auto& [key, owners] : indexes_->imports) {
        (void)key;
        std::sort(owners.begin(), owners.end());
        owners.erase(std::unique(owners.begin(), owners.end()), owners.end());
    }
    if (module_ != nullptr) {
        VariableContext context;
        context.symbols.reserve(binary_.symbol_count);
        for (std::size_t index = 0; index < binary_.symbol_count; ++index) {
            const xair_binary_symbol& raw = binary_.symbols[index];
            if (raw.name == nullptr || raw.name[0] == '\0') continue;
            VariableSymbol symbol;
            symbol.address = raw.va;
            symbol.size = raw.size;
            symbol.name = raw.name;
            symbol.origin = (raw.flags & XAIR_BINARY_SYMBOL_IMPORT) != 0
                ? VariableSymbolOrigin::import : VariableSymbolOrigin::binary_symbol;
            symbol.confidence = XAIR_CONFIDENCE_HIGH;
            symbol.source.begin = raw.va;
            symbol.source.end = raw.size <=
                    std::numeric_limits<std::uint64_t>::max() - raw.va
                ? raw.va + raw.size : std::numeric_limits<std::uint64_t>::max();
            symbol.source.confidence = symbol.confidence;
            symbol.source.record_count = 1;
            symbol.source.synthetic = true;
            context.symbols.push_back(std::move(symbol));
        }
        context.ranges.reserve(binary_.segment_count);
        for (std::size_t index = 0; index < binary_.segment_count; ++index) {
            const xair_binary_segment& segment = binary_.segments[index];
            VariableAddressRange range;
            range.begin = segment.va;
            range.end = segment.mem_size <=
                    std::numeric_limits<std::uint64_t>::max() - segment.va
                ? segment.va + segment.mem_size
                : std::numeric_limits<std::uint64_t>::max();
            range.readable = (segment.perms & XAIR_BINARY_PERM_READ) != 0;
            range.writable = (segment.perms & XAIR_BINARY_PERM_WRITE) != 0;
            range.executable = (segment.perms & XAIR_BINARY_PERM_EXEC) != 0;
            context.ranges.push_back(range);
        }
        context.calls.reserve(call_sites_.size());
        for (std::size_t index = 0; index < call_sites_.size(); ++index) {
            const xair_cfg_call_site* raw = xair_cfg_get_call_site(cfg_, index);
            if (raw == nullptr || raw->ir_op == XAIR_INVALID_ID ||
                ((raw->import_module == nullptr || raw->import_module[0] == '\0') &&
                 (raw->import_name == nullptr || raw->import_name[0] == '\0') &&
                 raw->import_ordinal == 0)) {
                continue;
            }
            VariableCallHint hint;
            hint.operation = raw->ir_op;
            if (raw->import_module != nullptr) hint.module = raw->import_module;
            if (raw->import_name != nullptr) hint.name = raw->import_name;
            hint.ordinal = raw->import_ordinal;
            hint.confidence = raw->confidence == XAIR_EDGE_SPECULATIVE
                ? XAIR_CONFIDENCE_LOW : XAIR_CONFIDENCE_HIGH;
            context.calls.push_back(std::move(hint));
        }
        variable_recovery_ = std::make_unique<VariableRecovery>(
            *module_, std::move(context));
        compact_recovery_ = std::make_unique<CompactRecovery>(
            *cfg_, *module_, binary_);
    }
    return XAIR_OK;
}

std::uint64_t AnalysisSession::recover_call_site_address(
    const xair_cfg_call_site& site) {
    if (module_ != nullptr && site.ir_op != XAIR_INVALID_ID) {
        const xair_source_id* sources = nullptr;
        std::size_t source_count = 0;
        if (xair_op_sources(module_, site.ir_op, &sources, &source_count) == XAIR_OK) {
            for (std::size_t index = 0; index < source_count; ++index) {
                xair_source_record source{};
                if (xair_module_get_source(module_, sources[index], &source) == XAIR_OK &&
                    source.location.instruction_va != 0) {
                    return source.location.instruction_va;
                }
            }
        }
    }
    const xair_cfg_node* node = xair_cfg_get_node(cfg_, site.node);
    if (node == nullptr || decode_cache_ == nullptr) return 0;
    std::uint64_t address = node->start;
    std::uint64_t last = address;
    while (address < node->end) {
        const xair_x86_decoded_inst* decoded = nullptr;
        if (decode_cache_->decode(address, decoded) != XAIR_OK ||
            decoded == nullptr || decoded->fallthrough <= address ||
            decoded->fallthrough > node->end) {
            break;
        }
        last = address;
        address = decoded->fallthrough;
    }
    return last;
}

const std::filesystem::path& AnalysisSession::path() const noexcept { return path_; }
const AnalysisOptions& AnalysisSession::options() const noexcept { return options_; }
const xair_binary_view& AnalysisSession::binary() const noexcept { return binary_; }
const xair_cfg& AnalysisSession::cfg() const noexcept { return *cfg_; }
const xair_module* AnalysisSession::module() const noexcept { return module_; }
const xair_cfg_stats& AnalysisSession::cfg_stats() const noexcept { return cfg_stats_; }
const SessionCompleteness& AnalysisSession::completeness() const noexcept {
    return completeness_;
}
const std::vector<FunctionInfo>& AnalysisSession::functions() const noexcept {
    return functions_;
}
const std::vector<CallSiteInfo>& AnalysisSession::call_sites() const noexcept {
    return call_sites_;
}

const FunctionInfo* AnalysisSession::function_by_address(
    const std::uint64_t address) const {
    const auto entry = indexes_->entries.find(address);
    if (entry != indexes_->entries.end()) return &functions_[entry->second];
    const xair_cfg_node_id node = xair_cfg_find_node_containing(cfg_, address);
    if (node == XAIR_CFG_INVALID_ID) return nullptr;
    xair_function_id owner = XAIR_CFG_INVALID_ID;
    if (xair_cfg_node_function_owners(cfg_, node, &owner, 1) == 0 ||
        owner >= functions_.size()) {
        return nullptr;
    }
    return &functions_[owner];
}

const FunctionInfo* AnalysisSession::function_by_name(const std::string_view name) const {
    const auto found = indexes_->names.find(ascii_lower(name));
    if (found == indexes_->names.end() || found->second.empty()) return nullptr;
    return &functions_[found->second.front()];
}

const FunctionInfo* AnalysisSession::function_by_call_site(
    const std::uint64_t address) const {
    const auto found = indexes_->call_sites.find(address);
    return found == indexes_->call_sites.end() ? nullptr : &functions_[found->second];
}

const FunctionInfo* AnalysisSession::function_by_import(
    const std::string_view module,
    const std::string_view name) const {
    const auto found = indexes_->imports.find(import_key(module, name));
    if (found == indexes_->imports.end() || found->second.empty()) return nullptr;
    return &functions_[found->second.front()];
}

const FunctionInfo* AnalysisSession::function_by_import(
    const std::string_view module,
    const std::uint32_t ordinal) const {
    const auto found = indexes_->imports.find(ordinal_key(module, ordinal));
    if (found == indexes_->imports.end() || found->second.empty()) return nullptr;
    return &functions_[found->second.front()];
}

std::vector<const FunctionInfo*> AnalysisSession::functions_referencing_import(
    const std::string_view module,
    const std::string_view name) const {
    std::vector<const FunctionInfo*> result;
    const auto found = indexes_->imports.find(import_key(module, name));
    if (found == indexes_->imports.end()) return result;
    result.reserve(found->second.size());
    for (const std::size_t index : found->second) result.push_back(&functions_[index]);
    return result;
}

DecodeCache& AnalysisSession::decode_cache() noexcept { return *decode_cache_; }
const DecodeCache& AnalysisSession::decode_cache() const noexcept {
    return *decode_cache_;
}

SemanticExpression AnalysisSession::expression_view(
    const xair_value_id value,
    const ExpressionOptions& options) const {
    if (expression_recovery_ == nullptr) {
        SemanticExpression result;
        result.status = XAIR_ERR_INCOMPLETE;
        result.value = value;
        result.text = "XAIR expression recovery is unavailable because IR was not built";
        return result;
    }
    return expression_recovery_->build(value, options);
}

std::size_t AnalysisSession::cached_expression_count() const noexcept {
    return expression_recovery_ == nullptr ? 0 : expression_recovery_->cache_size();
}

VariableView AnalysisSession::variable_view(
    const xair_function_id function,
    const VariableOptions& options) const {
    if (variable_recovery_ == nullptr || module_ == nullptr) {
        VariableView result;
        result.status = XAIR_ERR_INCOMPLETE;
        return result;
    }
    if (function >= functions_.size()) {
        VariableView result;
        result.status = XAIR_ERR_BAD_ARG;
        return result;
    }
    VariableScope scope;
    scope.function_address = functions_[function].entry;
    if (binary_.arch == XAIR_ARCH_X86_64) {
        scope.calling_convention = binary_.format == XAIR_BINARY_FORMAT_PE
            ? XAIR_CC_WIN64 : XAIR_CC_SYSV_X64;
    } else if (binary_.arch == XAIR_ARCH_X86_32) {
        scope.calling_convention = XAIR_CC_CDECL_X86;
    }
    std::size_t node_count = 0;
    const xair_cfg_node_id* nodes = xair_cfg_function_nodes(
        cfg_, function, &node_count);
    scope.blocks.reserve(node_count);
    for (std::size_t index = 0; index < node_count; ++index) {
        const xair_cfg_node* node = xair_cfg_get_node(cfg_, nodes[index]);
        if (node == nullptr || node->ir_block == XAIR_INVALID_ID) continue;
        if (node->start == functions_[function].entry) scope.entry_block = node->ir_block;
        if (std::find(scope.blocks.begin(), scope.blocks.end(), node->ir_block) ==
            scope.blocks.end()) {
            scope.blocks.push_back(node->ir_block);
        }
    }
    if (scope.entry_block == XAIR_INVALID_ID && !scope.blocks.empty()) {
        scope.entry_block = scope.blocks.front();
    }
    if (scope.entry_block == XAIR_INVALID_ID) {
        VariableView result;
        result.status = XAIR_ERR_INCOMPLETE;
        result.function_address = scope.function_address;
        return result;
    }
    return variable_recovery_->build(scope, options);
}

std::size_t AnalysisSession::cached_variable_view_count() const noexcept {
    return variable_recovery_ == nullptr ? 0 : variable_recovery_->cache_size();
}

ControlView AnalysisSession::control_view(
    const xair_function_id function,
    const ControlOptions& options) const {
    if (compact_recovery_ == nullptr || module_ == nullptr) {
        ControlView result;
        result.status = XAIR_ERR_INCOMPLETE;
        result.function = function;
        return result;
    }
    if (function >= functions_.size()) {
        ControlView result;
        result.status = XAIR_ERR_BAD_ARG;
        result.function = function;
        return result;
    }
    return compact_recovery_->control_view(function, options);
}

CompactFunctionView AnalysisSession::compact_view(
    const xair_function_id function,
    const CompactOptions& options) const {
    if (compact_recovery_ == nullptr || module_ == nullptr) {
        CompactFunctionView result;
        result.status = XAIR_ERR_INCOMPLETE;
        result.function.id = function;
        return result;
    }
    if (function >= functions_.size()) {
        CompactFunctionView result;
        result.status = XAIR_ERR_BAD_ARG;
        result.function.id = function;
        return result;
    }
    VariableOptions variable_options;
    variable_options.max_variables = 0;
    const VariableView variables = variable_view(function, variable_options);
    CompactFunctionDescriptor descriptor;
    descriptor.id = function;
    descriptor.name = functions_[function].name;
    descriptor.entry = functions_[function].entry;
    descriptor.range_start = functions_[function].range_start;
    descriptor.range_end = functions_[function].range_end;
    descriptor.coverage = functions_[function].semantic_coverage;
    descriptor.session_complete = completeness_.complete;
    return compact_recovery_->build(descriptor, variables, options);
}

std::size_t AnalysisSession::cached_control_view_count() const noexcept {
    return compact_recovery_ == nullptr ? 0 : compact_recovery_->control_cache_size();
}

std::size_t AnalysisSession::cached_compact_view_count() const noexcept {
    return compact_recovery_ == nullptr ? 0 : compact_recovery_->cache_size();
}

bool AnalysisSession::symbolic_context_initialized() const noexcept {
    return symbolic_context_ != nullptr;
}

bool AnalysisSession::solver_initialized() const noexcept {
    return xair_sym_context_solver_initialized(symbolic_context_) != 0;
}

xair_sym_context* AnalysisSession::symbolic_context(SessionDiagnostic* diagnostic) {
    if (symbolic_context_ != nullptr) return symbolic_context_;
    const xair_sym_status status = xair_sym_context_create(&symbolic_context_);
    if (status != XAIR_SYM_OK) {
        if (diagnostic != nullptr) {
            diagnostic->status = status == XAIR_SYM_ERR_OOM
                ? XAIR_ERR_OOM : XAIR_ERR_INTERNAL;
            diagnostic->stage = XAIR_STAGE_SYMBOLIC;
            diagnostic->message = xair_sym_status_name(status);
        }
        return nullptr;
    }
    xair_analysis_options symbolic_options{};
    xair_analysis_options_init(&symbolic_options);
    apply_analysis_options(symbolic_options, options_);
    xair_sym_context_set_analysis_options(symbolic_context_, &symbolic_options);
    return symbolic_context_;
}

} // namespace airece
