#include <airece/semantic/api_model.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>

namespace airece {
namespace {

using A = ApiArgumentModel;
constexpr std::array<A, 10> process_args{{
    {"application", "path", true, false}, {"command_line", "user-input", true, true},
    {"process_attributes", "security", true, false}, {"thread_attributes", "security", true, false},
    {"inherit_handles", "flags", false, false}, {"creation_flags", "enum", false, false},
    {"environment", "buffer", true, false}, {"current_directory", "path", true, false},
    {"startup_info", "configuration", true, false}, {"process_info", "out-process-thread-handles", false, true}}};
constexpr std::array<A, 6> create_thread_args{{
    {"thread_attributes", "security", true, false}, {"stack_size", "length", false, false},
    {"start_address", "function-pointer", false, false}, {"parameter", "opaque-pointer", false, false},
    {"creation_flags", "enum", false, false}, {"thread_id", "out-thread-id", false, true}}};
constexpr std::array<A, 4> virtual_alloc_args{{
    {"address", "address-hint", false, false}, {"size", "length", false, false},
    {"allocation_type", "enum", false, false}, {"protection", "enum", false, false}}};
constexpr std::array<A, 5> virtual_alloc_ex_args{{
    {"process", "handle", false, false}, {"address", "address-hint", false, false},
    {"size", "length", false, false}, {"allocation_type", "enum", false, false},
    {"protection", "enum", false, false}}};
constexpr std::array<A, 4> virtual_protect_args{{
    {"address", "memory-region", false, false}, {"size", "length", false, false},
    {"new_protection", "enum", false, false}, {"old_protection", "out-enum", false, true}}};
constexpr std::array<A, 5> virtual_protect_ex_args{{
    {"process", "handle", false, false}, {"address", "memory-region", false, false},
    {"size", "length", false, false}, {"new_protection", "enum", false, false},
    {"old_protection", "out-enum", false, true}}};
constexpr std::array<A, 5> read_file_args{{
    {"file", "handle", false, false}, {"buffer", "taint-output", false, true},
    {"bytes_to_read", "length", false, false}, {"bytes_read", "out-length", false, true},
    {"overlapped", "async-state", true, true}}};
constexpr std::array<A, 5> write_file_args{{
    {"file", "handle", false, false}, {"buffer", "taint-input", true, false},
    {"bytes_to_write", "length", false, false}, {"bytes_written", "out-length", false, true},
    {"overlapped", "async-state", true, true}}};
constexpr std::array<A, 7> create_file_args{{
    {"file_name", "path", true, false}, {"desired_access", "flags", false, false},
    {"share_mode", "flags", false, false}, {"security_attributes", "security", true, false},
    {"creation_disposition", "enum", false, false}, {"flags_and_attributes", "flags", false, false},
    {"template_file", "handle", false, false}}};
constexpr std::array<A, 5> reg_open_key_args{{
    {"key", "handle", false, false}, {"subkey", "registry-path", true, false},
    {"options", "reserved", false, false}, {"desired_access", "flags", false, false},
    {"result_key", "out-handle", false, true}}};
constexpr std::array<A, 6> reg_query_value_args{{
    {"key", "handle", false, false}, {"value_name", "registry-name", true, false},
    {"reserved", "reserved", false, false}, {"type", "out-enum", false, true},
    {"data", "taint-output", false, true}, {"data_size", "inout-length", true, true}}};
constexpr std::array<A, 4> recv_args{{
    {"socket", "handle", false, false}, {"buffer", "taint-output", false, true},
    {"length", "length", false, false}, {"flags", "enum", false, false}}};
constexpr std::array<A, 6> recvfrom_args{{
    {"socket", "handle", false, false}, {"buffer", "taint-output", false, true},
    {"length", "length", false, false}, {"flags", "enum", false, false},
    {"source_address", "out-network-address", false, true},
    {"source_address_length", "inout-length", true, true}}};
constexpr std::array<A, 4> send_args{{
    {"socket", "handle", false, false}, {"buffer", "taint-input", true, false},
    {"length", "length", false, false}, {"flags", "enum", false, false}}};
constexpr std::array<A, 3> connect_args{{
    {"socket", "handle", false, false}, {"address", "network-address", true, false},
    {"address_length", "length", false, false}}};
constexpr std::array<A, 4> stream_read_args{{
    {"handle", "handle", false, false}, {"buffer", "taint-output", false, true},
    {"bytes_to_read", "length", false, false}, {"bytes_read", "out-length", false, true}}};
constexpr std::array<A, 7> crypt_encrypt_args{{
    {"key", "crypto-handle", false, false}, {"hash", "crypto-handle", false, false},
    {"final", "boolean", false, false}, {"flags", "enum", false, false},
    {"data", "taint-inout-buffer", true, true}, {"data_length", "inout-length", true, true},
    {"buffer_length", "length", false, false}}};
constexpr std::array<A, 6> crypt_decrypt_args{{
    {"key", "crypto-handle", false, false}, {"hash", "crypto-handle", false, false},
    {"final", "boolean", false, false}, {"flags", "enum", false, false},
    {"data", "taint-inout-buffer", true, true}, {"data_length", "inout-length", true, true}}};
constexpr std::array<A, 10> bcrypt_crypt_args{{
    {"key", "crypto-handle", false, false}, {"input", "taint-input", true, false},
    {"input_length", "length", false, false}, {"padding_info", "configuration", true, false},
    {"iv", "inout-buffer", true, true}, {"iv_length", "length", false, false},
    {"output", "taint-output", false, true}, {"output_length", "length", false, false},
    {"result_length", "out-length", false, true}, {"flags", "enum", false, false}}};
constexpr std::array<A, 3> open_scm_args{{
    {"machine_name", "machine-name", true, false}, {"database_name", "service-database", true, false},
    {"desired_access", "flags", false, false}}};
constexpr std::array<A, 13> create_service_args{{
    {"service_manager", "handle", false, false}, {"service_name", "service-name", true, false},
    {"display_name", "display-name", true, false}, {"desired_access", "flags", false, false},
    {"service_type", "enum", false, false}, {"start_type", "enum", false, false},
    {"error_control", "enum", false, false}, {"binary_path", "path", true, false},
    {"load_order_group", "group-name", true, false}, {"tag_id", "out-id", false, true},
    {"dependencies", "multi-string", true, false}, {"service_start_name", "account-name", true, false},
    {"password", "credential", true, false}}};
constexpr std::array<A, 3> start_service_args{{
    {"service", "handle", false, false}, {"argument_count", "count", false, false},
    {"arguments", "string-array", true, false}}};
constexpr std::array<A, 3> create_mutex_args{{
    {"attributes", "security", true, false}, {"initial_owner", "boolean", false, false},
    {"name", "object-name", true, false}}};
constexpr std::array<A, 4> create_event_args{{
    {"attributes", "security", true, false}, {"manual_reset", "boolean", false, false},
    {"initial_state", "boolean", false, false}, {"name", "object-name", true, false}}};
constexpr std::array<A, 2> wait_args{{
    {"handle", "handle", false, false}, {"timeout", "milliseconds", false, false}}};
constexpr std::array<A, 1> load_library_args{{{"file_name", "path", true, false}}};
constexpr std::array<A, 2> get_proc_address_args{{
    {"module", "module-handle", false, false}, {"symbol", "name-or-ordinal", true, false}}};
constexpr std::array<A, 0> no_args{};
constexpr std::array<A, 2> check_debugger_args{{
    {"process", "handle", false, false}, {"debugger_present", "out-boolean", false, true}}};
constexpr std::array<A, 5> nt_query_process_args{{
    {"process", "handle", false, false}, {"information_class", "enum", false, false},
    {"information", "out-buffer", false, true}, {"information_length", "length", false, false},
    {"return_length", "out-length", false, true}}};
constexpr std::array<A, 3> environment_variable_args{{
    {"name", "environment-name", true, false}, {"buffer", "taint-output", false, true},
    {"size", "length", false, false}}};
constexpr std::array<A, 1> exit_args{{{"exit_code", "status", false, false}}};

constexpr std::uint32_t read = XAIR_EFFECT_READ_MEMORY;
constexpr std::uint32_t write = XAIR_EFFECT_WRITE_MEMORY;
constexpr std::uint32_t fault = XAIR_EFFECT_MAY_FAULT;
constexpr std::uint32_t noreturn = XAIR_EFFECT_NORETURN;

#define MODEL(mod, api, args, ret, fx, taint_role, category, enums, produced, consumed, kind, nr) \
    ApiModel{mod, api, 0, args, ret, fx, taint_role, category, enums, {produced, consumed}, \
        {kind, 1, 0}, nr}
#define MODEL_ORD(mod, api, ordinal_value, args, ret, fx, taint_role, category, enums, produced, consumed, kind, nr) \
    ApiModel{mod, api, ordinal_value, args, ret, fx, taint_role, category, enums, {produced, consumed}, \
        {kind, 1, 0}, nr}

const std::array models{
    MODEL("kernel32", "CreateProcessA", process_args, "success", read|write|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "CREATE_*", "process/thread handles", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "CreateProcessW", process_args, "success", read|write|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "CREATE_*", "process/thread handles", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "CreateThread", create_thread_args, "thread-handle", read|write|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "STACK_SIZE_PARAM_IS_A_RESERVATION", "thread handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "VirtualAlloc", virtual_alloc_args, "allocated-address", write|fault, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "MEM_*; PAGE_*", "memory region", "", XAIR_SYM_MODEL_ALLOC, false),
    MODEL("kernel32", "VirtualAllocEx", virtual_alloc_ex_args, "remote-address", write|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "MEM_*; PAGE_*", "remote memory region", "process handle", XAIR_SYM_MODEL_ALLOC, false),
    MODEL("kernel32", "VirtualProtect", virtual_protect_args, "success", read|write|fault, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "PAGE_*", "", "memory region", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "VirtualProtectEx", virtual_protect_ex_args, "success", read|write|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "PAGE_*", "", "process handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "ReadFile", read_file_args, "success", read|write|fault, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_FILE, "ERROR_IO_PENDING", "", "file handle", XAIR_SYM_MODEL_INPUT, false),
    MODEL("kernel32", "WriteFile", write_file_args, "success", read|write|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_FILE, "ERROR_IO_PENDING", "", "file handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "CreateFileA", create_file_args, "file-handle", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_FILE, "GENERIC_*; OPEN_*", "file handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "CreateFileW", create_file_args, "file-handle", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_FILE, "GENERIC_*; OPEN_*", "file handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("advapi32", "RegOpenKeyExA", reg_open_key_args, "status", read|write, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_REGISTRY, "KEY_*", "registry key handle", "parent key", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("advapi32", "RegOpenKeyExW", reg_open_key_args, "status", read|write, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_REGISTRY, "KEY_*", "registry key handle", "parent key", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("advapi32", "RegQueryValueExA", reg_query_value_args, "status", read|write, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_REGISTRY, "REG_*", "", "registry key handle", XAIR_SYM_MODEL_INPUT, false),
    MODEL("advapi32", "RegQueryValueExW", reg_query_value_args, "status", read|write, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_REGISTRY, "REG_*", "", "registry key handle", XAIR_SYM_MODEL_INPUT, false),
    MODEL_ORD("ws2_32", "recv", 16, recv_args, "bytes-received", read|write|fault, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_NETWORK, "MSG_*; SOCKET_ERROR", "", "socket", XAIR_SYM_MODEL_INPUT, false),
    MODEL_ORD("ws2_32", "recvfrom", 17, recvfrom_args, "bytes-received", read|write|fault, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_NETWORK, "MSG_*; SOCKET_ERROR", "", "socket", XAIR_SYM_MODEL_INPUT, false),
    MODEL_ORD("ws2_32", "send", 19, send_args, "bytes-sent", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_NETWORK, "MSG_*; SOCKET_ERROR", "", "socket", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL_ORD("ws2_32", "connect", 4, connect_args, "status", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_NETWORK, "AF_*; SOCK_*", "connection", "socket", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("winhttp", "WinHttpReadData", stream_read_args, "success", read|write|fault, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_NETWORK, "ERROR_IO_PENDING", "", "request handle", XAIR_SYM_MODEL_INPUT, false),
    MODEL("wininet", "InternetReadFile", stream_read_args, "success", read|write|fault, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_NETWORK, "ERROR_IO_PENDING", "", "internet handle", XAIR_SYM_MODEL_INPUT, false),
    MODEL("advapi32", "CryptEncrypt", crypt_encrypt_args, "success", read|write, ApiTaintRole::source_and_sink, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "CRYPT_*", "", "key handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("advapi32", "CryptDecrypt", crypt_decrypt_args, "success", read|write, ApiTaintRole::source_and_sink, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "CRYPT_*", "", "key handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("bcrypt", "BCryptEncrypt", bcrypt_crypt_args, "status", read|write, ApiTaintRole::source_and_sink, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "BCRYPT_*", "", "key handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("bcrypt", "BCryptDecrypt", bcrypt_crypt_args, "status", read|write, ApiTaintRole::source_and_sink, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "BCRYPT_*", "", "key handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("advapi32", "OpenSCManagerA", open_scm_args, "service-manager-handle", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "SC_MANAGER_*", "SCM handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("advapi32", "CreateServiceA", create_service_args, "service-handle", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "SERVICE_*", "service handle", "SCM handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("advapi32", "StartServiceA", start_service_args, "success", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_PROCESS, "SERVICE_*", "", "service handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "CreateMutexA", create_mutex_args, "mutex-handle", read|fault, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "ERROR_ALREADY_EXISTS", "mutex handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "CreateEventA", create_event_args, "event-handle", read|fault, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "manual-reset; initial-state", "event handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "WaitForSingleObject", wait_args, "wait-status", fault, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "WAIT_*; INFINITE", "", "sync handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "LoadLibraryA", load_library_args, "module-handle", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_FILE, "LOAD_LIBRARY_*", "module handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "LoadLibraryW", load_library_args, "module-handle", read|fault, ApiTaintRole::sink, XAIR_SYM_TAINT_CATEGORY_FILE, "LOAD_LIBRARY_*", "module handle", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "GetProcAddress", get_proc_address_args, "function-address", read|fault, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "ordinal <= 0xffff", "function address", "module handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "IsDebuggerPresent", no_args, "boolean", XAIR_EFFECT_PURE, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "BOOL", "", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "CheckRemoteDebuggerPresent", check_debugger_args, "success", write|fault, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "BOOL", "", "process handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("ntdll", "NtQueryInformationProcess", nt_query_process_args, "ntstatus", read|write|fault, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_PROCESS, "ProcessDebugPort; ProcessDebugFlags", "", "process handle", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "GetCommandLineA", no_args, "user-command-line", read, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_USER, "process command line", "", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "GetCommandLineW", no_args, "user-command-line", read, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_USER, "process command line", "", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "GetEnvironmentVariableA", environment_variable_args, "characters-written", read|write, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_USER, "ERROR_ENVVAR_NOT_FOUND", "", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "GetEnvironmentVariableW", environment_variable_args, "characters-written", read|write, ApiTaintRole::source, XAIR_SYM_TAINT_CATEGORY_USER, "ERROR_ENVVAR_NOT_FOUND", "", "", XAIR_SYM_MODEL_UNKNOWN, false),
    MODEL("kernel32", "ExitProcess", exit_args, "never", noreturn, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "exit-code", "", "", XAIR_SYM_MODEL_NO_RETURN, true),
    MODEL("ntdll", "RtlExitUserProcess", exit_args, "never", noreturn, ApiTaintRole::none, XAIR_SYM_TAINT_CATEGORY_UNKNOWN, "exit-code", "", "", XAIR_SYM_MODEL_NO_RETURN, true)
};
#undef MODEL
#undef MODEL_ORD

std::string normalized_module(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (result.ends_with(".dll")) result.resize(result.size() - 4);
    return result;
}

bool equal_fold(std::string_view left, std::string_view right) {
    return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(),
        [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); });
}

} // namespace

const ApiModel* find_api_model(
    const std::string_view module,
    const std::string_view name,
    const std::uint32_t ordinal) noexcept {
    const std::string normalized = normalized_module(module);
    for (const ApiModel& model : models) {
        if (!normalized.empty() && normalized != model.module) continue;
        if (!name.empty() && equal_fold(name, model.name)) return &model;
        if (name.empty() && ordinal != 0 && ordinal == model.ordinal) return &model;
    }
    return nullptr;
}

std::span<const ApiModel> api_models() noexcept { return models; }

const char* api_taint_role_name(const ApiTaintRole role) noexcept {
    switch (role) {
    case ApiTaintRole::source: return "source";
    case ApiTaintRole::sink: return "sink";
    case ApiTaintRole::source_and_sink: return "source+sink";
    case ApiTaintRole::none:
    default: return "none";
    }
}

std::string describe_api_effects(const ApiModel& model) {
    std::ostringstream out;
    bool separator = false;
    auto add = [&](const std::string_view text) {
        if (separator) out << ',';
        out << text;
        separator = true;
    };
    if ((model.effects & XAIR_EFFECT_READ_MEMORY) != 0) add("read-memory");
    if ((model.effects & XAIR_EFFECT_WRITE_MEMORY) != 0) add("write-memory");
    if ((model.effects & XAIR_EFFECT_MAY_FAULT) != 0) add("may-fault");
    if (model.no_return) add("no-return");
    return out.str();
}

xair_sym_status register_api_models(xair_sym_environment* environment) noexcept {
    if (environment == nullptr) return XAIR_SYM_ERR_BAD_ARG;
    for (const ApiModel& model : models) {
        xair_sym_model_identity identity{};
        identity.module = model.module.data();
        identity.name = model.name.data();
        const xair_sym_status status = xair_sym_environment_register_model_kind(
            environment, &identity, &model.symbolic);
        if (status != XAIR_SYM_OK) return status;
        if (model.ordinal != 0) {
            identity.name = nullptr;
            identity.ordinal = model.ordinal;
            const xair_sym_status ordinal_status =
                xair_sym_environment_register_model_kind(
                    environment, &identity, &model.symbolic);
            if (ordinal_status != XAIR_SYM_OK) return ordinal_status;
        }
    }
    return XAIR_SYM_OK;
}

} // namespace airece
