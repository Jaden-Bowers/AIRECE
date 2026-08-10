#include <airece/semantic/api_model.hpp>

#include <cassert>
#include <array>
#include <set>
#include <string>
#include <string_view>
#include <utility>

int main() {
    using namespace airece;
    using namespace std::string_view_literals;
    assert(api_model_set_version == "2.0.0");
    constexpr std::array expected_counts{
        std::pair{"CreateProcessA"sv, 10U}, std::pair{"CreateProcessW"sv, 10U},
        std::pair{"CreateThread"sv, 6U}, std::pair{"VirtualAlloc"sv, 4U},
        std::pair{"VirtualAllocEx"sv, 5U}, std::pair{"VirtualProtect"sv, 4U},
        std::pair{"VirtualProtectEx"sv, 5U}, std::pair{"ReadFile"sv, 5U},
        std::pair{"WriteFile"sv, 5U}, std::pair{"CreateFileA"sv, 7U},
        std::pair{"CreateFileW"sv, 7U}, std::pair{"RegOpenKeyExA"sv, 5U},
        std::pair{"RegOpenKeyExW"sv, 5U}, std::pair{"RegQueryValueExA"sv, 6U},
        std::pair{"RegQueryValueExW"sv, 6U}, std::pair{"recv"sv, 4U},
        std::pair{"recvfrom"sv, 6U}, std::pair{"send"sv, 4U},
        std::pair{"connect"sv, 3U}, std::pair{"WinHttpReadData"sv, 4U},
        std::pair{"InternetReadFile"sv, 4U}, std::pair{"CryptEncrypt"sv, 7U},
        std::pair{"CryptDecrypt"sv, 6U}, std::pair{"BCryptEncrypt"sv, 10U},
        std::pair{"BCryptDecrypt"sv, 10U}, std::pair{"OpenSCManagerA"sv, 3U},
        std::pair{"CreateServiceA"sv, 13U}, std::pair{"StartServiceA"sv, 3U},
        std::pair{"CreateMutexA"sv, 3U}, std::pair{"CreateEventA"sv, 4U},
        std::pair{"WaitForSingleObject"sv, 2U}, std::pair{"LoadLibraryA"sv, 1U},
        std::pair{"LoadLibraryW"sv, 1U}, std::pair{"GetProcAddress"sv, 2U},
        std::pair{"IsDebuggerPresent"sv, 0U},
        std::pair{"CheckRemoteDebuggerPresent"sv, 2U},
        std::pair{"NtQueryInformationProcess"sv, 5U},
        std::pair{"GetCommandLineA"sv, 0U}, std::pair{"GetCommandLineW"sv, 0U},
        std::pair{"GetEnvironmentVariableA"sv, 3U},
        std::pair{"GetEnvironmentVariableW"sv, 3U},
        std::pair{"ExitProcess"sv, 1U}, std::pair{"RtlExitUserProcess"sv, 1U}};
    static_assert(expected_counts.size() == 43);
    assert(api_models().size() == expected_counts.size());
    for (const auto& [name, count] : expected_counts) {
        const ApiModel* model = find_api_model("", name);
        assert(model != nullptr);
        assert(model->arguments.size() == count);
        std::set<std::string_view> argument_names;
        for (const ApiArgumentModel& argument : model->arguments) {
            assert(!argument.name.empty());
            assert(!argument.role.empty());
            assert(argument_names.insert(argument.name).second);
        }
    }
    const ApiModel* read = find_api_model("KERNEL32.DLL", "ReadFile");
    assert(read != nullptr);
    assert(read->taint == ApiTaintRole::source);
    assert(read->taint_category == XAIR_SYM_TAINT_CATEGORY_FILE);
    assert((read->effects & XAIR_EFFECT_WRITE_MEMORY) != 0);
    assert(read->symbolic.kind == XAIR_SYM_MODEL_INPUT);
    const ApiModel* exit = find_api_model("kernel32", "ExitProcess");
    assert(exit != nullptr && exit->no_return);
    assert(exit->symbolic.kind == XAIR_SYM_MODEL_NO_RETURN);
    const ApiModel* network = find_api_model("WS2_32.dll", "recv");
    assert(network != nullptr && network->taint_category == XAIR_SYM_TAINT_CATEGORY_NETWORK);
    assert(find_api_model("ws2_32.dll", "", 16) == network);
    const ApiModel* user = find_api_model("kernel32", "GetCommandLineW");
    assert(user != nullptr && user->taint_category == XAIR_SYM_TAINT_CATEGORY_USER);
    assert(user->arguments.empty());
    const ApiModel* create_file = find_api_model("kernel32", "CreateFileW");
    assert(create_file != nullptr && create_file->arguments[0].name == "file_name");
    assert(create_file->arguments[0].reads && !create_file->arguments[0].writes);
    const ApiModel* recv = find_api_model("ws2_32", "recv");
    assert(recv != nullptr && recv->arguments[1].role == "taint-output");
    assert(!recv->arguments[1].reads && recv->arguments[1].writes);
    const ApiModel* send = find_api_model("ws2_32", "send");
    assert(send != nullptr && send->arguments[1].role == "taint-input");
    assert(send->arguments[1].reads && !send->arguments[1].writes);
    assert(find_api_model("unknown", "MysteryApi") == nullptr);
    assert(describe_api_effects(*read).find("write-memory") != std::string::npos);
    return 0;
}
