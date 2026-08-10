#pragma once

#include <cstddef>
#include <cstdint>
#include <map>

extern "C" {
#include <xair/xair_binary.h>
}

namespace airece {

struct DecodeCacheStats {
    std::size_t requests{};
    std::size_t hits{};
    std::size_t entries{};
};

// Session-owned cache for XAIR's canonical decoded instruction records.
// The referenced binary view must outlive the cache.
class DecodeCache final {
public:
    explicit DecodeCache(const xair_binary_view& binary) noexcept;

    xair_status decode(std::uint64_t address,
                       const xair_x86_decoded_inst*& instruction);
    [[nodiscard]] DecodeCacheStats stats() const noexcept;
    void clear() noexcept;

private:
    struct Entry {
        xair_status status{XAIR_ERR_INTERNAL};
        xair_x86_decoded_inst instruction{};
    };

    const xair_binary_view* binary_;
    std::map<std::uint64_t, Entry> entries_;
    std::size_t requests_{};
    std::size_t hits_{};
};

} // namespace airece
