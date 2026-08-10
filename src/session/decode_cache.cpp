#include <airece/session/decode_cache.hpp>

namespace airece {

DecodeCache::DecodeCache(const xair_binary_view& binary) noexcept
    : binary_(&binary) {}

xair_status DecodeCache::decode(
    const std::uint64_t address,
    const xair_x86_decoded_inst*& instruction) {
    ++requests_;
    const auto existing = entries_.find(address);
    if (existing != entries_.end()) {
        ++hits_;
        instruction = existing->second.status == XAIR_OK
            ? &existing->second.instruction
            : nullptr;
        return existing->second.status;
    }

    Entry entry;
    entry.status = xair_decode_instruction(binary_, address, &entry.instruction);
    const auto inserted = entries_.emplace(address, entry).first;
    instruction = inserted->second.status == XAIR_OK
        ? &inserted->second.instruction
        : nullptr;
    return inserted->second.status;
}

DecodeCacheStats DecodeCache::stats() const noexcept {
    return {requests_, hits_, entries_.size()};
}

void DecodeCache::clear() noexcept {
    entries_.clear();
    requests_ = 0;
    hits_ = 0;
}

} // namespace airece
