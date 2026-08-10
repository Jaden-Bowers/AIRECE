#pragma once

#include <airece/semantic/compact_view.hpp>

#include <string>

namespace airece {

struct RenderedSemanticText {
    std::string text;
    bool truncated{};
    std::size_t omitted_lines{};
};

[[nodiscard]] RenderedSemanticText render_compact(
    const CompactFunctionView& view,
    const CompactOptions& options = {});

[[nodiscard]] RenderedSemanticText render_pseudo(
    const CompactFunctionView& view,
    const CompactOptions& options = {});

} // namespace airece
