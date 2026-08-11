#include <stdint.h>

#define EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#define NOINLINE __declspec(noinline)

struct Pair32 { uint32_t left; uint32_t right; };
static volatile uint32_t global_bias = 0x10203040u;

EXPORT uint32_t f_60ac2836(uint32_t a, uint32_t b) {
    Pair32 pair{a ^ 0x1234u, b + 9u};
    return pair.left + pair.right;
}

static NOINLINE uint32_t recurse_71bd3947(uint32_t value) {
    if (value <= 1u) return 1u;
    return value + recurse_71bd3947(value - 1u);
}

EXPORT uint32_t f_71bd3947(uint32_t a, uint32_t b) {
    return recurse_71bd3947(a & 7u) + b;
}

EXPORT uint32_t f_82ce4a58(uint32_t a, uint32_t b) {
    switch (a & 7u) {
    case 0: return b + 11u;
    case 1: return b * 3u;
    case 2: return b - 19u;
    case 3: return b ^ 0x55u;
    case 4: return b + 101u;
    case 5: return b - 7u;
    default: return b ^ 0x313u;
    }
}

EXPORT uint32_t f_93df5b69(uint32_t a, uint32_t b) {
    uint32_t prior = global_bias;
    global_bias = (a ^ b) + 0x44u;
    return prior ^ global_bias;
}

typedef uint32_t (*transform_fn)(uint32_t);
static NOINLINE uint32_t transform_add(uint32_t value) { return value + 0x21u; }
static NOINLINE uint32_t transform_xor(uint32_t value) { return value ^ 0x87654321u; }

EXPORT uint32_t f_a4e06c7a(uint32_t a, uint32_t b) {
    transform_fn selected = (a & 1u) ? transform_add : transform_xor;
    return selected(b) + (a & 0xffu);
}

EXPORT int bench_entry(void) {
    return (int)(f_60ac2836(1, 2) + f_71bd3947(3, 4) +
        f_82ce4a58(5, 6) + f_93df5b69(7, 8) + f_a4e06c7a(9, 10));
}

