#include <stdint.h>

#define EXPORT __declspec(dllexport) __declspec(noinline)
#define NOINLINE __declspec(noinline)

EXPORT uint32_t f_19a7d3e1(uint32_t a, uint32_t b) {
    uint32_t count = b & 31u;
    uint32_t rotated = count == 0 ? a : (a << count) | (a >> (32u - count));
    return rotated ^ UINT32_C(0xa5a5a5a5);
}

EXPORT uint32_t f_2bc8e4f2(uint32_t a, uint32_t b) {
    switch (a) {
    case 3: return b + 31u;
    case 9: return b ^ 97u;
    case 17: return b * 173u;
    default: return b - 1u;
    }
}

EXPORT uint32_t f_3cd9f503(uint32_t a, uint32_t b) {
    uint32_t values[4] = {a, b, a ^ b, a + b};
    uint32_t result = 0;
    for (uint32_t index = 0; index < 4; ++index) {
        result += values[index] * (index + 1u);
    }
    return result;
}

EXPORT uint32_t f_4dea0614(uint32_t a, uint32_t b) {
    if ((a & 1u) != 0) {
        if (b > 100u) return (a + b) ^ 0x55u;
        return a * 3u + b;
    }
    if (b == 0) return a + 7u;
    return (a - b) ^ 0x33u;
}

static NOINLINE uint32_t helper_5efb1725(uint32_t value) {
    return value * 7u + 3u;
}

EXPORT uint32_t f_5efb1725(uint32_t a, uint32_t b) {
    return helper_5efb1725(a) ^ helper_5efb1725(b);
}

typedef void* bench_handle;
__declspec(dllimport) int __stdcall ReadFile(
    bench_handle, void*, uint32_t, uint32_t*, void*);
__declspec(dllimport) int __stdcall WriteFile(
    bench_handle, const void*, uint32_t, uint32_t*, void*);

EXPORT uint32_t f_b5f17d8b(uint32_t a, uint32_t b) {
    uint32_t value = a;
    uint32_t transferred = 0;
    bench_handle handle = (bench_handle)(uintptr_t)b;
    if (ReadFile(handle, &value, 4u, &transferred, (void*)0)) {
        WriteFile(handle, &value, transferred, &transferred, (void*)0);
    }
    return value ^ transferred;
}

EXPORT int bench_entry(void) {
    return (int)(f_19a7d3e1(1, 2) + f_2bc8e4f2(3, 4) +
        f_3cd9f503(5, 6) + f_4dea0614(7, 8) + f_5efb1725(9, 10));
}
