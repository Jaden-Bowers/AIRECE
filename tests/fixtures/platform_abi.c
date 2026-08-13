#include <stdint.h>

#if defined(_MSC_VER)
#define AIRECE_PLATFORM_EXPORT __declspec(dllexport) __declspec(noinline)
#else
#define AIRECE_PLATFORM_EXPORT __attribute__((visibility("default"), noinline))
#endif

AIRECE_PLATFORM_EXPORT uint32_t airece_platform_mix(
    uint32_t first, uint32_t second) {
    return (first & UINT32_C(7)) + second * UINT32_C(3) + UINT32_C(0x21);
}

AIRECE_PLATFORM_EXPORT uint32_t airece_platform_entry(void) {
    return airece_platform_mix(UINT32_C(11), UINT32_C(13));
}
