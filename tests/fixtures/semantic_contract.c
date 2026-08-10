#include <stdint.h>

#if defined(_MSC_VER)
#define AIRECE_EXPORT __declspec(dllexport) __declspec(noinline)
#else
#define AIRECE_EXPORT __attribute__((visibility("default"), noinline))
#endif

#if defined(AIRECE_RTC_STUBS)
/* CMake before CMP0184 cannot disable /RTC1 for one target.  These no-op
 * definitions keep the deliberately non-executed, CRT-free PE fixture
 * linkable on those generators. */
void _RTC_InitBase(void) {}
void _RTC_Shutdown(void) {}
void __fastcall _RTC_CheckStackVars(void* frame, void* descriptor) {
    (void)frame;
    (void)descriptor;
}
#endif

/* Source-backed compiler fixtures.  These deliberately exercise value
 * results, a load, a diamond, and a switch without depending on a CRT API. */
AIRECE_EXPORT uint64_t airece_semantic_load(const uint64_t* input) {
    return *input + UINT64_C(7);
}

AIRECE_EXPORT int airece_semantic_branch(int value) {
    int result = value + 3;
    if ((value & 1) != 0) {
        result *= 2;
    } else {
        result -= 5;
    }
    return result;
}

AIRECE_EXPORT int airece_semantic_switch(unsigned value) {
    switch (value) {
    case 3: return 31;
    case 9: return 97;
    case 17: return 173;
    default: return -1;
    }
}

/* A CRT-free DLL entry seeds CFG discovery and keeps all three semantic
 * contracts reachable.  It is analyzed, never loaded or executed by tests. */
AIRECE_EXPORT int airece_semantic_entry(void) {
    uint64_t value = UINT64_C(11);
    return (int)airece_semantic_load(&value) +
        airece_semantic_branch((int)value) +
        airece_semantic_switch((unsigned)value);
}
