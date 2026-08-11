#include <stdint.h>

#if defined(_MSC_VER)
#define AIRECE_EXPORT __declspec(dllexport) __declspec(noinline)
#define AIRECE_NOINLINE __declspec(noinline)
#else
#define AIRECE_EXPORT __attribute__((visibility("default"), noinline))
#define AIRECE_NOINLINE __attribute__((noinline))
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

static AIRECE_NOINLINE int dense_case0(unsigned value) { return (int)value + 11; }
static AIRECE_NOINLINE int dense_case1(unsigned value) { return (int)value * 3; }
static AIRECE_NOINLINE int dense_case2(unsigned value) { return (int)value - 19; }
static AIRECE_NOINLINE int dense_case3(unsigned value) { return (int)(value ^ 0x55U); }
static AIRECE_NOINLINE int dense_case4(unsigned value) { return (int)value + 101; }
static AIRECE_NOINLINE int dense_case5(unsigned value) { return (int)value - 7; }

AIRECE_EXPORT int airece_semantic_dense_switch(unsigned value) {
    switch (value) {
    case 0: return dense_case0(value);
    case 1: return dense_case1(value);
    case 2: return dense_case2(value);
    case 3: return dense_case3(value);
    case 4: return dense_case4(value);
    case 5: return dense_case5(value);
    default: return -313;
    }
}

AIRECE_EXPORT uint32_t airece_semantic_agent_dense_switch(
    uint32_t selector, uint32_t value) {
    switch (selector & 7U) {
    case 0: return value + 11U;
    case 1: return value * 3U;
    case 2: return value - 19U;
    case 3: return value ^ 0x55U;
    case 4: return value + 101U;
    case 5: return value - 7U;
    default: return value ^ 0x313U;
    }
}

AIRECE_EXPORT int airece_semantic_loop(const int* values, unsigned count) {
    int sum = 0;
    unsigned index = 0;
    while (index < count) {
        sum += values[index];
        ++index;
    }
    return sum;
}

AIRECE_EXPORT int airece_semantic_storage(int input) {
    volatile int slot = input + 1;
    slot = slot * 3;
    return slot;
}

AIRECE_EXPORT int airece_semantic_transform(int input) {
    return input * 7 + 3;
}

AIRECE_EXPORT int airece_semantic_interproc(int input) {
    return airece_semantic_transform(input);
}

AIRECE_EXPORT int airece_semantic_memory_flow(int* output, int input) {
    *output = input + 5;
    return *output;
}

/* A CRT-free DLL entry seeds CFG discovery and keeps all three semantic
 * contracts reachable.  It is analyzed, never loaded or executed by tests. */
AIRECE_EXPORT int airece_semantic_entry(void) {
    uint64_t value = UINT64_C(11);
    return (int)airece_semantic_load(&value) +
        airece_semantic_branch((int)value) +
        airece_semantic_switch((unsigned)value) +
        airece_semantic_dense_switch((unsigned)value) +
        airece_semantic_loop((const int*)&value, 1) +
        airece_semantic_storage((int)value) +
        airece_semantic_interproc((int)value) +
        airece_semantic_memory_flow((int*)&value, (int)value);
}
