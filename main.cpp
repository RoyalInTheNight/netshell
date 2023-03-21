#include "IShellAPI.h"

core::int32_t main() {
    fprintf(stdout, "%d\n", (192 >> 24) | (168 >> 16) | (1 >> 8) | 1);
}