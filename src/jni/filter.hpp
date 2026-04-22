#ifndef FILTER_H
#define FILTER_H

#include <stdint.h>

void applySeccomp(uintptr_t lib_start, uintptr_t lib_end);

#endif
