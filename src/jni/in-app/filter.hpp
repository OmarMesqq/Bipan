#ifndef FILTER_HPP
#define FILTER_HPP

#include <stdint.h>

void applySeccomp(uintptr_t lib_start, uintptr_t lib_end);

#endif
