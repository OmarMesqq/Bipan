#ifndef BIPAN_FILTERS_H
#define BIPAN_FILTERS_H

enum BIPAN_FILTER { 
    BLOCK = 0,
    LOG = 1,
    TRAP = 2
};

void applySeccompFilter(BIPAN_FILTER opt);

#endif