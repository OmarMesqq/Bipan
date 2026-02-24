#ifndef BIPAN_FILTERS_H
#define BIPAN_FILTERS_H

enum BIPAN_FILTER { 
    LOG = 0,
};

void applySeccompFilter(BIPAN_FILTER opt);

#endif