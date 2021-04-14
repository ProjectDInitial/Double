#ifndef __DBL_PROCESS_H
#define __DBL_PROCESS_H

#include "dbl_eventloop.h"

int dbl_init_signal(struct dbl_eventloop *evloop); 

void dbl_process_eventloop(struct dbl_eventloop *evloop); 

#endif
