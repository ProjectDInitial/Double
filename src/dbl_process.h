#ifndef __DBL_PROCESS_H
#define __DBL_PROCESS_H

#include "dbl_eventloop.h"

/**
 * @brief Process starts processing event loop 
 */
void dbl_process_runeventloop(struct dbl_eventloop *evloop); 

/**
 * @brief Send a signal to Read PID from file and send a signal to process
 */
void dbl_process_sendsignal(const char *signal, struct dbl_log *log); 

#endif
