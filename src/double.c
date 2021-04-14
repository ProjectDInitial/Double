#include "dbl_config.h"

//static int dbl_get_options_(int argc, char *const *argv, const char **signame) {
//    char *p;
//
//    if (argc == 1) {
//        return 0; 
//    }
//
//    p = argv[1];
//    if (*p++ != '-') {
//        dbl_log_write(stderr, DBL_LOG_ERROR, 0,"invalid option: \"%s\"", argv[1]);
//        return -1;
//    }
//
//    switch (*p++) {
//        case 's':
//            if (*p) {
//                dbl_log_write(stderr, DBL_LOG_ERROR, 0,"invalid option: \"%s\"", argv[1]);
//                return -1;
//            }
//            if (argc < 3) {
//                dbl_log_write(stderr, DBL_LOG_ERROR, 0, "option \"-s\" requires parameter");
//                return -1;
//            }
//            *signame = argv[2];
//            return 0;
//        default:
//            dbl_log_write(stderr, DBL_LOG_ERROR, 0,"invalid option: \"%s\"", argv[1]);
//    }
//    return -1;
//}


//struct dbl_yaml_mapper_command cmd2= {
//    "logee",
//    0,
//    0,
//    0,
//    NULL,
//    YAML_SCALAR_NODE,
//};

#include <signal.h>
#include "dbl_pool.h"
#include "dbl_eventloop.h"
#include "dbl_config.h"
#include <uchar.h>
#include <inttypes.h>
#include <stddef.h>
#include <event2/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <amqp.h>
#include <amqp_framing.h>
#include "dbl_mq.h"
#include <features.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <dbl_process.h>
#include <event2/event_compat.h>
#include <event2/event.h>

#include <setjmp.h>
#include <event2/event_compat.h>


void showterm(int signo) {
    volatile int i= 0;
    while (i < INT_MAX) {
        i++;
    }
    printf("signal term\n");
}

void showusr1(int signo) {
    printf("signal usr1\n");
}

void showalrm(int signo) {
    printf("signal alrm\n");
    //sigset_t set;

    //sigemptyset(&set);
    //sigpending(&set);
    //sigaddset(&set, SIGUSR1);

    //sigprocmask(SIG_UNBLOCK, &set, NULL);
    //printf("unblock usr1\n");
}

#include <setjmp.h>

//static jmp_buf buf;
//
//void second(void) {
//    printf("second\n");         // 打印
//    longjmp(buf,1);             // 跳回setjmp的调用处 - 使得setjmp返回值为1
//
//    printf("end");
//}
//
//void first(void) {
//    if (!setjmp(buf) ) {
//        second();
//    } else {                    // 当longjmp跳转回，setjmp返回1，因此进入此行
//        printf("first\n");          // 不可能执行到此行
//    }
//}
//
//int main() {
//    first();
//    return 0;
//}


#include "dbl_eventloop.h"

int main(int argc, char **argv) {
    struct dbl_eventloop service;
    struct dbl_log log;
    
    log.file = stdout;
    log.log_level = DBL_LOG_ERROR;

    if (SSL_library_init() != 1) {
        dbl_log_error(DBL_LOG_ERROR, &log, errno, "SSL_library_init() failed");
        return 1;
    }

    dbl_init_eventloop(&service, DOUBLE_CONFIG_PATH, DOUBLE_PID_PATH, &log);
    dbl_process_eventloop(&service);
    return 0;

    ///* Get input options */
    //if (dbl_get_options_(argc, argv, &signame) == -1) {
    //    return 1;
    //}

    ///* If get a signal from the input, send a signal to the 
    // * specified process */ 
    //if (signame) {
    //    dbl_send_signal(DBL_PID_PATH, signame);
    //    return 0;
    //}

    //if (SSL_library_init() == -1) {
    //    dbl_log_writestd(DBL_LOG_ERROR, errno, "SSL_library_init() failed");
    //    return 1;
    //}

    //cyc = dbl_cycle_new(DBL_CONFIG_PATH, DBL_PID_PATH);
    //if (cyc == NULL) {
    //    return 1;
    //}

    //if (dbl_deamon() != 0) {
    //    dbl_cycle_free(cyc);
    //    return 1;
    //}

    //dbl_process_cycle(cyc);
    //dbl_cycle_free(cyc);
    //return 0;
    //
    
}
