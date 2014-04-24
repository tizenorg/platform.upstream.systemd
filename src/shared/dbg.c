#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

#include "dbg.h"

#define DBG_LOG_FILE        "/root/dbg_log.txt"

#define DBG_TIMER_STATS_RANGE 200
#define DBG_TIMER_STATS_COUNT 100000

#define DBG_TIMER_COUNT 100

static char asserted[25];

void dbg_print(const char *msg, ...) {
        int fd;
        static char buff[250];
        int len;

        va_list args;
        va_start(args, msg);

        len = vsnprintf(buff, sizeof(buff), msg, args);

        fd = open(DBG_LOG_FILE, O_CREAT | O_WRONLY | O_APPEND,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        write(fd, buff, len);
        close(fd);

        va_end(args);
}

void dbg_print_asserted(unsigned int n, unsigned int level, const char *msg, ...) {
        if (asserted[n] >= level) {
                va_list args;
                va_start(args, msg);
                dbg_print(msg, args);
                va_end(args);
        }
}

void dbg_assert(unsigned int n, unsigned int level) {
        asserted[n] = level;
}

void dbg_time_now(void) {
        time_t rawtime;
        struct tm *timeinfo;
        char buffer[50];

        time (&rawtime);
        timeinfo = localtime (&rawtime);

        strftime(buffer, sizeof(buffer), "%H:%M:%S", timeinfo);
        dbg_print("%s\n", buffer);
}

static void dbg_timer_stats(int time, const char *msg) {
        static unsigned int stats[DBG_TIMER_STATS_RANGE] = { 0 };
        static unsigned int count = 0;
        static unsigned int count_ovrange = 0;
        int i, j;
        const int rows = 25;

        if (time < DBG_TIMER_STATS_RANGE) {
                stats[time]++;
                count++;
        } else {
                count_ovrange++;
                //dbg_print("%ld", time);
        }

        if ((count+count_ovrange) >= DBG_TIMER_STATS_COUNT) {
                dbg_print("%s\n", msg);
                for (i = 0; i < rows; i++) {
                        for (j = i; j < DBG_TIMER_STATS_RANGE; j+=rows) {
                                dbg_print("%3d: %5d |\t", j, stats[j]);
                                stats[j] = 0;
                        }
                        dbg_print("\n");
                }
                dbg_time_now();
                dbg_print("samples = %d, over range = %d\n\n",
                          count+count_ovrange, count_ovrange);
                count = 0;
                count_ovrange = 0;
        }
}

static void dbg_timer(int start, int index, const char *msg) {
        static struct timespec tstart[DBG_TIMER_COUNT], tend;
        static char tactive[DBG_TIMER_COUNT] = { 0 };
        static long int telapsed;

        if (!(index < DBG_TIMER_COUNT))
                return;

        if (start == 0) {
                if (tactive[index]) {
                        tactive[index] = 2;
                        return;
                }
                clock_gettime(CLOCK_REALTIME, &tstart[index]);
                tactive[index] = 1;
                return;
        }

        clock_gettime(CLOCK_REALTIME, &tend);
        telapsed = (long int)(tend.tv_nsec - tstart[index].tv_nsec);
        if (start == 2) {
                dbg_timer_stats(telapsed / 1000, msg);
                tactive[index] = 0;
                return;
        }
        dbg_print("%s %ld us%s\n",  msg, telapsed / 1000,
                  tactive[index] == 2 ? " time in use!" : "");
        tactive[index] = 0;
}

void dbg_timer_start(int index) {
        dbg_timer(0, index, NULL);
}

void dbg_timer_stop(int index, const char *msg) {
        dbg_timer(1, index, msg);
}

void dbg_timer_stop_stats(int index, const char *msg) {
        dbg_timer(2, index, msg);
}
