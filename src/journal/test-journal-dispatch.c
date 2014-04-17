/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#include <systemd/sd-journal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "log.h"
#include "dbg.h"

#define MSG_STR_LEN 30

int main(int argc, char *argv[]) {
        long msg_per_sec, test_period;
        long msg_total, msg_count;
        long msg_delay_us;
        char str[MSG_STR_LEN];
        char random = 0;

        if (argc < 3) {
                printf("Usage: test-journald-dispatch msg_per_sec test_period_sec <-v>\n");
                return -1;
        }

        msg_per_sec = strtol(argv[1], NULL, 10);
        test_period = strtol(argv[2], NULL, 10);

        if (msg_per_sec == 0)
                return -1;

        msg_total = msg_per_sec * test_period;
        msg_delay_us = 1000000 / msg_per_sec;

        if (argc == 4 && strcmp(argv[3], "-r")==0) {
                random = 1;
        }

//        printf("Messages per second = %ld, test period = %ld, message delay = %ld us, msg_total = %ld\n",
//               msg_per_sec, test_period, msg_delay_us, msg_total);

        for (msg_count = 0; msg_count < msg_total; msg_count++) {
                if (random) {
                        snprintf(str, MSG_STR_LEN, "MESSAGE=%d", rand());
                        sd_journal_send(str, NULL);
                } else {
                        sd_journal_send("MESSAGE=foobar", NULL);
                }
                usleep(msg_delay_us);
        }

        return 0;
}
