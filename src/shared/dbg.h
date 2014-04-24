void dbg_print(const char *msg, ...);

void dbg_print_asserted(unsigned int n, unsigned int level, const char *msg, ...);
void dbg_assert(unsigned int n, unsigned int level);

void dbg_time_now(void);
void dbg_timer_start(int index);
void dbg_timer_stop(int index, const char *msg);
void dbg_timer_stop_stats(int index, const char *msg);
