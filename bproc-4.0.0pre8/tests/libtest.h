#ifndef _LIBTEST_H_
#define _LIBTEST_H_

void dumpfds(void);
void sayhi(void);
void iter_start(void);
void iter_end(void);
int  get_node(void);

extern char rank;
extern int stat_interval;
extern int target_node;
extern int verbose;
#endif
