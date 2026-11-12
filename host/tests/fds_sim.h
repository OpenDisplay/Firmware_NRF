#ifndef HOST_FDS_SIM_H
#define HOST_FDS_SIM_H
#include <setjmp.h>
extern jmp_buf *fds_sim_jmp;     /* where a simulated power cut lands */
extern unsigned fds_sim_steps;   /* flash steps run so far */
void fds_sim_pump(void);         /* run queued operations and deliver their events */
void fds_sim_cut_after(int steps);
void fds_sim_reboot(void);       /* drop the queue and the callback; flash contents stay */
void fds_sim_wipe(void);
int fds_sim_valid_records(void);
#endif
