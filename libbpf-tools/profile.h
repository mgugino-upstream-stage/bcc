#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN 16
#define MAX_CPU_NR	512

struct key_t {
    __u32 pid;
    __u64 tgid;
    // u64 kernel_ip;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};

#endif /* __PROFILE_H */
