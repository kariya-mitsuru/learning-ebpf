#!/usr/bin/python3  
from bcc import BPF
import ctypes as ct

program = r"""
BPF_PROG_ARRAY(syscall, 350);

int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

int hello_exec(void *ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

int ignore_opcode(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")
prog_array[ct.c_int( 59)] = ct.c_int(exec_fn.fd)  # __NR_execve
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd) # __NR_timer_create
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd) # __NR_timer_delete
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd) # __NR_timer_getoverrun
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd) # __NR_timer_gettime
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd) # __NR_timer_settime

# Ignore some syscalls that come up a lot
prog_array[ct.c_int(321)] = ct.c_int(ignore_fn.fd) # __NR_bpf
prog_array[ct.c_int(230)] = ct.c_int(ignore_fn.fd) # __NR_clock_nanosleep
prog_array[ct.c_int(  3)] = ct.c_int(ignore_fn.fd) # __NR_close
prog_array[ct.c_int(233)] = ct.c_int(ignore_fn.fd) # __NR_epoll_ctl
prog_array[ct.c_int(281)] = ct.c_int(ignore_fn.fd) # __NR_epoll_pwait
prog_array[ct.c_int(232)] = ct.c_int(ignore_fn.fd) # __NR_epoll_wait
prog_array[ct.c_int( 72)] = ct.c_int(ignore_fn.fd) # __NR_fcntl
prog_array[ct.c_int(202)] = ct.c_int(ignore_fn.fd) # __NR_futex
prog_array[ct.c_int( 39)] = ct.c_int(ignore_fn.fd) # __NR_getpid
prog_array[ct.c_int(318)] = ct.c_int(ignore_fn.fd) # __NR_getrandom
prog_array[ct.c_int( 16)] = ct.c_int(ignore_fn.fd) # __NR_ioctl
prog_array[ct.c_int( 28)] = ct.c_int(ignore_fn.fd) # __NR_madvise
prog_array[ct.c_int( 35)] = ct.c_int(ignore_fn.fd) # __NR_nanosleep
prog_array[ct.c_int(262)] = ct.c_int(ignore_fn.fd) # __NR_newfstatat
prog_array[ct.c_int(257)] = ct.c_int(ignore_fn.fd) # __NR_openat
prog_array[ct.c_int(  7)] = ct.c_int(ignore_fn.fd) # __NR_poll
prog_array[ct.c_int(271)] = ct.c_int(ignore_fn.fd) # __NR_ppoll
prog_array[ct.c_int(270)] = ct.c_int(ignore_fn.fd) # __NR_pselect6
prog_array[ct.c_int(  0)] = ct.c_int(ignore_fn.fd) # __NR_read
prog_array[ct.c_int( 13)] = ct.c_int(ignore_fn.fd) # __NR_rt_sigaction
prog_array[ct.c_int( 14)] = ct.c_int(ignore_fn.fd) # __NR_rt_sigprocmask
prog_array[ct.c_int( 15)] = ct.c_int(ignore_fn.fd) # __NR_rt_sigreturn
prog_array[ct.c_int(332)] = ct.c_int(ignore_fn.fd) # __NR_statx
prog_array[ct.c_int(234)] = ct.c_int(ignore_fn.fd) # __NR_tgkill
prog_array[ct.c_int(  1)] = ct.c_int(ignore_fn.fd) # __NR_write
prog_array[ct.c_int( 20)] = ct.c_int(ignore_fn.fd) # __NR_writev

b.trace_print()
