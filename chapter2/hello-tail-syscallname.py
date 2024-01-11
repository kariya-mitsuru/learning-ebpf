#!/usr/bin/python3  
from bcc import BPF
from bcc.syscall import syscalls
import ctypes as ct

syscall_no = {name:no for no, name in syscalls.items()}

program = rf"""
BPF_PROG_ARRAY(syscall, 350);

int hello(struct bpf_raw_tracepoint_args *ctx) {{
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}}

int hello_exec(void *ctx) {{
    bpf_trace_printk("Executing a program");
    return 0;
}}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {{
    int opcode = ctx->args[1];
    switch (opcode) {{
        case {syscall_no[b"timer_create"]}:
            bpf_trace_printk("Creating a timer");
            break;
        case {syscall_no[b"timer_delete"]}:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }}
    return 0;
}}

int ignore_opcode(void *ctx) {{
    return 0;
}}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")

prog_array[ct.c_int(syscall_no[b"execve"])] = ct.c_int(exec_fn.fd)

for no, name in syscalls.items():
    if name.startswith(b"timer_"):
        prog_array[ct.c_int(no)] = ct.c_int(timer_fn.fd)

# Ignore some syscalls that come up a lot
ignore_syscalls = [
    b"bpf",
    b"clock_nanosleep",
    b"close",
    b"epoll_ctl",
    b"epoll_pwait",
    b"epoll_wait",
    b"fcntl",
    b"futex",
    b"getpid",
    b"getrandom",
    b"ioctl",
    b"madvise",
    b"nanosleep",
    b"newfstatat",
    b"openat",
    b"poll",
    b"ppoll",
    b"pselect6",
    b"read",
    b"rt_sigaction",
    b"rt_sigprocmask",
    b"rt_sigreturn",
    b"statx",
    b"tgkill",
    b"write",
    b"writev",
]
for name in ignore_syscalls:
    if name in syscall_no:
        prog_array[ct.c_int(syscall_no[name])] = ct.c_int(ignore_fn.fd)

b.trace_print()
