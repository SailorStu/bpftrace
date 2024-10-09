#BPF Playground

##Using bpftrace

On the current ubuntu 20.x distros, one can use bpftrace to investigate system call ongoings.

We have choices of hooking syscalls on entry or on exit. 

We must run bpftrace as root.

What probes can we trace?
In this case, let's see all `sendto` occurrences.
```
sudo bpftrace -lv '*sendto'

kfunc:vmlinux:__ia32_sys_sendto
    const struct pt_regs * __unused
    long int retval
kfunc:vmlinux:__sys_sendto
    int fd
    void * buff
    size_t len
    unsigned int flags
    struct sockaddr * addr
    int addr_len
    int retval
kfunc:vmlinux:__x64_sys_sendto
    const struct pt_regs * __unused
    long int retval
kprobe:__ia32_sys_sendto
kprobe:__sys_sendto
kprobe:__x64_sys_sendto
tracepoint:syscalls:sys_enter_sendto
    int __syscall_nr
    int fd
    void * buff
    size_t len
    unsigned int flags
    struct sockaddr * addr
    int addr_len
tracepoint:syscalls:sys_exit_sendto
    int __syscall_nr
    long ret

```

```
Generating a vmlinux.h file for kicks. 
This is unnecessary for bpftrace, but I show it anyways.

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

```


Our source code for our sendt-_count.bt is the following. We have to test the
IP payload which is ICMP. 


```
struct S {
    uint8_t  Type;  // 8 = echo(ping)
    uint8_t  Code;  // 0 
    uint16_t Checksum;
    uint16_t Id;
    uint16_t Seq;
}

BEGIN {
    printf("Tracing sendto() syscalls.\n");
}

END {
    printf("Done tracing sendto() syscalls.\n");
    // clear maps here
}

// Check if the buffer is AF_INET then look for ICMP echo request(smells like) 
// and then count the found matches.
tracepoint:syscalls:sys_enter_sendto { 
    if (args.len > sizeof(struct S)) {
        $s = (struct S *)args.buff;
        if (args.addr->sa_family == AF_INET &&
            $s->Type == 8 && $s->Code == 0 && $s->Checksum > 0 && $s->Id > 0 && $s->Seq > 0) {
/*
 Debug only:
            printf(" ICMP Type = %02x, Code = %02x, Checksum = %04x, Id = %04x, Seq = %04x\n",
                    $s->Type, $s->Code, $s->Checksum, $s->Id, $s->Seq);
*/
            @[comm] = count(); 
        }
    }
}
```



e.g. Let's run 'ping 9.9.9.9 -c 5'  and see if we can detect our use of ping. Ping sends ICMP and the buffer 
passed to sendto() contains icmp header:
    uint8_t  Type  // 8 = echo(ping)
    uint8_t  Code  // 0 
    uint16_t Checksum
    uint16_t Id
    uint16_t Seq
```
sudo bpftrace sendto_count.bt -c 'ping 9.9.9.9 -c5 -s16'
```

should show something of the effect:
```
Attaching 3 probes...
Tracing sendto() syscalls.
PING 9.9.9.9 (9.9.9.9) 16(44) bytes of data.
24 bytes from 9.9.9.9: icmp_seq=1 ttl=128 time=36.4 ms
24 bytes from 9.9.9.9: icmp_seq=2 ttl=128 time=32.9 ms
24 bytes from 9.9.9.9: icmp_seq=3 ttl=128 time=40.0 ms
24 bytes from 9.9.9.9: icmp_seq=4 ttl=128 time=37.2 ms
24 bytes from 9.9.9.9: icmp_seq=5 ttl=128 time=32.4 ms

--- 9.9.9.9 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4013ms
rtt min/avg/max/mdev = 32.360/35.782/39.976/2.820 ms
Done tracing sendto() syscalls.


@[ping]: 5


```
We can see that ping called sys_sendto() 5 times. 

Alternatively, we can hook the result of the syscall too.
