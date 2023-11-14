### Group 17 
### Topic: eBPF for Simple-Firewalling, Load Balancing, and Rate-Limiting
###  Team Members:
1. Pratik Raj               20110144
2. Jayesh Bhadange    20110082
3. Karan Bhardwaj       20110093
4. Balu Karthik Ram     20110036

### Rate LImiting
The ratelimiter folder contains code for implementing rate limiting. 


How to run?


  
    - `Go to the directory where the files are stored.
    
    -  Run the command to compile 'clang -O2 -target bpf -c RateLimit.c -o RateLimit.o'
    
    -  Run the command 'gcc -o load_program load_program.c -lbpf'
    
    -  Load into the kernel by running the command 'sudo ./load_program'
    
    -  Check if attached to interface by 'ip link show <interface name>' (Note default interface in load_program.c is enp0s3, can be changed by modifying ifindex).
    -  Send packets from another terminal and notice the result( Example run 'ping google.com') i.e. packets are dropped if the limit is crossed.
       
    -  Offload  xdp program  from interface by running command 'sudo ip link set dev <interface name> xdp off'

   
### Firewall
The Firewall folder contains code for implementing firewall. 


How to run?


    - `Go to the directory where the files are stored.
    
    -  Run the command to compile 'clang -target bpf -I/usr/include/$(uname -m)-linux-gnu -g -O2 -c hello.bpf.c -o hello.bpf.o'
    
    -  Inspect by running  the command 'llvm-objdump -S hello.bpf.o'
    
    -  Load into kernel by running the command 'bpftool prog load hello.bpf.o /sys/fs/bpf/hello'
    
    -  To check run any of the following commands
        1. ls /sys/fs/bpf
        2. bpftool prog list
        3. bpftool prog show id 540 --pretty
    -  Attach to interface by running the command 'sudo bpftool net attach xdp id 68 dev wlo1'
       
    -  To traceout run 'sudo cat /sys/kernel/debug/tracing/trace_pipe'

    -  To detach the prog run 'sudo bpftool net detach xdp dev wlo1'

   

### Load Balancer
The LoadBalancer folder contains code for implementing load balancing.

How to run?


    -  Go to the directory where the files are stored.
    -  Run the command to compile 'clang xdp_loadBalancer.c -o xdp_loadBalancer -lelf -lbpf'
