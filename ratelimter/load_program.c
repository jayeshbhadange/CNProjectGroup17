// load_program.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <net/if.h> 
#include <linux/if_link.h>


int main(int argc, char **argv) {
    const char *filename = "rate_limit.o"; // Replace with your compiled eBPF program file name
    const char *iface = "enp0s3"; // Replace with your desired network interface name
    int prog_fd, ret, ifindex;

    // Load the compiled eBPF program
    struct bpf_object *obj;
    struct bpf_program *prog;
    obj = bpf_object__open_file(filename, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object file\n");
        return 1;
    }

    // Find the first program (Assuming only one program exists in the object file)
    bpf_object__for_each_program(prog, obj) {
        prog_fd = bpf_program__fd(prog);
        break;
    }

    // Get the interface index
    /*ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index\n");
        return 1;
    }*/

    // Attach the program to XDP of the specified interface
    ret = bpf_set_link_xdp_fd(2, prog_fd, XDP_FLAGS_SKB_MODE);
    if (ret) {
        fprintf(stderr, "Failed to attach program to interface\n");
        return 1;
    }

    printf("eBPF program successfully loaded and attached to interface %s\n", iface);

    // Close resources
    bpf_object__close(obj);

    return 0;
}


