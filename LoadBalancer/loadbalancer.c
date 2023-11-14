#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stddef.h>
#include <linux/tcp.h>

#define XDP_PASS 0
#define XDP_DROP 1




struct backend_container {
    char mac_addr[18];  // 17 characters for the MAC address plus null-terminator
    int weight;
};

struct backend_container backend_containers[] = {
    {"00:0c:29:63:b5:4e", 1},
    {"00:0c:29:63:b5:4f", 1},
};


int xdp_load_balancer(struct xdp_md *ctx) {
    // struct ethhdr *eth = (struct ethhdr *)ctx->data;
    struct ethhdr *eth = __builtin_pointer_cast<struct ethhdr *>(ctx->data);
    struct iphdr *ip = (struct iphdr *)(ctx->data + sizeof(struct ethhdr));

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct backend_container *backend_container = NULL;
        int dst_port = 0;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
            dst_port = tcp->dest;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
            dst_port = udp->dest;
        }

        // Round-robin load balancing
        int backend_index = dst_port % (sizeof(backend_containers) / sizeof(backend_containers[0]));
        backend_container = &backend_containers[backend_index];

        memcpy(eth->h_dest, backend_container->mac_addr, ETH_ALEN);

        return XDP_PASS;
    } else {
        return XDP_DROP;
    }
}

int main() {
    struct bpf_prog *xdp_prog = bpf_prog_create(xdp_load_balancer);
    if (xdp_prog == NULL) {
        return -1;
    }

    int err = bpf_xdp_attach(xdp_prog, "eth0", 0);
    if (err < 0) {
        return err;
    }

    getchar();

    bpf_xdp_detach(xdp_prog, "eth0");

    bpf_prog_destroy(xdp_prog);

    return 0;
}
