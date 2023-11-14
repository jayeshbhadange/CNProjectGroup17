#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include "packet.h"

#define SERVER 0x0a00894f

SEC("xdp")
int firewall(struct xdp_md *ctx)
{
    bpf_printk("Request recieved\n");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    unsigned int src_ip = bpf_ntohl(iph->saddr);
    unsigned int dst_ip = bpf_ntohl(iph->daddr);
    bpf_printk("Source IP address: %pI4, Destination IP address: %pI4\n", &iph->saddr, &iph->daddr);

    if (iph->saddr == htonl(SERVER))
    {
        bpf_printk("Request recieved, Dropping!!");
        return XDP_DROP;
    }
    bpf_printk("3\n");
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";

