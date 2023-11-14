#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

struct lladdr_state {
    __u8 tokens;
    __u64 timestamp;
    __u16 pkt_counter;
    __u16 pkt_drop_counter;
} __attribute__((packed));

struct bpf_map_def SEC("maps") lladdr_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8)* ETH_ALEN,
    .value_size = sizeof(struct lladdr_state),
    .max_entries =500,
};
#define NS_IN_SEC 1000000000LL
#define MAX_PACKETS 20 //The maximum number of packet allowed per period
#define INTERVAL 10 // The period in second at which the tokens are refilled 

SEC("xdp")
int xdp_l2_tbf(struct xdp_md *ctx)
{
    struct lladdr_state *elem = NULL, entry = {0};
    __u64  now;
    void   *data_end = (void *)(long) ctx->data_end;
    void   *data= (void *)(long) ctx->data;
    // Map the Ethernet header to the data pointer 
    struct ethhdr *eth = data;
    // Verify size of ethernet header
    __u64 nh_off =sizeof(*eth);
    if (data + nh_off > data_end) {
        return XDP_DROP;
    }
    elem = bpf_map_lookup_elem(&lladdr_map, eth->h_source);
    if (elem== NULL) {
        entry.tokens= MAX_PACKETS;
        entry.timestamp= bpf_ktime_get_ns();
        entry.pkt_counter = 1; // The first packet is free 
        bpf_map_update_elem(&lladdr_map, eth->h_source, &entry, BPF_ANY);
    }else{
        if (elem->tokens == 0) {
            now = bpf_ktime_get_ns();
            if (now - elem->timestamp> (NS_IN_SEC* INTERVAL)) {
                elem->timestamp = now;
                elem->tokens = MAX_PACKETS;
            } else { 
                elem->pkt_drop_counter++;
                return XDP_DROP;
            }
        }
        elem->tokens--;
        elem->pkt_counter++;
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

