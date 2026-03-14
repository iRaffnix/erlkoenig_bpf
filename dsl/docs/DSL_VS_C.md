# Elixir DSL vs C/XDP — Vergleich

Dieses Dokument zeigt typische XDP-Programme in C und die aequivalente
Elixir-DSL-Version. Ziel: Gleiche Funktionalitaet, Bruchteil des Codes,
keine manuellen Bounds Checks, keine Pointer-Arithmetik.

---

## 1. DDoS Blocklist Filter

Pakete von bekannten Angreifer-IPs droppen, Drop-Zaehler fuehren.

### C/XDP (45 LOC)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} blocklist SEC(".maps");

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    __u32 *drop_cnt = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (drop_cnt) {
        __sync_fetch_and_add(drop_cnt, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Elixir DSL (12 LOC)

```elixir
defmodule DdosBlocklist do
  use ErlkoenigEbpfDsl.XDP

  xdp "ddos_blocklist" do
    map :blocklist, :hash, key: :u32, value: :u64, max_entries: 10240

    on_ipv4 do
      drop_cnt = map_lookup(blocklist, src_ip)
      if drop_cnt > 0 do
        map_update(blocklist, src_ip, drop_cnt + 1)
        :drop
      else
        :pass
      end
    end
  end
end
```

**Reduktion: 73% weniger Code.** Bounds Checks, EtherType-Guard, Header-Parsing
und Feld-Bindings werden automatisch generiert.

---

## 2. SYN Flood Protection

TCP-SYN-Pakete pro Source-IP zaehlen, ab Threshold droppen.

### C/XDP (~65 LOC)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} syn_count SEC(".maps");

SEC("xdp")
int xdp_syn_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Nur SYN ohne ACK
    if (!(tcp->syn && !tcp->ack))
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u64 *cnt = bpf_map_lookup_elem(&syn_count, &src);
    __u64 new_cnt = cnt ? *cnt + 1 : 1;
    bpf_map_update_elem(&syn_count, &src, &new_cnt, BPF_ANY);

    if (new_cnt > 100)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Elixir DSL (16 LOC)

```elixir
defmodule SynFloodProtect do
  use ErlkoenigEbpfDsl.XDP

  xdp "syn_flood" do
    map :count, :hash, key: :u32, value: :u64, max_entries: 65536

    on_tcp do
      if is_syn && !is_ack do
        c = map_lookup(count, src_ip)
        map_update(count, src_ip, c + 1)
        if c > 100, do: :drop, else: :pass
      else
        :pass
      end
    end
  end
end
```

**Reduktion: 75% weniger Code.** `on_tcp` generiert automatisch:
ETH-Bounds-Check, EtherType==0x0800, IPv4-Bounds-Check, protocol==6,
TCP-Bounds-Check, und alle Feld-Bindings inkl. `is_syn`/`is_ack`.

---

## 3. TTL-basierter Filter mit Statistik

Pakete mit verdaechtig niedrigem TTL droppen, TTL-Verteilung zaehlen.

### C/XDP (~50 LOC)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} ttl_stats SEC(".maps");

SEC("xdp")
int xdp_ttl_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ttl = ip->ttl;

    // TTL-Statistik aktualisieren
    __u64 *count = bpf_map_lookup_elem(&ttl_stats, &ttl);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&ttl_stats, &ttl, &new_count, BPF_ANY);

    // TTL <= 2 ist verdaechtig (Traceroute, Scanning)
    if (ttl <= 2)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Elixir DSL (14 LOC)

```elixir
defmodule TtlFilter do
  use ErlkoenigEbpfDsl.XDP

  xdp "ttl_filter" do
    map :ttl_stats, :hash, key: :u32, value: :u64, max_entries: 256

    on_ipv4 do
      count = map_lookup(ttl_stats, ttl)
      map_update(ttl_stats, ttl, count + 1)
      if ttl <= 2, do: :drop, else: :pass
    end
  end
end
```

**Reduktion: 72% weniger Code.**

---

## 4. ICMP Rate Limiter

Echo Requests (Ping) pro Source-IP zaehlen, ab Threshold droppen.

### C/XDP (~60 LOC)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} ping_count SEC(".maps");

SEC("xdp")
int xdp_icmp_limit(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // Nur Echo Request (Typ 8)
    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u64 *cnt = bpf_map_lookup_elem(&ping_count, &src);
    __u64 new_cnt = cnt ? *cnt + 1 : 1;
    bpf_map_update_elem(&ping_count, &src, &new_cnt, BPF_ANY);

    if (new_cnt > 50)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Elixir DSL (16 LOC)

```elixir
defmodule IcmpRateLimit do
  use ErlkoenigEbpfDsl.XDP

  xdp "icmp_rate_limit" do
    map :ping_count, :hash, key: :u32, value: :u64, max_entries: 4096

    on_icmp do
      if icmp_type == @icmp_echo_request do
        c = map_lookup(ping_count, src_ip)
        map_update(ping_count, src_ip, c + 1)
        if c > 50, do: :drop, else: :pass
      else
        :pass
      end
    end
  end
end
```

**Reduktion: 73% weniger Code.** `@icmp_echo_request` statt Magic Number `8`.

---

## 5. Port Firewall

Nur bestimmte TCP-Ports durchlassen (Allowlist).

### C/XDP (~55 LOC)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} allowed SEC(".maps");

SEC("xdp")
int xdp_port_fw(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 port = bpf_ntohs(tcp->dest);
    __u32 *ok = bpf_map_lookup_elem(&allowed, &port);
    if (ok)
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
```

### Elixir DSL (13 LOC)

```elixir
defmodule PortFirewall do
  use ErlkoenigEbpfDsl.XDP

  xdp "port_firewall" do
    map :allowed, :hash, key: :u32, value: :u32, max_entries: 64

    on_tcp do
      ok = map_lookup(allowed, dst_port)
      if ok > 0, do: :pass, else: :drop
    end
  end
end
```

**Reduktion: 76% weniger Code.**

---

## 6. Protocol Profiler (Struct-Value Workaround)

Pakete und Bytes pro IP-Protokoll zaehlen. Das Original nutzt
`BPF_MAP_TYPE_PERCPU_ARRAY` mit `struct datarec` — beides Features die
unsere DSL (noch) nicht hat. Workaround: zwei separate Hash-Maps.

### C/XDP (~45 LOC)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct datarec);
} protocol_stats SEC(".maps");

SEC("xdp")
int xdp_profiler(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        __u32 proto = ip->protocol;
        struct datarec *rec = bpf_map_lookup_elem(&protocol_stats, &proto);
        if (rec) {
            rec->rx_packets++;
            rec->rx_bytes += (data_end - data);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Elixir DSL (16 LOC)

```elixir
defmodule ProtocolProfiler do
  use ErlkoenigEbpfDsl.XDP

  xdp "protocol_profiler" do
    map :proto_packets, :hash, key: :u32, value: :u64, max_entries: 256
    map :proto_bytes,   :hash, key: :u32, value: :u64, max_entries: 256

    on_ipv4 do
      pkts = map_lookup(proto_packets, protocol)
      map_update(proto_packets, protocol, pkts + 1)

      bytes = map_lookup(proto_bytes, protocol)
      map_update(proto_bytes, protocol, bytes + total_length)

      :pass
    end
  end
end
```

**Reduktion: 64% weniger Code.** Erfordert zwei Maps statt einer mit
Struct-Value — ein Trade-off der DSL-Vereinfachung.

### Aktuelle DSL-Einschraenkungen (sichtbar in diesem Beispiel)

| Feature | C/XDP | DSL | Status |
|---------|-------|-----|--------|
| `BPF_MAP_TYPE_PERCPU_ARRAY` | ja | nein | Backlog |
| Struct als Map-Value | ja | nein | Backlog |
| In-Place Map-Update (`rec->field++`) | ja | nein (read-modify-write) | By Design |
| `data_end - data` (Paketlaenge) | ja | `total_length` (IP-Header-Feld) | Semantisch aequivalent |

---

## Was die DSL automatisch generiert

Jedes `on_*`-Makro erzeugt unsichtbar:

| Aspekt | C (manuell) | DSL (automatisch) |
|--------|-------------|-------------------|
| Ethernet Bounds Check | `(void *)(eth + 1) > data_end` | generiert |
| EtherType Guard | `eth->h_proto != bpf_htons(ETH_P_IP)` | generiert |
| IPv4 Bounds Check | `(void *)(ip + 1) > data_end` | generiert |
| Protocol Guard | `ip->protocol != IPPROTO_TCP` | generiert (bei `on_tcp` etc.) |
| L4 Bounds Check | `(void *)(tcp + 1) > data_end` | generiert |
| Feld-Bindings | `ip->saddr`, `tcp->dest`, ... | `src_ip`, `dst_port`, ... |
| Byte-Order-Konvertierung | `bpf_htons()` / `bpf_ntohs()` | automatisch (big-endian reads) |
| `data`/`data_end` Zeiger | manuell aus `ctx` | automatisch |
| Map-FD + Stack-Allokation | `bpf_map_lookup_elem(&map, &key)` | `map_lookup(map, key)` |

## Verfuegbare Protokoll-Makros

| Makro | Schichten | Auto-Guards |
|-------|-----------|-------------|
| `on_ipv4` | ETH + IPv4 | EtherType == 0x0800 |
| `on_tcp` | ETH + IPv4 + TCP | + protocol == 6 |
| `on_udp` | ETH + IPv4 + UDP | + protocol == 17 |
| `on_icmp` | ETH + IPv4 + ICMP | + protocol == 1 |
| `on_ipv6` | ETH + IPv6 | EtherType == 0x86DD |
| `on_tcp6` | ETH + IPv6 + TCP | + next_header == 6 |
| `on_udp6` | ETH + IPv6 + UDP | + next_header == 17 |
| `on_arp` | ETH + ARP | EtherType == 0x0806 |
| `on_vlan_ipv4` | ETH + 802.1Q + IPv4 | EtherType == 0x8100, inner == 0x0800 |
| `on_vlan_tcp` | ETH + 802.1Q + IPv4 + TCP | + protocol == 6 |
| `on_dns` | ETH + IPv4 + UDP + DNS | + protocol == 17, port == 53 |

## Zusammenfassung

| Metrik | C/XDP | Elixir DSL | Faktor |
|--------|-------|------------|--------|
| Durchschnitt LOC | ~53 | ~14 | **~4x weniger** |
| Header-Includes | 3-5 | 0 | entfaellt |
| Bounds Checks | 2-4 manuell | 0 manuell | automatisch |
| Pointer-Arithmetik | ja | nein | entfaellt |
| Byte-Order Bugs | moeglich | unmoeglich | eliminiert |
| Compile-Target | gleich: BPF Bytecode | gleich: BPF Bytecode | identisch |
