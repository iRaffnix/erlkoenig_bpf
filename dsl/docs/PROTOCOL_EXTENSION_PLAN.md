# Protocol Extension Plan — `on_*` Makro-Pattern

**Datum**: 2026-03-13
**Status**: Geplant

---

## 1. Ueberblick

Das `on_*` Pattern abstrahiert Paket-Parsing komplett weg. Der User schreibt
nur Geschaeftslogik, der Builder generiert: Data-Bindings, Bounds-Check,
Protokoll-Guards, Feld-Bindings.

**Bestehend**: `on_ipv4`, `on_tcp`, `on_udp`, `on_icmp`

**Neu**: 7 weitere Protokolle.

---

## 2. Neue Protokolle

### 2.1 IPv6 (`on_ipv6`)

ETH(14) + IPv6(40) = **54 Bytes**.

| Feld | Offset | Read | Beschreibung |
|------|--------|------|-------------|
| `next_header` | 20 | `read_u8` | Protokoll (6=TCP, 17=UDP) |
| `hop_limit` | 21 | `read_u8` | Wie TTL bei IPv4 |
| `payload_length` | 18 | `read_u16_be` | Payload-Laenge |
| `src_ip6_hi` | 22 | `read_u32_be` | Erste 4 Bytes der Source (Netz-Prefix) |
| `src_ip6_lo` | 34 | `read_u32_be` | Letzte 4 Bytes der Source (Interface-ID) |
| `dst_ip6_hi` | 38 | `read_u32_be` | Erste 4 Bytes der Dest |
| `dst_ip6_lo` | 50 | `read_u32_be` | Letzte 4 Bytes der Dest |

Guard: `ethertype != 0x86DD`

Einschraenkung: IPv6 Extension Headers werden nicht geparst.
`next_header` bezieht sich auf den Fixed Header.

### 2.2 TCP ueber IPv6 (`on_tcp6`)

ETH(14) + IPv6(40) + TCP(20) = **74 Bytes**. TCP beginnt bei Byte 54.

Erbt alle IPv6-Felder, plus:

| Feld | Offset | Read |
|------|--------|------|
| `src_port` | 54 | `read_u16_be` |
| `dst_port` | 56 | `read_u16_be` |
| `flags` | 67 | `read_u8` |
| `is_syn` | — | `(flags & 0x02) != 0` |
| `is_ack` | — | `(flags & 0x10) != 0` |
| `is_fin` | — | `(flags & 0x01) != 0` |
| `is_rst` | — | `(flags & 0x04) != 0` |

Guards: `ethertype != 0x86DD`, `next_header != 6`

### 2.3 UDP ueber IPv6 (`on_udp6`)

ETH(14) + IPv6(40) + UDP(8) = **62 Bytes**. UDP beginnt bei Byte 54.

Erbt alle IPv6-Felder, plus:

| Feld | Offset | Read |
|------|--------|------|
| `src_port` | 54 | `read_u16_be` |
| `dst_port` | 56 | `read_u16_be` |
| `udp_length` | 58 | `read_u16_be` |

Guards: `ethertype != 0x86DD`, `next_header != 17`

### 2.4 ARP (`on_arp`)

ETH(14) + ARP(28) = **42 Bytes**. ARP beginnt bei Byte 14.

| Feld | Offset | Read | Beschreibung |
|------|--------|------|-------------|
| `arp_op` | 20 | `read_u16_be` | 1=Request, 2=Reply |
| `sender_ip` | 28 | `read_u32_be` | Sender IPv4 |
| `target_ip` | 38 | `read_u32_be` | Target IPv4 |
| `sender_mac_hi` | 22 | `read_u32_be` | Erste 4 Bytes Sender MAC |
| `sender_mac_lo` | 26 | `read_u16_be` | Letzte 2 Bytes Sender MAC |
| `target_mac_hi` | 32 | `read_u32_be` | Erste 4 Bytes Target MAC |
| `target_mac_lo` | 36 | `read_u16_be` | Letzte 2 Bytes Target MAC |

Guard: `ethertype != 0x0806`

### 2.5 VLAN-tagged IPv4 (`on_vlan_ipv4`)

802.1Q fuegt 4 Bytes nach Byte 12 ein. Alle IP-Offsets verschieben sich um +4.

ETH(14) + VLAN(4) + IPv4(20) = **38 Bytes**.

| Feld | Offset | Read | Beschreibung |
|------|--------|------|-------------|
| `outer_ethertype` | 12 | `read_u16_be` | Muss 0x8100 sein |
| `vlan_tci` | 14 | `read_u16_be` | PCP(3) + DEI(1) + VLAN-ID(12) |
| `ethertype` | 16 | `read_u16_be` | Innerer EtherType, muss 0x0800 sein |
| `src_ip` | 30 | `read_u32_be` | 26+4 |
| `dst_ip` | 34 | `read_u32_be` | 30+4 |
| `protocol` | 27 | `read_u8` | 23+4 |
| `ttl` | 26 | `read_u8` | 22+4 |
| `total_length` | 20 | `read_u16_be` | 16+4 |

Guards: `outer_ethertype != 0x8100`, `ethertype != 0x0800`

Einschraenkung: Nur Single-Tag (802.1Q). QinQ (0x88A8) nicht unterstuetzt.

### 2.6 VLAN-tagged TCP (`on_vlan_tcp`)

ETH(14) + VLAN(4) + IPv4(20) + TCP(20) = **58 Bytes**. TCP bei Byte 38.

Erbt alle VLAN-IPv4-Felder, plus:

| Feld | Offset | Read |
|------|--------|------|
| `src_port` | 38 | `read_u16_be` |
| `dst_port` | 40 | `read_u16_be` |
| `flags` | 51 | `read_u8` |
| `is_syn/ack/fin/rst` | — | Flag-Helpers |

Guards: `outer_ethertype != 0x8100`, `ethertype != 0x0800`, `protocol != 6`

### 2.7 DNS ueber UDP (`on_dns`)

ETH(14) + IPv4(20) + UDP(8) + DNS(12) = **54 Bytes**. DNS bei Byte 42.

| Feld | Offset | Read | Beschreibung |
|------|--------|------|-------------|
| Alle IPv4+UDP Felder | | | |
| `dns_id` | 42 | `read_u16_be` | Transaction ID |
| `dns_flags` | 44 | `read_u16_be` | QR/Opcode/AA/TC/RD/RA |
| `dns_qcount` | 46 | `read_u16_be` | Anzahl Fragen |
| `dns_acount` | 48 | `read_u16_be` | Anzahl Antworten |

Guards: `ethertype != 0x0800`, `protocol != 17`, `src_port != 53 AND dst_port != 53`

Der dritte Guard braucht einen neuen Guard-Typ `{:both_!=, var1, var2, value}`:
"Wenn WEDER var1 noch var2 den Wert hat → kein DNS-Paket → :pass".

---

## 3. Implementierungsschritte

| # | Datei | Aenderung |
|---|-------|-----------|
| 1 | `builder.ex` | `wrap_with_preamble/2`: `{:both_!=, ...}` Guard-Typ |
| 2 | `builder.ex` | 7 neue `protocol_preamble/1` Klauseln |
| 3 | `xdp.ex` | 7 neue `on_*` Makros + moduledoc |
| 4 | `constants.ex` | `@eth_p_8021q`, `@eth_p_ipv6`, etc. |
| 5 | `protocol_test.exs` | 7 neue `describe` Bloecke |
| 6 | `examples/` | 4 neue Beispiele (09-12) |

### Abhaengigkeiten

```
Schritt 1 (both_!= Guard) ──┐
                             ├──→ Schritt 2 (Preambles) ──→ Schritt 3 (Makros)
Schritt 4 (Constants) ──────┘         │
                                      ├──→ Schritt 5 (Tests)
                                      └──→ Schritt 6 (Beispiele)
```

---

## 4. Neue Beispiele

### 09_ipv6_filter.ex
```elixir
defmodule Ipv6Filter do
  use ErlkoenigEbpfDsl.XDP
  xdp "ipv6_filter" do
    map :hop_stats, :hash, key: :u32, value: :u64, max_entries: 256
    on_ipv6 do
      count = map_lookup(hop_stats, hop_limit)
      map_update(hop_stats, hop_limit, count + 1)
      :pass
    end
  end
end
```

### 10_arp_monitor.ex
```elixir
defmodule ArpMonitor do
  use ErlkoenigEbpfDsl.XDP
  xdp "arp_monitor" do
    map :arp_count, :hash, key: :u32, value: :u64, max_entries: 4096
    on_arp do
      count = map_lookup(arp_count, sender_ip)
      map_update(arp_count, sender_ip, count + 1)
      if count > 50 do
        :drop
      else
        :pass
      end
    end
  end
end
```

### 11_vlan_firewall.ex
```elixir
defmodule VlanFirewall do
  use ErlkoenigEbpfDsl.XDP
  xdp "vlan_firewall" do
    map :allowed_ports, :hash, key: :u32, value: :u64, max_entries: 1024
    on_vlan_tcp do
      allowed = map_lookup(allowed_ports, dst_port)
      if allowed != 0 do
        :pass
      else
        :drop
      end
    end
  end
end
```

### 12_dns_monitor.ex
```elixir
defmodule DnsMonitor do
  use ErlkoenigEbpfDsl.XDP
  xdp "dns_monitor" do
    map :dns_queries, :hash, key: :u32, value: :u64, max_entries: 65536
    on_dns do
      count = map_lookup(dns_queries, src_ip)
      map_update(dns_queries, src_ip, count + 1)
      :pass
    end
  end
end
```

---

## 5. Verifikation

Nach Implementierung:
- `mix test` — alle bestehenden + neuen Tests gruen
- `mix compile` — keine Warnings
- Alle 12 Beispiele (01-12) compilieren zu validem BPF-Bytecode
- `rebar3 eunit` — 915 Erlang-Tests weiterhin gruen
