# erlkoenig_bpf

Programmable eBPF data plane for the [erlkoenig](https://github.com/iRaffnix/erlkoenig)
container runtime. Custom language (EBL), custom compiler, custom VM — all in pure Erlang.

**XDP only.** No ELF. No CO-RE. No libbpf. Just raw BPF bytecode for the XDP hook,
compiled from a purpose-built language and an Elixir DSL.

## Elixir DSL

Write XDP firewall programs like this:

```elixir
defmodule SynFloodProtect do
  use ErlkoenigEbpfDsl.XDP

  xdp "syn_flood_protect" do
    map :syn_count, :hash, key: :u32, value: :u64, max_entries: 65536

    on_tcp do
      if is_syn && !is_ack do
        count = map_lookup(syn_count, src_ip)
        if count + 1 > 100, do: :drop, else: :pass
      else
        :pass
      end
    end
  end
end
```

No manual packet parsing. No byte offsets. No bounds checks. Just declare *what* to filter.

Protocol-aware macros handle everything:

| Macro | Handles |
|-------|---------|
| `on_ipv4` | Ethernet + IPv4 bounds check, ethertype |
| `on_tcp` / `on_udp` / `on_icmp` | + L4 protocol dispatch |
| `on_dns` | UDP port 53 |
| `on_arp` | Ethertype 0x0806 |
| `on_ipv6` / `on_tcp6` / `on_udp6` | IPv6 variants |
| `on_vlan_ipv4` / `on_vlan_tcp` | 802.1Q VLAN tagged |

Built-in variables: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `ttl`,
`total_length`, `is_syn`, `is_ack`, `icmp_type`, `udp_length`, `hop_limit`,
`src_ip6_lo`, `vlan_tci`, `sender_ip` (ARP), ...

19 complete examples in [`dsl/examples/`](dsl/examples/), from hello-world to
DDoS protection, DNS amplification detection, and VLAN traffic accounting.

## EBL — The Low-Level Language

The DSL generates EBL, which compiles to BPF bytecode. You can also write EBL directly:

```
xdp syn_flood_protect do
  map :syn_count, hash, key: u32, value: u64, max_entries: 65536

  fn main(ctx) -> action do
    let data = ctx.data
    let data_end = ctx.data_end

    if data + 54 > data_end do return :pass end

    let ethertype = read_u16_be(data, 12)
    if ethertype != 0x0800 do return :pass end

    let protocol = read_u8(data, 23)
    if protocol != 6 do return :pass end

    let flags = read_u8(data, 47)
    if (flags & 0x02) == 0 do return :pass end
    if (flags & 0x10) != 0 do return :pass end

    let src_ip = read_u32_be(data, 26)
    let count = map_lookup(syn_count, src_ip)
    let new_count = count + 1

    if new_count > 100 do
      map_update(syn_count, src_ip, new_count)
      return :drop
    end

    map_update(syn_count, src_ip, new_count)
    return :pass
  end
end
```

EBL features:

- Actions: `:pass`, `:drop`, `:tx`, `:redirect`, `:aborted`
- Types: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `bool`
- User-defined structs with field access
- BPF hash maps with `map_lookup`, `map_update`, `map_delete`
- Control flow: `if`/`elif`/`else`, `for`/`break`/`continue`, `match`
- Packet reads: `read_u8`, `read_u16_be`, `read_u32_be`
- XDP context: `ctx.data`, `ctx.data_end`, `ctx.ingress_ifindex`, ...

22 examples in [`examples/`](examples/).

## Status

| Component | Status |
|-----------|--------|
| EBL Compiler (Lexer, Parser, Typecheck, IR, RegAlloc, Codegen) | Complete |
| Pure Erlang BPF VM | Complete |
| Elixir DSL | Complete |
| uBPF Cross-Validation | Complete |
| Static Pre-Verifier (12 checks) | Complete |
| Compiler Explorer (Web UI) | Complete |
| Kernel Bridge (`bpf()` syscall, XDP attach) | **Not yet implemented** |

**921 tests, 0 failures, 0 Dialyzer warnings.**

## Scope

This project deliberately targets **XDP only**:

- **No ELF output** — the compiler emits raw BPF bytecode, not ELF object files
- **No CO-RE** — no BTF, no `bpf_core_read`, no kernel struct relocation
- **No libbpf** — program loading will use direct `bpf()` syscalls from Erlang
- **No TC/cgroup/socket** — XDP is the only supported program type

This keeps the toolchain minimal and the attack surface small. The goal is a
self-contained eBPF policy engine for erlkoenig containers, not a general-purpose
BPF toolchain.

## Quick Start

### Prerequisites

- Erlang/OTP >= 27
- Elixir >= 1.17 (for the DSL)

### Build & Test

```bash
rebar3 compile
rebar3 eunit        # 918 tests
rebar3 dialyzer     # 0 warnings
```

### Compile and Run

```erlang
rebar3 shell
1> {ok, Bin} = ebl_compile:file("examples/15_syn_flood_protect.ebl").
2> Pkt = ebpf_test_pkt:tcp(#{src_ip => {10,0,0,1}, dst_ip => {10,0,0,2}}).
3> Ctx = ebpf_test_pkt:xdp_ctx(Pkt).
4> {ok, Result} = ebpf_vm:run(Bin, Ctx, #{maps => [{hash, 4, 8, 65536}]}).
```

### Use the Elixir DSL

```bash
cd dsl
mix deps.get
iex -S mix
```

```elixir
iex> SynFloodProtect.compile()
{:ok, <<0x18, ...>>}
```

## Compiler Explorer

A built-in web UI lets you inspect every stage of the compiler pipeline interactively:

```bash
make explorer    # opens http://localhost:8080
```

Paste EBL source and see in real time:

- **Compiled BPF bytecode** with disassembly
- **Register state** at every instruction (R0-R10)
- **Stack and map contents** as the program executes
- **Single-step** through instructions, set breakpoints, run to completion
- **Source mapping** — highlights which EBL line produced which BPF instruction

Useful for understanding what the compiler generates and debugging XDP programs
before loading them into the kernel.

## Architecture

```
Elixir DSL          EBL Source
    |                   |
    +-------+-----------+
            |
            v
         ebl_lexer        Tokenizer
            |
            v
         ebl_parser       Recursive descent + Pratt precedence
            |
            v
         ebl_typecheck    Type inference, XDP context validation
            |
            v
         ebpf_ir_gen      Register-based IR (basic blocks)
            |
            v
         ebpf_regalloc    Linear-scan with spilling
            |
            v
         ebpf_codegen     Two-pass with jump patching
            |
            v
         ebpf_peephole    mov elimination, store-load forwarding
            |
            v
       Raw BPF Bytecode
            |
            +---> ebpf_vm          Pure Erlang VM (test + debug)
            +---> ubpf_port        uBPF C reference (cross-validation)
            +---> ebl_pre_verify   Static analysis (12 checks)
            +---> [Kernel]         bpf() syscall + XDP attach (planned)
```

## Project Structure

```
src/             25 Erlang modules — compiler + VM + explorer
test/            24 test modules (918 tests)
c_src/           C port bridge to uBPF
include/         Header files (AST, IR, opcodes, VM records)
dsl/             Elixir DSL (use ErlkoenigEbpfDsl.XDP)
examples/        22 EBL example programs
scripts/         Build scripts (uBPF)
third-party/     uBPF (external, build instructions in BUILD.md)
```

## uBPF Cross-Validation (Optional)

Compiled programs can be verified against the [uBPF](https://github.com/iovisor/ubpf)
C reference implementation. To enable:

```bash
./scripts/build_ubpf.sh
```

Requires `gcc`, `cmake`, `libelf-dev`.

## Roadmap

- **Kernel Bridge**: `bpf()` syscall wrapper, program load, XDP attach
- **Integration**: Embed as XDP policy engine in [erlkoenig](https://github.com/iRaffnix/erlkoenig) containers

## License

Apache-2.0 — see [LICENSE](LICENSE).
