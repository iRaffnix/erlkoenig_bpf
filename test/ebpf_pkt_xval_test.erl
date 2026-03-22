%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(ebpf_pkt_xval_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("ebpf_vm.hrl").

%%% ===================================================================
%%% Cross-validation: Endian + Packet Parsing (Erlang VM vs uBPF)
%%%
%%% Every test runs the SAME bytecode in both VMs and asserts identical
%%% results. This is the gold standard for correctness.
%%% ===================================================================

%%% ===================================================================
%%% Endian cross-validation
%%% ===================================================================

xval_be16_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#0102),
        ebpf_insn:be16(0),
        ebpf_insn:exit_insn()
    ]),
    assert_xval(Prog, <<>>, 16#0201).

xval_be32_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#01020304),
        ebpf_insn:be32(0),
        ebpf_insn:exit_insn()
    ]),
    assert_xval(Prog, <<>>, 16#04030201).

xval_be64_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#0102030405060708),
        ebpf_insn:be64(0),
        ebpf_insn:exit_insn()
    ]),
    assert_xval(Prog, <<>>, 16#0807060504030201).

xval_le16_noop_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#ABCD),
        ebpf_insn:le16(0),
        ebpf_insn:exit_insn()
    ]),
    assert_xval(Prog, <<>>, 16#ABCD).

xval_le32_truncation_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#FFFFFFFF12345678),
        ebpf_insn:le32(0),
        ebpf_insn:exit_insn()
    ]),
    assert_xval(Prog, <<>>, 16#12345678).

xval_be16_double_swap_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#1234),
        ebpf_insn:be16(0),
        ebpf_insn:be16(0),
        ebpf_insn:exit_insn()
    ]),
    assert_xval(Prog, <<>>, 16#1234).

%%% ===================================================================
%%% Packet parsing cross-validation (XDP context)
%%% ===================================================================

xval_read_ethertype_test() ->
    %% Read Ethertype at offset 12, apply be16 to get network byte order value
    Pkt = make_eth_ip_pkt({10, 0, 0, 1}, {10, 0, 0, 2}),
    Prog = ebpf_insn:assemble([
        %% save ctx
        ebpf_insn:mov64_reg(6, 1),
        %% R1 = ctx.data
        ebpf_insn:ldxw(1, 6, 0),
        %% R0 = ethertype (LE read)
        ebpf_insn:ldxh(0, 1, 12),
        %% swap to network order → 0x0800
        ebpf_insn:be16(0),
        ebpf_insn:exit_insn()
    ]),
    assert_xval_xdp(Prog, Pkt, 16#0800).

xval_read_ip_protocol_test() ->
    %% IP protocol at offset 23 (ETH 14 + IP protocol offset 9)
    Pkt = make_eth_ip_pkt({10, 0, 0, 1}, {10, 0, 0, 2}),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(1, 6, 0),
        %% protocol byte
        ebpf_insn:ldxb(0, 1, 23),
        ebpf_insn:exit_insn()
    ]),
    %% TCP
    assert_xval_xdp(Prog, Pkt, 6).

xval_read_src_ip_test() ->
    %% Source IP at offset 26, be32 for network → host
    Pkt = make_eth_ip_pkt({192, 168, 1, 100}, {10, 0, 0, 2}),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(1, 6, 0),
        ebpf_insn:ldxw(0, 1, 26),
        ebpf_insn:be32(0),
        ebpf_insn:exit_insn()
    ]),
    %% 192.168.1.100 = 0xC0A80164
    assert_xval_xdp(Prog, Pkt, 16#C0A80164).

xval_read_dst_ip_test() ->
    %% Destination IP at offset 30
    Pkt = make_eth_ip_pkt({10, 0, 0, 1}, {172, 16, 0, 42}),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(1, 6, 0),
        ebpf_insn:ldxw(0, 1, 30),
        ebpf_insn:be32(0),
        ebpf_insn:exit_insn()
    ]),
    %% 172.16.0.42 = 0xAC10002A
    assert_xval_xdp(Prog, Pkt, 16#AC10002A).

%%% ===================================================================
%%% Bounds check cross-validation
%%% ===================================================================

xval_bounds_check_short_pkt_test() ->
    %% Short packet (10 bytes) → bounds check for 34 → XDP_PASS (2)
    Pkt = <<0:80>>,
    Prog = make_bounds_check_prog(34),
    %% XDP_PASS
    assert_xval_xdp(Prog, Pkt, 2).

xval_bounds_check_long_pkt_test() ->
    %% Full packet → bounds check passes → XDP_DROP (1)
    Pkt = make_eth_ip_pkt({10, 0, 0, 1}, {10, 0, 0, 2}),
    Prog = make_bounds_check_prog(34),
    %% XDP_DROP
    assert_xval_xdp(Prog, Pkt, 1).

xval_bounds_check_exact_size_test() ->
    %% Packet exactly 34 bytes → data+34 == data_end → NOT greater → DROP
    Pkt = <<0:(34 * 8)>>,
    Prog = make_bounds_check_prog(34),
    %% XDP_DROP (not strictly greater)
    assert_xval_xdp(Prog, Pkt, 1).

xval_bounds_check_one_short_test() ->
    %% Packet 33 bytes → data+34 > data_end → PASS
    Pkt = <<0:(33 * 8)>>,
    Prog = make_bounds_check_prog(34),
    %% XDP_PASS
    assert_xval_xdp(Prog, Pkt, 2).

%%% ===================================================================
%%% Full XDP IP filter pattern
%%% ===================================================================

xval_ethertype_filter_ip_test() ->
    %% Accept only IPv4 (ethertype 0x0800), return DROP(1) for IP, PASS(2) for non-IP
    Pkt = make_eth_ip_pkt({10, 0, 0, 1}, {10, 0, 0, 2}),
    Prog = make_ethertype_filter_prog(),
    %% DROP (is IPv4)
    assert_xval_xdp(Prog, Pkt, 1).

xval_ethertype_filter_arp_test() ->
    %% ARP packet (ethertype 0x0806) → PASS
    Pkt = make_arp_pkt(),
    Prog = make_ethertype_filter_prog(),
    %% PASS (not IPv4)
    assert_xval_xdp(Prog, Pkt, 2).

%%% ===================================================================
%%% Helpers: packet construction
%%% ===================================================================

make_eth_ip_pkt({S1, S2, S3, S4}, {D1, D2, D3, D4}) ->
    EthDst = <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>,
    EthSrc = <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55>>,
    EthType = <<16#08, 16#00>>,
    IHL_Ver = 16#45,
    DSCP = 0,
    TotalLen = <<0, 40>>,
    Ident = <<0, 0>>,
    Flags = <<0, 0>>,
    TTL = 64,
    %% TCP
    Protocol = 6,
    Checksum = <<0, 0>>,
    SrcIP = <<S1, S2, S3, S4>>,
    DstIP = <<D1, D2, D3, D4>>,
    TcpStub = <<0:160>>,
    <<EthDst/binary, EthSrc/binary, EthType/binary, IHL_Ver, DSCP, TotalLen/binary, Ident/binary,
        Flags/binary, TTL, Protocol, Checksum/binary, SrcIP/binary, DstIP/binary, TcpStub/binary>>.

make_arp_pkt() ->
    EthDst = <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>,
    EthSrc = <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55>>,
    %% ARP
    EthType = <<16#08, 16#06>>,
    %% Minimal ARP body (28 bytes)
    ArpBody = <<0:(28 * 8)>>,
    <<EthDst/binary, EthSrc/binary, EthType/binary, ArpBody/binary>>.

%%% ===================================================================
%%% Helpers: program construction
%%% ===================================================================

%% Bounds check program: if data + N > data_end → PASS(2), else → DROP(1)
make_bounds_check_prog(N) ->
    ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        %% R2 = ctx.data
        ebpf_insn:ldxw(2, 6, 0),
        %% R3 = ctx.data_end
        ebpf_insn:ldxw(3, 6, 4),
        ebpf_insn:mov64_reg(4, 2),
        %% R4 = data + N
        ebpf_insn:add64_imm(4, N),
        %% if too short → PASS
        ebpf_insn:jgt_reg(4, 3, 2),
        %% DROP
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:exit_insn(),
        %% PASS
        ebpf_insn:mov64_imm(0, 2),
        ebpf_insn:exit_insn()
    ]).

%% Ethertype filter: if ethertype == 0x0800 → DROP(1), else → PASS(2)
make_ethertype_filter_prog() ->
    ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        %% R2 = ctx.data
        ebpf_insn:ldxw(2, 6, 0),
        %% R3 = ctx.data_end
        ebpf_insn:ldxw(3, 6, 4),
        %% Bounds check: need at least 14 bytes (Ethernet header)
        ebpf_insn:mov64_reg(4, 2),
        ebpf_insn:add64_imm(4, 14),
        %% too short → PASS (+5: skip to PASS)
        ebpf_insn:jgt_reg(4, 3, 5),
        %% Read ethertype at offset 12
        ebpf_insn:ldxh(0, 2, 12),
        %% network → host
        ebpf_insn:be16(0),
        %% Check if 0x0800 (IPv4)

        %% not IPv4 → PASS (+2: skip to PASS)
        ebpf_insn:jne_imm(0, 16#0800, 2),
        %% DROP (is IPv4)
        ebpf_insn:mov64_imm(0, 1),
        ebpf_insn:exit_insn(),
        %% PASS
        ebpf_insn:mov64_imm(0, 2),
        ebpf_insn:exit_insn()
    ]).

%%% ===================================================================
%%% Cross-validation core
%%% ===================================================================

%% Run in both Erlang VM and uBPF with plain context, assert same result
assert_xval(Prog, Ctx, Expected) ->
    %% Erlang VM
    ErlResult = ebpf_vm:run(Prog, #{ctx => Ctx}),
    ?assertEqual({ok, Expected}, ErlResult),
    %% uBPF
    case ebpf_ubpf:start() of
        {ok, Port} ->
            try
                ok = ebpf_ubpf:load(Port, Prog),
                UbpfResult = ebpf_ubpf:run(Port, Ctx),
                ?assertEqual({ok, Expected}, UbpfResult)
            after
                ebpf_ubpf:stop(Port)
            end;
        {error, ubpf_port_not_found} ->
            %% Skip uBPF if not built
            ok
    end.

%% Run in both VMs with XDP context (packet-based)
assert_xval_xdp(Prog, Pkt, Expected) ->
    %% Erlang VM: construct XDP context
    PktBase = ?VM_PACKET_BASE,
    PktLen = byte_size(Pkt),
    Ctx =
        <<PktBase:32/little, (PktBase + PktLen):32/little,
            %% data_meta
            0:32/little,
            %% ingress_ifindex
            0:32/little,
            %% rx_queue_index
            0:32/little,
            %% egress_ifindex
            0:32/little>>,
    ErlResult = ebpf_vm:run(Prog, #{ctx => Ctx, packet => Pkt}),
    ?assertEqual({ok, Expected}, ErlResult),
    %% uBPF: use run_xdp which constructs xdp_md in C
    case ebpf_ubpf:start() of
        {ok, Port} ->
            try
                ok = ebpf_ubpf:load(Port, Prog),
                UbpfResult = ebpf_ubpf:run_xdp(Port, Pkt),
                ?assertEqual({ok, Expected}, UbpfResult)
            after
                ebpf_ubpf:stop(Port)
            end;
        {error, ubpf_port_not_found} ->
            ok
    end.
