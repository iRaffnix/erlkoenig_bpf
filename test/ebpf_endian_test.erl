-module(ebpf_endian_test).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Endian instruction encoding / decoding
%%% ===================================================================

be16_encode_test() ->
    Bin = ebpf_insn:be16(2),
    {be, 2, 0, 0, 16} = ebpf_insn:decode(Bin).

be32_encode_test() ->
    Bin = ebpf_insn:be32(3),
    {be, 3, 0, 0, 32} = ebpf_insn:decode(Bin).

be64_encode_test() ->
    Bin = ebpf_insn:be64(0),
    {be, 0, 0, 0, 64} = ebpf_insn:decode(Bin).

le16_encode_test() ->
    Bin = ebpf_insn:le16(1),
    {le, 1, 0, 0, 16} = ebpf_insn:decode(Bin).

le32_encode_test() ->
    Bin = ebpf_insn:le32(4),
    {le, 4, 0, 0, 32} = ebpf_insn:decode(Bin).

le64_encode_test() ->
    Bin = ebpf_insn:le64(5),
    {le, 5, 0, 0, 64} = ebpf_insn:decode(Bin).

%% Verify exact opcode bytes
be_opcode_is_0xdc_test() ->
    <<16#dc, _/binary>> = ebpf_insn:be16(0).

le_opcode_is_0xd4_test() ->
    <<16#d4, _/binary>> = ebpf_insn:le16(0).

%%% ===================================================================
%%% VM execution: be16/be32/be64
%%% ===================================================================

vm_be16_test() ->
    %% 0x0102 → be16 → 0x0201
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#0102),
        ebpf_insn:be16(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#0201, Result).

vm_be16_network_test() ->
    %% 0x0800 in little-endian host → be16 → 0x0008
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#0008),
        ebpf_insn:be16(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#0800, Result).

vm_be32_test() ->
    %% 0x01020304 → be32 → 0x04030201
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#01020304),
        ebpf_insn:be32(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#04030201, Result).

vm_be32_ip_test() ->
    %% 10.0.0.1 = 0x0A000001 → be32 → 0x0100000A
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#0100000A),
        ebpf_insn:be32(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#0A000001, Result).

vm_be64_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#0102030405060708),
        ebpf_insn:be64(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#0807060504030201, Result).

%% le16/le32/le64 are no-ops on little-endian — they just mask to width
vm_le16_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#ABCD),
        ebpf_insn:le16(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#ABCD, Result).

vm_le32_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#DEADBEEF),
        ebpf_insn:le32(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#DEADBEEF, Result).

vm_le32_truncates_test() ->
    %% le32 should mask to 32 bits
    Prog = ebpf_insn:assemble([
        ebpf_insn:ld64_imm(0, 16#FFFFFFFF12345678),
        ebpf_insn:le32(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#12345678, Result).

%%% ===================================================================
%%% VM: Packet memory read (ldxb/ldxh/ldxw from packet region)
%%% ===================================================================

%% Build an XDP context pointing to a packet buffer
make_xdp_ctx(PktBin) ->
    PktBase = 16#20000000,
    PktLen = byte_size(PktBin),
    Ctx = <<PktBase:32/little,
            (PktBase + PktLen):32/little,
            0:32/little,     %% data_meta
            0:32/little,     %% ingress_ifindex
            0:32/little,     %% rx_queue_index
            0:32/little>>,   %% egress_ifindex
    #{ctx => Ctx, packet => PktBin}.

vm_read_u8_from_packet_test() ->
    %% Packet: [0xAA, 0xBB, 0xCC]
    Pkt = <<16#AA, 16#BB, 16#CC>>,
    CtxMap = make_xdp_ctx(Pkt),
    %% Load ctx.data (offset 0, u32) into R1, then ldxb R0, [R1 + 1]
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),   %% save ctx
        ebpf_insn:ldxw(1, 6, 0),      %% R1 = ctx.data (packet base)
        ebpf_insn:ldxb(0, 1, 1),      %% R0 = *(u8*)(R1 + 1) = 0xBB
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, CtxMap),
    ?assertEqual(16#BB, Result).

vm_read_u16_from_packet_test() ->
    %% Ethernet header: dst(6) + src(6) + ethertype(2)
    %% Ethertype at offset 12: 0x0800 (IP) stored in network byte order
    EthHdr = <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF,  %% dst MAC
               16#00, 16#11, 16#22, 16#33, 16#44, 16#55,  %% src MAC
               16#08, 16#00>>,                              %% ethertype 0x0800 (big-endian)
    CtxMap = make_xdp_ctx(EthHdr),
    %% Load ctx.data, ldxh at offset 12
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(1, 6, 0),      %% R1 = ctx.data
        ebpf_insn:ldxh(0, 1, 12),     %% R0 = *(u16*)(R1 + 12)
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, CtxMap),
    %% On LE host, memory read of 0x08,0x00 as u16-LE = 0x0008
    ?assertEqual(16#0008, Result).

vm_read_u16_be_from_packet_test() ->
    %% Same as above, but with be16 to get network byte order value
    EthHdr = <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF,
               16#00, 16#11, 16#22, 16#33, 16#44, 16#55,
               16#08, 16#00>>,
    CtxMap = make_xdp_ctx(EthHdr),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(1, 6, 0),
        ebpf_insn:ldxh(0, 1, 12),
        ebpf_insn:be16(0),            %% swap to big-endian: 0x0008 → 0x0800
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, CtxMap),
    ?assertEqual(16#0800, Result).

vm_read_u32_from_packet_test() ->
    %% Source IP at offset 26 in Ethernet+IP packet
    %% 10.0.0.1 = 0x0A000001 in network byte order
    Pkt = make_ip_packet({10, 0, 0, 1}, {10, 0, 0, 2}),
    CtxMap = make_xdp_ctx(Pkt),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(1, 6, 0),
        ebpf_insn:ldxw(0, 1, 26),     %% src_ip at offset 26
        ebpf_insn:be32(0),            %% network → host order
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, CtxMap),
    ?assertEqual(16#0A000001, Result).

vm_read_protocol_from_ip_test() ->
    %% IP protocol at offset 23 (Ethernet 14 + IP protocol offset 9)
    %% TCP = 6
    Pkt = make_ip_packet({10, 0, 0, 1}, {10, 0, 0, 2}),
    CtxMap = make_xdp_ctx(Pkt),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(1, 6, 0),
        ebpf_insn:ldxb(0, 1, 23),     %% protocol at offset 23
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, CtxMap),
    ?assertEqual(6, Result).  %% TCP

%%% ===================================================================
%%% Bounds check pattern (data + N > data_end)
%%% ===================================================================

vm_bounds_check_pass_test() ->
    %% Short packet (10 bytes) — bounds check for 34 bytes should fail → return 2 (XDP_PASS)
    Pkt = <<0:80>>,  %% 10 bytes
    CtxMap = make_xdp_ctx(Pkt),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(2, 6, 0),      %% R2 = ctx.data
        ebpf_insn:ldxw(3, 6, 4),      %% R3 = ctx.data_end
        ebpf_insn:mov64_reg(4, 2),
        ebpf_insn:add64_imm(4, 34),   %% R4 = data + 34
        ebpf_insn:jgt_reg(4, 3, 2),   %% if data+34 > data_end → skip to pass+exit
        ebpf_insn:mov64_imm(0, 1),    %% XDP_DROP (not reached for short packet)
        ebpf_insn:exit_insn(),
        ebpf_insn:mov64_imm(0, 2),    %% XDP_PASS
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, CtxMap),
    ?assertEqual(2, Result).  %% XDP_PASS (bounds check triggered)

vm_bounds_check_ok_test() ->
    %% Full-size packet — bounds check should pass → proceed to "drop"
    Pkt = make_ip_packet({10, 0, 0, 1}, {10, 0, 0, 2}),
    CtxMap = make_xdp_ctx(Pkt),
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_reg(6, 1),
        ebpf_insn:ldxw(2, 6, 0),
        ebpf_insn:ldxw(3, 6, 4),
        ebpf_insn:mov64_reg(4, 2),
        ebpf_insn:add64_imm(4, 34),
        ebpf_insn:jgt_reg(4, 3, 2),   %% if too short → skip to pass+exit
        ebpf_insn:mov64_imm(0, 1),    %% XDP_DROP (packet large enough)
        ebpf_insn:exit_insn(),
        ebpf_insn:mov64_imm(0, 2),    %% XDP_PASS
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, CtxMap),
    ?assertEqual(1, Result).  %% XDP_DROP (bounds check passed)

%%% ===================================================================
%%% Endian double-swap roundtrip
%%% ===================================================================

be16_double_swap_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#1234),
        ebpf_insn:be16(0),
        ebpf_insn:be16(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#1234, Result).

be32_double_swap_test() ->
    Prog = ebpf_insn:assemble([
        ebpf_insn:mov64_imm(0, 16#12345678),
        ebpf_insn:be32(0),
        ebpf_insn:be32(0),
        ebpf_insn:exit_insn()
    ]),
    {ok, Result} = ebpf_vm:run(Prog, #{}),
    ?assertEqual(16#12345678, Result).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Build a minimal Ethernet+IPv4 packet (no payload)
make_ip_packet({S1, S2, S3, S4}, {D1, D2, D3, D4}) ->
    %% Ethernet header (14 bytes)
    EthDst = <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>,
    EthSrc = <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55>>,
    EthType = <<16#08, 16#00>>,  %% IPv4
    %% IPv4 header (20 bytes, minimal)
    IHL_Ver = 16#45,  %% version=4, IHL=5 (20 bytes)
    DSCP = 0,
    TotalLen = <<0, 40>>,  %% 20 IP + 20 TCP (big-endian)
    Ident = <<0, 0>>,
    Flags_Frag = <<0, 0>>,
    TTL = 64,
    Protocol = 6,  %% TCP
    Checksum = <<0, 0>>,
    SrcIP = <<S1, S2, S3, S4>>,
    DstIP = <<D1, D2, D3, D4>>,
    %% TCP header stub (20 bytes, minimal)
    TcpHdr = <<0:160>>,
    <<EthDst/binary, EthSrc/binary, EthType/binary,
      IHL_Ver, DSCP, TotalLen/binary, Ident/binary,
      Flags_Frag/binary, TTL, Protocol, Checksum/binary,
      SrcIP/binary, DstIP/binary, TcpHdr/binary>>.
