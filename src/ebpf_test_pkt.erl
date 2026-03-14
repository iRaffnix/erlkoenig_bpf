%%% @doc Test packet generator for XDP testing.
%%% Generates raw Ethernet frames with IPv4 + TCP/UDP/ICMP/ARP headers.
-module(ebpf_test_pkt).

-export([tcp/1, udp/1, icmp/1, arp/1, raw/2, xdp_ctx/1]).

%% --- Public API ---

-spec tcp(map()) -> <<_:64, _:_*8>>.
tcp(Opts) ->
    SrcMac  = maps:get(src_mac, Opts, <<16#00,16#11,16#22,16#33,16#44,16#55>>),
    DstMac  = maps:get(dst_mac, Opts, <<16#66,16#77,16#88,16#99,16#AA,16#BB>>),
    SrcIP   = maps:get(src_ip, Opts, {10,0,0,1}),
    DstIP   = maps:get(dst_ip, Opts, {10,0,0,2}),
    SrcPort = maps:get(src_port, Opts, 12345),
    DstPort = maps:get(dst_port, Opts, 80),
    Flags   = maps:get(flags, Opts, [syn]),
    Payload = maps:get(payload, Opts, <<>>),

    FlagBits = tcp_flags(Flags),
    TcpHdr = <<SrcPort:16/big, DstPort:16/big,
               0:32,          % seq
               0:32,          % ack
               5:4, 0:3, FlagBits:9/big,
               65535:16/big,  % window
               0:16,          % checksum (not computed)
               0:16>>,        % urgent pointer
    TTL     = maps:get(ttl, Opts, 64),

    IpPayload = <<TcpHdr/binary, Payload/binary>>,
    IpHdr = ipv4_header(6, IpPayload, SrcIP, DstIP, TTL),
    eth_frame(DstMac, SrcMac, 16#0800, <<IpHdr/binary, IpPayload/binary>>).

-spec udp(map()) -> <<_:64, _:_*8>>.
udp(Opts) ->
    SrcMac  = maps:get(src_mac, Opts, <<16#00,16#11,16#22,16#33,16#44,16#55>>),
    DstMac  = maps:get(dst_mac, Opts, <<16#66,16#77,16#88,16#99,16#AA,16#BB>>),
    SrcIP   = maps:get(src_ip, Opts, {10,0,0,1}),
    DstIP   = maps:get(dst_ip, Opts, {10,0,0,2}),
    SrcPort = maps:get(src_port, Opts, 1024),
    DstPort = maps:get(dst_port, Opts, 53),
    Payload = maps:get(payload, Opts, <<>>),

    UdpLen = 8 + byte_size(Payload),
    UdpHdr = <<SrcPort:16/big, DstPort:16/big, UdpLen:16/big, 0:16>>,
    TTL     = maps:get(ttl, Opts, 64),

    IpPayload = <<UdpHdr/binary, Payload/binary>>,
    IpHdr = ipv4_header(17, IpPayload, SrcIP, DstIP, TTL),
    eth_frame(DstMac, SrcMac, 16#0800, <<IpHdr/binary, IpPayload/binary>>).

-spec icmp(map()) -> <<_:64, _:_*8>>.
icmp(Opts) ->
    SrcMac  = maps:get(src_mac, Opts, <<16#00,16#11,16#22,16#33,16#44,16#55>>),
    DstMac  = maps:get(dst_mac, Opts, <<16#66,16#77,16#88,16#99,16#AA,16#BB>>),
    SrcIP   = maps:get(src_ip, Opts, {10,0,0,1}),
    DstIP   = maps:get(dst_ip, Opts, {10,0,0,2}),
    Id      = maps:get(id, Opts, 1),
    Seq     = maps:get(seq, Opts, 1),
    Payload = maps:get(payload, Opts, <<>>),

    IcmpNoChk = <<8:8, 0:8, 0:16, Id:16/big, Seq:16/big, Payload/binary>>,
    Chk = ip_checksum(IcmpNoChk),
    IcmpHdr = <<8:8, 0:8, Chk:16/big, Id:16/big, Seq:16/big>>,
    TTL     = maps:get(ttl, Opts, 64),

    IpPayload = <<IcmpHdr/binary, Payload/binary>>,
    IpHdr = ipv4_header(1, IpPayload, SrcIP, DstIP, TTL),
    eth_frame(DstMac, SrcMac, 16#0800, <<IpHdr/binary, IpPayload/binary>>).

-spec arp(map()) -> <<_:64, _:_*8>>.
arp(Opts) ->
    SrcMac    = maps:get(src_mac, Opts, <<16#00,16#11,16#22,16#33,16#44,16#55>>),
    DstMac    = maps:get(dst_mac, Opts, <<16#66,16#77,16#88,16#99,16#AA,16#BB>>),
    SenderMac = maps:get(sender_mac, Opts, SrcMac),
    SenderIP  = maps:get(sender_ip, Opts, {10,0,0,1}),
    TargetMac = maps:get(target_mac, Opts, <<0,0,0,0,0,0>>),
    TargetIP  = maps:get(target_ip, Opts, {10,0,0,2}),

    SenderIPInt = ip_to_int(SenderIP),
    TargetIPInt = ip_to_int(TargetIP),
    ArpPayload = <<1:16/big,          % hardware type: ethernet
                   16#0800:16/big,     % protocol type: IPv4
                   6:8,                % hw addr len
                   4:8,                % proto addr len
                   1:16/big,           % operation: request
                   SenderMac:6/binary, SenderIPInt:32/big,
                   TargetMac:6/binary, TargetIPInt:32/big>>,
    eth_frame(DstMac, SrcMac, 16#0806, ArpPayload).

-spec raw(non_neg_integer(), binary()) -> binary().
raw(EthType, Payload) ->
    SrcMac = <<16#00,16#11,16#22,16#33,16#44,16#55>>,
    DstMac = <<16#66,16#77,16#88,16#99,16#AA,16#BB>>,
    eth_frame(DstMac, SrcMac, EthType, Payload).

%% @doc Build an XDP context map for the Erlang VM from a packet binary.
%% Returns #{ctx => CtxBin, packet => PktBin} suitable for ebpf_vm:run/2.
-spec xdp_ctx(binary()) -> #{ctx := binary(), packet := binary()}.
xdp_ctx(PktBin) ->
    PktBase = 16#20000000,
    PktLen = byte_size(PktBin),
    Ctx = <<PktBase:32/little,
            (PktBase + PktLen):32/little,
            0:32/little,     %% data_meta
            0:32/little,     %% ingress_ifindex
            0:32/little,     %% rx_queue_index
            0:32/little>>,   %% egress_ifindex
    #{ctx => Ctx, packet => PktBin}.

%% --- Internal ---

eth_frame(DstMac, SrcMac, EthType, Payload) ->
    <<DstMac:6/binary, SrcMac:6/binary, EthType:16/big, Payload/binary>>.

ipv4_header(Protocol, Payload, SrcIP, DstIP, TTL) ->
    TotalLen = 20 + byte_size(Payload),
    SrcIPInt = ip_to_int(SrcIP),
    DstIPInt = ip_to_int(DstIP),
    HdrNoChk = <<4:4, 5:4, 0:8, TotalLen:16/big,
                 0:16, 16#4000:16/big,
                 TTL:8, Protocol:8, 0:16,
                 SrcIPInt:32/big, DstIPInt:32/big>>,
    Chk = ip_checksum(HdrNoChk),
    <<4:4, 5:4, 0:8, TotalLen:16/big,
      0:16, 16#4000:16/big,
      TTL:8, Protocol:8, Chk:16/big,
      SrcIPInt:32/big, DstIPInt:32/big>>.

ip_checksum(Data) ->
    PaddedData = case byte_size(Data) rem 2 of
        0 -> Data;
        1 -> <<Data/binary, 0:8>>
    end,
    Words = [W || <<W:16/big>> <= PaddedData],
    Sum = lists:foldl(fun(W, Acc) -> Acc + W end, 0, Words),
    Folded = (Sum band 16#FFFF) + (Sum bsr 16),
    bnot Folded band 16#FFFF.

ip_to_int({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

tcp_flags(Flags) ->
    lists:foldl(fun(F, Acc) -> Acc bor tcp_flag_bit(F) end, 0, Flags).

tcp_flag_bit(fin) -> 16#001;
tcp_flag_bit(syn) -> 16#002;
tcp_flag_bit(rst) -> 16#004;
tcp_flag_bit(psh) -> 16#008;
tcp_flag_bit(ack) -> 16#010.
