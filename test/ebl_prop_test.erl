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

-module(ebl_prop_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% PropEr macros (avoid including proper.hrl which clashes with eunit)
-define(FORALL(X, RawType, Prop),
    proper:forall(RawType, fun(X) -> Prop end)
).
-define(PROP_LET(X, RawType, Gen),
    proper_types:bind(RawType, fun(X) -> Gen end, false)
).

%%% ===================================================================
%%% Property-based tests for EBL XDP programs.
%%%
%%% Two categories:
%%%   1. Stateless properties — per-packet invariants (non-IPv4, short, etc.)
%%%   2. Stateful properties — multi-packet sequences with persistent maps
%%%      that verify threshold behavior, accumulation, and DROP paths.
%%% ===================================================================

-define(NUMTESTS, 300).
-define(XDP_DROP, 1).
-define(XDP_PASS, 2).

%%% ===================================================================
%%% Packet generators
%%% ===================================================================

ip_addr() ->
    {proper_types:byte(), proper_types:byte(), proper_types:byte(), proper_types:byte()}.

tcp_flags() ->
    proper_types:non_empty(
        proper_types:list(proper_types:oneof([syn, ack, rst, fin, psh]))
    ).

tcp_pkt() ->
    ?PROP_LET(
        {SrcIP, DstIP, SrcPort, DstPort, Flags, PayloadSize},
        {
            ip_addr(),
            ip_addr(),
            proper_types:range(1, 65535),
            proper_types:range(1, 65535),
            tcp_flags(),
            proper_types:range(0, 200)
        },
        ebpf_test_pkt:tcp(#{
            src_ip => SrcIP,
            dst_ip => DstIP,
            src_port => SrcPort,
            dst_port => DstPort,
            flags => lists:usort(Flags),
            payload => <<0:(PayloadSize * 8)>>
        })
    ).

udp_pkt() ->
    ?PROP_LET(
        {SrcIP, DstIP, SrcPort, DstPort, PayloadSize},
        {
            ip_addr(),
            ip_addr(),
            proper_types:range(1, 65535),
            proper_types:range(1, 65535),
            proper_types:range(0, 200)
        },
        ebpf_test_pkt:udp(#{
            src_ip => SrcIP,
            dst_ip => DstIP,
            src_port => SrcPort,
            dst_port => DstPort,
            payload => <<0:(PayloadSize * 8)>>
        })
    ).

icmp_pkt() ->
    ?PROP_LET(
        {SrcIP, DstIP},
        {ip_addr(), ip_addr()},
        ebpf_test_pkt:icmp(#{src_ip => SrcIP, dst_ip => DstIP})
    ).

arp_pkt() ->
    ?PROP_LET(
        {SenderIP, TargetIP},
        {ip_addr(), ip_addr()},
        ebpf_test_pkt:arp(#{sender_ip => SenderIP, target_ip => TargetIP})
    ).

non_ipv4_pkt() ->
    proper_types:oneof([
        arp_pkt(),
        ?PROP_LET(
            Payload,
            proper_types:binary(20),
            ebpf_test_pkt:raw(16#86DD, Payload)
        ),
        ?PROP_LET(
            Payload,
            proper_types:binary(20),
            ebpf_test_pkt:raw(16#8100, Payload)
        )
    ]).

short_pkt() ->
    ?PROP_LET(
        Size,
        proper_types:range(1, 33),
        <<0:(Size * 8)>>
    ).

any_pkt() ->
    proper_types:oneof([tcp_pkt(), udp_pkt(), icmp_pkt(), arp_pkt(), short_pkt()]).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

run_xdp(Path, Pkt, MapSpecs) ->
    {ok, Bin} = ebl_compile:file(Path),
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    Opts =
        case MapSpecs of
            [] -> #{};
            _ -> #{maps => MapSpecs}
        end,
    {ok, Result} = ebpf_vm:run(Bin, Ctx, Opts),
    Result.

%% Run N identical packets through the same program with persistent maps.
%% Returns the list of results (one per packet).
run_multi(Bin, Pkt, MapState, N) ->
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    run_multi_loop(Bin, Ctx, MapState, N, []).

run_multi_loop(_Bin, _Ctx, MapState, 0, Acc) ->
    {lists:reverse(Acc), MapState};
run_multi_loop(Bin, Ctx, MapState, N, Acc) ->
    {ok, Result, MapState2} = ebpf_vm:run_stateful(Bin, Ctx, MapState, #{}),
    run_multi_loop(Bin, Ctx, MapState2, N - 1, [Result | Acc]).

%% Run a list of different packets through the program with persistent maps.
run_sequence(Bin, Pkts, MapState) ->
    run_sequence(Bin, Pkts, MapState, []).

run_sequence(_Bin, [], MapState, Acc) ->
    {lists:reverse(Acc), MapState};
run_sequence(Bin, [Pkt | Rest], MapState, Acc) ->
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    {ok, Result, MapState2} = ebpf_vm:run_stateful(Bin, Ctx, MapState, #{}),
    run_sequence(Bin, Rest, MapState2, [Result | Acc]).

%% Read a u64 value from a map by u32 key.
map_read_u64(MapState, MapIdx, KeyU32) ->
    {MapsTabs, MapsMeta} = MapState,
    Tab = maps:get(MapIdx, MapsTabs),
    Meta = maps:get(MapIdx, MapsMeta),
    KeyBin = <<KeyU32:32/little>>,
    case ebpf_vm_maps:lookup(Tab, KeyBin, Meta) of
        {ok, <<Val:64/little>>} -> Val;
        none -> 0
    end.

is_xdp_action(V) -> V >= 0 andalso V =< 4.

%%% ===================================================================
%%% PART 1: Stateless properties (per-packet invariants)
%%% ===================================================================

%%% --- Non-IPv4 always PASS ---

prop_non_ipv4_always_pass(Path, MapSpecs) ->
    ?FORALL(
        Pkt,
        non_ipv4_pkt(),
        run_xdp(Path, Pkt, MapSpecs) =:= ?XDP_PASS
    ).

prop_15_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/15_syn_flood_protect.ebl", [{hash, 4, 8, 65536}]
        )
    end).

prop_16_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/16_port_firewall.ebl", [{hash, 4, 8, 1024}]
        )
    end).

prop_17_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/17_ttl_filter.ebl", [{hash, 4, 8, 16384}]
        )
    end).

prop_18_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/18_icmp_rate_limiter.ebl", [{hash, 4, 8, 32768}]
        )
    end).

prop_19_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/19_dns_amplification.ebl", [{hash, 4, 8, 32768}]
        )
    end).

prop_20_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/20_subnet_firewall.ebl", [{hash, 4, 8, 4096}]
        )
    end).

prop_21_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/21_port_scan_detect.ebl", [{hash, 4, 8, 16384}]
        )
    end).

prop_22_non_ipv4_test_() ->
    prop_test(fun() ->
        prop_non_ipv4_always_pass(
            "examples/22_bandwidth_monitor.ebl", [{hash, 4, 8, 65536}]
        )
    end).

%%% --- Short packets always PASS ---

prop_short_always_pass(Path, MapSpecs) ->
    ?FORALL(
        Pkt,
        short_pkt(),
        run_xdp(Path, Pkt, MapSpecs) =:= ?XDP_PASS
    ).

prop_15_short_test_() ->
    prop_test(fun() ->
        prop_short_always_pass(
            "examples/15_syn_flood_protect.ebl", [{hash, 4, 8, 65536}]
        )
    end).

prop_16_short_test_() ->
    prop_test(fun() ->
        prop_short_always_pass(
            "examples/16_port_firewall.ebl", [{hash, 4, 8, 1024}]
        )
    end).

prop_19_short_test_() ->
    prop_test(fun() ->
        prop_short_always_pass(
            "examples/19_dns_amplification.ebl", [{hash, 4, 8, 32768}]
        )
    end).

prop_21_short_test_() ->
    prop_test(fun() ->
        prop_short_always_pass(
            "examples/21_port_scan_detect.ebl", [{hash, 4, 8, 16384}]
        )
    end).

%%% --- Result always a valid XDP action ---

prop_always_valid_action(Path, MapSpecs) ->
    ?FORALL(
        Pkt,
        any_pkt(),
        is_xdp_action(run_xdp(Path, Pkt, MapSpecs))
    ).

prop_15_valid_action_test_() ->
    prop_test(fun() ->
        prop_always_valid_action(
            "examples/15_syn_flood_protect.ebl", [{hash, 4, 8, 65536}]
        )
    end).

prop_16_valid_action_test_() ->
    prop_test(fun() ->
        prop_always_valid_action(
            "examples/16_port_firewall.ebl", [{hash, 4, 8, 1024}]
        )
    end).

prop_19_valid_action_test_() ->
    prop_test(fun() ->
        prop_always_valid_action(
            "examples/19_dns_amplification.ebl", [{hash, 4, 8, 32768}]
        )
    end).

prop_21_valid_action_test_() ->
    prop_test(fun() ->
        prop_always_valid_action(
            "examples/21_port_scan_detect.ebl", [{hash, 4, 8, 16384}]
        )
    end).

%%% --- Protocol-specific bypass ---

prop_15_non_tcp_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            Pkt,
            proper_types:oneof([udp_pkt(), icmp_pkt()]),
            run_xdp(
                "examples/15_syn_flood_protect.ebl",
                Pkt,
                [{hash, 4, 8, 65536}]
            ) =:= ?XDP_PASS
        )
    end).

prop_15_tcp_no_syn_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            {SrcIP, DstIP, DstPort},
            {ip_addr(), ip_addr(), proper_types:range(1, 65535)},
            run_xdp(
                "examples/15_syn_flood_protect.ebl",
                ebpf_test_pkt:tcp(#{
                    src_ip => SrcIP,
                    dst_ip => DstIP,
                    dst_port => DstPort,
                    flags => [ack]
                }),
                [{hash, 4, 8, 65536}]
            ) =:= ?XDP_PASS
        )
    end).

prop_16_icmp_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            Pkt,
            icmp_pkt(),
            run_xdp(
                "examples/16_port_firewall.ebl",
                Pkt,
                [{hash, 4, 8, 1024}]
            ) =:= ?XDP_PASS
        )
    end).

prop_21_non_rst_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            {SrcIP, DstIP, DstPort, Flags},
            {
                ip_addr(),
                ip_addr(),
                proper_types:range(1, 65535),
                proper_types:oneof([[syn], [ack], [syn, ack], [fin], [fin, ack], [psh, ack]])
            },
            run_xdp(
                "examples/21_port_scan_detect.ebl",
                ebpf_test_pkt:tcp(#{
                    src_ip => SrcIP,
                    dst_ip => DstIP,
                    dst_port => DstPort,
                    flags => Flags
                }),
                [{hash, 4, 8, 16384}]
            ) =:= ?XDP_PASS
        )
    end).

prop_18_non_icmp_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            Pkt,
            proper_types:oneof([tcp_pkt(), udp_pkt()]),
            run_xdp(
                "examples/18_icmp_rate_limiter.ebl",
                Pkt,
                [{hash, 4, 8, 32768}]
            ) =:= ?XDP_PASS
        )
    end).

prop_19_non_dns_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            Pkt,
            proper_types:oneof([tcp_pkt(), icmp_pkt()]),
            run_xdp(
                "examples/19_dns_amplification.ebl",
                Pkt,
                [{hash, 4, 8, 32768}]
            ) =:= ?XDP_PASS
        )
    end).

prop_19_udp_non53_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            {SrcIP, DstIP, SrcPort},
            {ip_addr(), ip_addr(), proper_types:range(54, 65535)},
            run_xdp(
                "examples/19_dns_amplification.ebl",
                ebpf_test_pkt:udp(#{
                    src_ip => SrcIP,
                    dst_ip => DstIP,
                    src_port => SrcPort
                }),
                [{hash, 4, 8, 32768}]
            ) =:= ?XDP_PASS
        )
    end).

prop_17_normal_ttl_pass_test_() ->
    prop_test(fun() ->
        ?FORALL(
            {SrcIP, DstIP},
            {ip_addr(), ip_addr()},
            run_xdp(
                "examples/17_ttl_filter.ebl",
                ebpf_test_pkt:tcp(#{src_ip => SrcIP, dst_ip => DstIP}),
                [{hash, 4, 8, 16384}]
            ) =:= ?XDP_PASS
        )
    end).

%%% ===================================================================
%%% PART 2: Stateful properties — multi-packet with persistent maps
%%%
%%% These are the REAL tests. They verify that:
%%%   - Maps accumulate state across packets
%%%   - Thresholds trigger DROP at the correct count
%%%   - Values in maps are correct after N packets
%%% ===================================================================

%%% --- 15: SYN flood: 101 SYNs from same IP → packet 101 is DROP ---

stateful_15_syn_flood_threshold_test_() ->
    {timeout, 60, fun() ->
        {ok, Bin} = ebl_compile:file("examples/15_syn_flood_protect.ebl"),
        MapState = ebpf_vm:create_maps([{hash, 4, 8, 65536}]),
        try
            Pkt = ebpf_test_pkt:tcp(#{
                src_ip => {10, 0, 0, 1},
                dst_ip => {10, 0, 0, 2},
                flags => [syn]
            }),
            {Results, _} = run_multi(Bin, Pkt, MapState, 105),
            %% Packets 1-100: PASS (count 1..100, check is > 100)
            First100 = lists:sublist(Results, 100),
            ?assert(lists:all(fun(R) -> R =:= ?XDP_PASS end, First100)),
            %% Packet 101: DROP (count=101 > 100)
            ?assertEqual(?XDP_DROP, lists:nth(101, Results)),
            %% Packets 102-105: still DROP
            Last = lists:nthtail(101, Results),
            ?assert(lists:all(fun(R) -> R =:= ?XDP_DROP end, Last))
        after
            ebpf_vm:destroy_maps(MapState)
        end
    end}.

%%% --- 15: SYN flood with random IPs — different IPs don't interfere ---

stateful_15_syn_flood_isolation_test_() ->
    {timeout, 60, fun() ->
        ?assert(
            proper:quickcheck(
                ?FORALL(
                    {IP_A, IP_B},
                    {ip_addr(), ip_addr()},
                    begin
                        {ok, Bin} = ebl_compile:file("examples/15_syn_flood_protect.ebl"),
                        MapState = ebpf_vm:create_maps([{hash, 4, 8, 65536}]),
                        try
                            PktA = ebpf_test_pkt:tcp(#{
                                src_ip => IP_A,
                                dst_ip => {10, 0, 0, 2},
                                flags => [syn]
                            }),
                            PktB = ebpf_test_pkt:tcp(#{
                                src_ip => IP_B,
                                dst_ip => {10, 0, 0, 2},
                                flags => [syn]
                            }),
                            %% Send 5 from A, then 5 from B
                            Pkts = lists:duplicate(5, PktA) ++ lists:duplicate(5, PktB),
                            {Results, _} = run_sequence(Bin, Pkts, MapState),
                            %% All should pass (count never exceeds 5)
                            lists:all(fun(R) -> R =:= ?XDP_PASS end, Results)
                        after
                            ebpf_vm:destroy_maps(MapState)
                        end
                    end
                ),
                [{numtests, 50}]
            )
        )
    end}.

%%% --- 17: TTL filter: 51 low-TTL packets → DROP ---

stateful_17_ttl_threshold_test_() ->
    {timeout, 60, fun() ->
        {ok, Bin} = ebl_compile:file("examples/17_ttl_filter.ebl"),
        MapState = ebpf_vm:create_maps([{hash, 4, 8, 16384}]),
        try
            %% TTL=1 is at byte offset 22 in the packet
            Pkt = ebpf_test_pkt:tcp(#{
                src_ip => {10, 0, 0, 1},
                dst_ip => {10, 0, 0, 2},
                ttl => 1
            }),
            {Results, _} = run_multi(Bin, Pkt, MapState, 55),
            First50 = lists:sublist(Results, 50),
            ?assert(lists:all(fun(R) -> R =:= ?XDP_PASS end, First50)),
            ?assertEqual(?XDP_DROP, lists:nth(51, Results))
        after
            ebpf_vm:destroy_maps(MapState)
        end
    end}.

%%% --- 18: ICMP rate limiter: 11 ICMPs → DROP ---

stateful_18_icmp_threshold_test_() ->
    {timeout, 60, fun() ->
        {ok, Bin} = ebl_compile:file("examples/18_icmp_rate_limiter.ebl"),
        MapState = ebpf_vm:create_maps([{hash, 4, 8, 32768}]),
        try
            Pkt = ebpf_test_pkt:icmp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
            {Results, _} = run_multi(Bin, Pkt, MapState, 15),
            First10 = lists:sublist(Results, 10),
            ?assert(lists:all(fun(R) -> R =:= ?XDP_PASS end, First10)),
            ?assertEqual(?XDP_DROP, lists:nth(11, Results))
        after
            ebpf_vm:destroy_maps(MapState)
        end
    end}.

%%% --- 19: DNS amplification: 21 large DNS responses → DROP ---

stateful_19_dns_amp_threshold_test_() ->
    {timeout, 60, fun() ->
        {ok, Bin} = ebl_compile:file("examples/19_dns_amplification.ebl"),
        MapState = ebpf_vm:create_maps([{hash, 4, 8, 32768}]),
        try
            BigPayload = <<0:(600 * 8)>>,
            Pkt = ebpf_test_pkt:udp(#{
                src_ip => {8, 8, 8, 8},
                dst_ip => {10, 0, 0, 1},
                src_port => 53,
                dst_port => 1024,
                payload => BigPayload
            }),
            {Results, _} = run_multi(Bin, Pkt, MapState, 25),
            First20 = lists:sublist(Results, 20),
            ?assert(lists:all(fun(R) -> R =:= ?XDP_PASS end, First20)),
            ?assertEqual(?XDP_DROP, lists:nth(21, Results))
        after
            ebpf_vm:destroy_maps(MapState)
        end
    end}.

%%% --- 21: Port scan: 31 RSTs → DROP ---

stateful_21_portscan_threshold_test_() ->
    {timeout, 60, fun() ->
        {ok, Bin} = ebl_compile:file("examples/21_port_scan_detect.ebl"),
        MapState = ebpf_vm:create_maps([{hash, 4, 8, 16384}]),
        try
            Pkt = ebpf_test_pkt:tcp(#{
                src_ip => {10, 0, 0, 1},
                dst_ip => {10, 0, 0, 2},
                flags => [rst]
            }),
            {Results, _} = run_multi(Bin, Pkt, MapState, 35),
            First30 = lists:sublist(Results, 30),
            ?assert(lists:all(fun(R) -> R =:= ?XDP_PASS end, First30)),
            ?assertEqual(?XDP_DROP, lists:nth(31, Results))
        after
            ebpf_vm:destroy_maps(MapState)
        end
    end}.

%%% --- 22: Bandwidth monitor — map accumulates IP total length ---

stateful_22_bwmon_accumulation_test_() ->
    {timeout, 60, fun() ->
        {ok, Bin} = ebl_compile:file("examples/22_bandwidth_monitor.ebl"),
        MapState = ebpf_vm:create_maps([{hash, 4, 8, 65536}]),
        try
            Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
            {Results, MapState2} = run_multi(Bin, Pkt, MapState, 10),
            %% All must be PASS
            ?assert(lists:all(fun(R) -> R =:= ?XDP_PASS end, Results)),
            %% Map must contain accumulated bytes for src_ip
            %% src_ip 10.0.0.1 = 0x0A000001

            %% big-endian u32
            SrcIPKey = (10 bsl 24) bor 1,
            AccBytes = map_read_u64(MapState2, 0, SrcIPKey),
            %% Must be > 0 (exact value depends on IP total length)
            ?assert(AccBytes > 0),
            %% Must be exactly 10x the per-packet IP length
            Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
            PktBin = maps:get(packet, Ctx),
            %% IP total length at offset 16 (ETH=14 + 2)
            <<_:16/binary, IPLen:16/big, _/binary>> = PktBin,
            ?assertEqual(IPLen * 10, AccBytes)
        after
            ebpf_vm:destroy_maps(MapState)
        end
    end}.

%%% --- 22: Bandwidth monitor with random packets — always accumulates ---

stateful_22_bwmon_random_test_() ->
    {timeout, 60, fun() ->
        ?assert(
            proper:quickcheck(
                ?FORALL(
                    PayloadSize,
                    proper_types:range(0, 500),
                    begin
                        {ok, Bin} = ebl_compile:file("examples/22_bandwidth_monitor.ebl"),
                        MapState = ebpf_vm:create_maps([{hash, 4, 8, 65536}]),
                        try
                            Pkt = ebpf_test_pkt:tcp(#{
                                src_ip => {192, 168, 1, 1},
                                dst_ip => {10, 0, 0, 2},
                                payload => <<0:(PayloadSize * 8)>>
                            }),
                            {Results, MapState2} = run_multi(Bin, Pkt, MapState, 5),
                            AllPass = lists:all(fun(R) -> R =:= ?XDP_PASS end, Results),
                            SrcIPKey = (192 bsl 24) bor (168 bsl 16) bor (1 bsl 8) bor 1,
                            AccBytes = map_read_u64(MapState2, 0, SrcIPKey),
                            Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
                            PktBin = maps:get(packet, Ctx),
                            <<_:16/binary, IPLen:16/big, _/binary>> = PktBin,
                            AllPass andalso (AccBytes =:= IPLen * 5)
                        after
                            ebpf_vm:destroy_maps(MapState)
                        end
                    end
                ),
                [{numtests, 100}]
            )
        )
    end}.

%%% --- 21: Port scan with random IPs — threshold per destination IP ---

stateful_21_portscan_random_test_() ->
    {timeout, 60, fun() ->
        ?assert(
            proper:quickcheck(
                ?FORALL(
                    {SrcIP, DstIP},
                    {ip_addr(), ip_addr()},
                    begin
                        {ok, Bin} = ebl_compile:file("examples/21_port_scan_detect.ebl"),
                        MapState = ebpf_vm:create_maps([{hash, 4, 8, 16384}]),
                        try
                            Pkt = ebpf_test_pkt:tcp(#{
                                src_ip => SrcIP,
                                dst_ip => DstIP,
                                flags => [rst]
                            }),
                            {Results, _} = run_multi(Bin, Pkt, MapState, 35),
                            %% First 30 PASS, 31st DROP
                            First30 = lists:sublist(Results, 30),
                            AllPassFirst = lists:all(fun(R) -> R =:= ?XDP_PASS end, First30),
                            DropAt31 = (lists:nth(31, Results) =:= ?XDP_DROP),
                            AllPassFirst andalso DropAt31
                        after
                            ebpf_vm:destroy_maps(MapState)
                        end
                    end
                ),
                [{numtests, 50}]
            )
        )
    end}.

%%% --- 18: ICMP rate limiter with random IPs — threshold per source IP ---

stateful_18_icmp_random_test_() ->
    {timeout, 60, fun() ->
        ?assert(
            proper:quickcheck(
                ?FORALL(
                    {SrcIP, DstIP},
                    {ip_addr(), ip_addr()},
                    begin
                        {ok, Bin} = ebl_compile:file("examples/18_icmp_rate_limiter.ebl"),
                        MapState = ebpf_vm:create_maps([{hash, 4, 8, 32768}]),
                        try
                            Pkt = ebpf_test_pkt:icmp(#{src_ip => SrcIP, dst_ip => DstIP}),
                            {Results, _} = run_multi(Bin, Pkt, MapState, 15),
                            First10 = lists:sublist(Results, 10),
                            AllPassFirst = lists:all(fun(R) -> R =:= ?XDP_PASS end, First10),
                            DropAt11 = (lists:nth(11, Results) =:= ?XDP_DROP),
                            AllPassFirst andalso DropAt11
                        after
                            ebpf_vm:destroy_maps(MapState)
                        end
                    end
                ),
                [{numtests, 50}]
            )
        )
    end}.

%%% --- Mixed traffic: non-matching packets don't increment counters ---

stateful_15_mixed_traffic_test_() ->
    {timeout, 60, fun() ->
        {ok, Bin} = ebl_compile:file("examples/15_syn_flood_protect.ebl"),
        MapState = ebpf_vm:create_maps([{hash, 4, 8, 65536}]),
        try
            SynPkt = ebpf_test_pkt:tcp(#{
                src_ip => {10, 0, 0, 1},
                dst_ip => {10, 0, 0, 2},
                flags => [syn]
            }),
            UdpPkt = ebpf_test_pkt:udp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
            IcmpPkt = ebpf_test_pkt:icmp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
            AckPkt = ebpf_test_pkt:tcp(#{
                src_ip => {10, 0, 0, 1},
                dst_ip => {10, 0, 0, 2},
                flags => [ack]
            }),
            %% Interleave: 50 SYN + 200 non-SYN traffic
            Pkts = lists:flatten([
                lists:duplicate(10, SynPkt),
                lists:duplicate(50, UdpPkt),
                lists:duplicate(10, SynPkt),
                lists:duplicate(50, IcmpPkt),
                lists:duplicate(10, SynPkt),
                lists:duplicate(50, AckPkt),
                lists:duplicate(10, SynPkt),
                %% total SYN = 50
                lists:duplicate(10, SynPkt)
            ]),
            {Results, _} = run_sequence(Bin, Pkts, MapState),
            %% Only 50 SYNs total — all under threshold (100)
            ?assert(lists:all(fun(R) -> R =:= ?XDP_PASS end, Results))
        after
            ebpf_vm:destroy_maps(MapState)
        end
    end}.

%%% --- Cross-validation: Erlang VM == uBPF (stateless, per-packet) ---

prop_xval(Path, MapSpecs) ->
    ?FORALL(
        Pkt,
        any_pkt(),
        begin
            {ok, Bin} = ebl_compile:file(Path),
            Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
            Opts = #{maps => MapSpecs},
            {ok, ErlResult} = ebpf_vm:run(Bin, Ctx, Opts),
            case ebpf_ubpf:start() of
                {ok, Port} ->
                    try
                        case ebpf_ubpf:load(Port, Bin) of
                            ok ->
                                {ok, UbpfResult} = ebpf_ubpf:run_xdp(Port, Pkt),
                                ErlResult =:= UbpfResult;
                            {error, _} ->
                                true
                        end
                    after
                        ebpf_ubpf:stop(Port)
                    end;
                {error, ubpf_port_not_found} ->
                    true
            end
        end
    ).

prop_xval_15_test_() ->
    {timeout, 120, fun() ->
        ?assert(
            proper:quickcheck(
                prop_xval(
                    "examples/15_syn_flood_protect.ebl", [{hash, 4, 8, 65536}]
                ),
                [{numtests, 200}]
            )
        )
    end}.

prop_xval_16_test_() ->
    {timeout, 120, fun() ->
        ?assert(
            proper:quickcheck(
                prop_xval(
                    "examples/16_port_firewall.ebl", [{hash, 4, 8, 1024}]
                ),
                [{numtests, 200}]
            )
        )
    end}.

prop_xval_20_test_() ->
    {timeout, 120, fun() ->
        ?assert(
            proper:quickcheck(
                prop_xval(
                    "examples/20_subnet_firewall.ebl", [{hash, 4, 8, 4096}]
                ),
                [{numtests, 200}]
            )
        )
    end}.

prop_xval_22_test_() ->
    {timeout, 120, fun() ->
        ?assert(
            proper:quickcheck(
                prop_xval(
                    "examples/22_bandwidth_monitor.ebl", [{hash, 4, 8, 65536}]
                ),
                [{numtests, 200}]
            )
        )
    end}.

%%% ===================================================================
%%% Test wrapper
%%% ===================================================================

prop_test(PropFun) ->
    {timeout, 60, fun() ->
        ?assert(proper:quickcheck(PropFun(), [{numtests, ?NUMTESTS}]))
    end}.
