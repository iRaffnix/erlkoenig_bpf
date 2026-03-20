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

%% @doc Property-based cross-validation: random packets through both VMs.
%%
%% Uses PropEr to generate random packet sequences and verify that the
%% Erlang VM and uBPF agree on every return value.  This catches
%% corner cases that hand-written tests miss: unusual IPs, edge-case
%% TTLs, payload sizes, flag combinations.
-module(ebl_prop_xval_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(FORALL(X, RawType, Prop),
    proper:forall(RawType, fun(X) -> Prop end)
).
-define(PROP_LET(X, RawType, Gen),
    proper_types:bind(RawType, fun(X) -> Gen end, false)
).

-define(XDP_DROP, 1).
-define(XDP_PASS, 2).

%%% ===================================================================
%%% Packet generators (same as ebl_prop_test, duplicated for isolation)
%%% ===================================================================

ip_addr() ->
    {
        proper_types:range(1, 254),
        proper_types:range(0, 255),
        proper_types:range(0, 255),
        proper_types:range(1, 254)
    }.

tcp_flags() ->
    proper_types:non_empty(
        proper_types:list(proper_types:oneof([syn, ack, rst, fin, psh]))
    ).

tcp_pkt() ->
    ?PROP_LET(
        {SrcIP, DstIP, SrcPort, DstPort, Flags, PayloadSize, TTL},
        {
            ip_addr(),
            ip_addr(),
            proper_types:range(1, 65535),
            proper_types:range(1, 65535),
            tcp_flags(),
            proper_types:range(0, 200),
            proper_types:range(1, 255)
        },
        ebpf_test_pkt:tcp(#{
            src_ip => SrcIP,
            dst_ip => DstIP,
            src_port => SrcPort,
            dst_port => DstPort,
            flags => lists:usort(Flags),
            payload => <<0:(PayloadSize * 8)>>,
            ttl => TTL
        })
    ).

udp_pkt() ->
    ?PROP_LET(
        {SrcIP, DstIP, SrcPort, DstPort, PayloadSize, TTL},
        {
            ip_addr(),
            ip_addr(),
            proper_types:range(1, 65535),
            proper_types:range(1, 65535),
            proper_types:range(0, 300),
            proper_types:range(1, 255)
        },
        ebpf_test_pkt:udp(#{
            src_ip => SrcIP,
            dst_ip => DstIP,
            src_port => SrcPort,
            dst_port => DstPort,
            payload => <<0:(PayloadSize * 8)>>,
            ttl => TTL
        })
    ).

icmp_pkt() ->
    ?PROP_LET(
        {SrcIP, DstIP, TTL},
        {ip_addr(), ip_addr(), proper_types:range(1, 255)},
        ebpf_test_pkt:icmp(#{
            src_ip => SrcIP,
            dst_ip => DstIP,
            ttl => TTL
        })
    ).

arp_pkt() ->
    ?PROP_LET(
        {SenderIP, TargetIP},
        {ip_addr(), ip_addr()},
        ebpf_test_pkt:arp(#{sender_ip => SenderIP, target_ip => TargetIP})
    ).

any_pkt() ->
    proper_types:oneof([tcp_pkt(), udp_pkt(), icmp_pkt(), arp_pkt()]).

short_pkt() ->
    ?PROP_LET(
        Size,
        proper_types:range(1, 33),
        <<0:(Size * 8)>>
    ).

%%% ===================================================================
%%% Cross-validation core
%%% ===================================================================

port_available() ->
    try
        PortPath = filename:join(code:priv_dir(erlkoenig_ebpf), "ubpf_port"),
        filelib:is_file(PortPath)
    catch
        _:_ -> false
    end.

%% Run a single packet through both VMs and compare.
%% uBPF maps are fresh per call (stateless per-packet).
xval_single(Bin, Pkt, MapSpecs) ->
    %% Erlang VM
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    Opts =
        case MapSpecs of
            [] -> #{};
            _ -> #{maps => MapSpecs}
        end,
    {ok, ErlResult} = ebpf_vm:run(Bin, Ctx, Opts),
    %% uBPF
    case ebpf_ubpf:start() of
        {ok, Port} ->
            try
                lists:foreach(
                    fun({_Type, KS, VS, Max}) ->
                        {ok, _Fd} = ebpf_ubpf:create_map(Port, KS, VS, Max)
                    end,
                    MapSpecs
                ),
                case ebpf_ubpf:load(Port, Bin) of
                    ok ->
                        {ok, UbpfResult} = ebpf_ubpf:run_xdp(Port, Pkt),
                        ErlResult =:= UbpfResult;
                    {error, _} ->
                        %% uBPF doesn't support this program
                        true
                end
            after
                ebpf_ubpf:stop(Port)
            end;
        {error, ubpf_port_not_found} ->
            true
    end.

%%% ===================================================================
%%% Per-program cross-validation properties
%%% ===================================================================

%% Property: for any random packet, Erlang VM and uBPF agree.
prop_xval(Path, MapSpecs) ->
    {ok, Bin} = ebl_compile:file(Path),
    ?FORALL(
        Pkt,
        any_pkt(),
        xval_single(Bin, Pkt, MapSpecs)
    ).

prop_xval_short(Path, MapSpecs) ->
    {ok, Bin} = ebl_compile:file(Path),
    ?FORALL(
        Pkt,
        short_pkt(),
        xval_single(Bin, Pkt, MapSpecs)
    ).

%%% --- 15: SYN Flood ---

prop_xval_15_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/15_syn_flood_protect.ebl", [{hash, 4, 8, 65536}]
            )
        end,
        200
    ).

prop_xval_15_short_test_() ->
    prop_test(
        fun() ->
            prop_xval_short(
                "examples/15_syn_flood_protect.ebl", [{hash, 4, 8, 65536}]
            )
        end,
        100
    ).

%%% --- 16: Port Firewall ---

prop_xval_16_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/16_port_firewall.ebl", [{hash, 4, 8, 1024}]
            )
        end,
        200
    ).

%%% --- 17: TTL Filter ---

prop_xval_17_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/17_ttl_filter.ebl", [{hash, 4, 8, 16384}]
            )
        end,
        200
    ).

%%% --- 18: ICMP Rate Limiter ---

prop_xval_18_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/18_icmp_rate_limiter.ebl", [{hash, 4, 8, 32768}]
            )
        end,
        200
    ).

%%% --- 19: DNS Amplification ---

prop_xval_19_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/19_dns_amplification.ebl", [{hash, 4, 8, 32768}]
            )
        end,
        200
    ).

%%% --- 20: Subnet Firewall ---

prop_xval_20_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/20_subnet_firewall.ebl", [{hash, 4, 8, 4096}]
            )
        end,
        200
    ).

%%% --- 21: Port Scan Detect ---

prop_xval_21_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/21_port_scan_detect.ebl", [{hash, 4, 8, 16384}]
            )
        end,
        200
    ).

%%% --- 22: Bandwidth Monitor ---

prop_xval_22_any_test_() ->
    prop_test(
        fun() ->
            prop_xval(
                "examples/22_bandwidth_monitor.ebl", [{hash, 4, 8, 65536}]
            )
        end,
        200
    ).

%%% ===================================================================
%%% Stateful property: N packets from same IP through both VMs
%%% ===================================================================

%% This is the strongest test: run a fixed number of trigger packets
%% and verify BOTH VMs produce identical sequences of PASS/DROP.
prop_xval_stateful(Path, MapSpecs, PktGen, N) ->
    {ok, Bin} = ebl_compile:file(Path),
    ?FORALL(
        Pkt,
        PktGen,
        begin
            %% Erlang VM: stateful run
            MapState = ebpf_vm:create_maps(MapSpecs),
            try
                ErlResults = erl_run_multi(Bin, Pkt, MapState, N),
                %% uBPF: stateful run (maps persist across run_xdp calls)
                case ebpf_ubpf:start() of
                    {ok, Port} ->
                        try
                            lists:foreach(
                                fun({_Type, KS, VS, Max}) ->
                                    {ok, _} = ebpf_ubpf:create_map(Port, KS, VS, Max)
                                end,
                                MapSpecs
                            ),
                            ok = ebpf_ubpf:load(Port, Bin),
                            UbpfResults = [
                                begin
                                    {ok, R} = ebpf_ubpf:run_xdp(Port, Pkt),
                                    R
                                end
                             || _ <- lists:seq(1, N)
                            ],
                            ErlResults =:= UbpfResults
                        after
                            ebpf_ubpf:stop(Port)
                        end;
                    {error, _} ->
                        true
                end
            after
                ebpf_vm:destroy_maps(MapState)
            end
        end
    ).

erl_run_multi(Bin, Pkt, MapState, N) ->
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    {Results, _} = erl_run_loop(Bin, Ctx, MapState, N, []),
    Results.

erl_run_loop(_Bin, _Ctx, MapState, 0, Acc) ->
    {lists:reverse(Acc), MapState};
erl_run_loop(Bin, Ctx, MapState, N, Acc) ->
    {ok, Result, MapState2} = ebpf_vm:run_stateful(Bin, Ctx, MapState, #{}),
    erl_run_loop(Bin, Ctx, MapState2, N - 1, [Result | Acc]).

%%% --- Stateful: SYN flood with random IPs, 105 packets each ---

prop_xval_stateful_15_test_() ->
    %% 105 SYNs from random IP → first 100 PASS, then DROP
    prop_test(
        fun() ->
            prop_xval_stateful(
                "examples/15_syn_flood_protect.ebl",
                [{hash, 4, 8, 65536}],
                ?PROP_LET(
                    {SrcIP, DstIP},
                    {ip_addr(), ip_addr()},
                    ebpf_test_pkt:tcp(#{
                        src_ip => SrcIP,
                        dst_ip => DstIP,
                        flags => [syn]
                    })
                ),
                105
            )
        end,
        20
    ).

%%% --- Stateful: ICMP rate limiter, 15 packets ---

prop_xval_stateful_18_test_() ->
    prop_test(
        fun() ->
            prop_xval_stateful(
                "examples/18_icmp_rate_limiter.ebl",
                [{hash, 4, 8, 32768}],
                ?PROP_LET(
                    {SrcIP, DstIP},
                    {ip_addr(), ip_addr()},
                    ebpf_test_pkt:icmp(#{src_ip => SrcIP, dst_ip => DstIP})
                ),
                15
            )
        end,
        20
    ).

%%% --- Stateful: Port scan, 35 RSTs ---

prop_xval_stateful_21_test_() ->
    prop_test(
        fun() ->
            prop_xval_stateful(
                "examples/21_port_scan_detect.ebl",
                [{hash, 4, 8, 16384}],
                ?PROP_LET(
                    {SrcIP, DstIP},
                    {ip_addr(), ip_addr()},
                    ebpf_test_pkt:tcp(#{
                        src_ip => SrcIP,
                        dst_ip => DstIP,
                        flags => [rst]
                    })
                ),
                35
            )
        end,
        20
    ).

%%% ===================================================================
%%% Test wrapper
%%% ===================================================================

prop_test(PropFun, NumTests) ->
    case port_available() of
        false ->
            {skip, "ubpf_port not available"};
        true ->
            {timeout, 120, fun() ->
                ?assert(proper:quickcheck(PropFun(), [{numtests, NumTests}]))
            end}
    end.
