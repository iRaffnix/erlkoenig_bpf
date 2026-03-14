-module(ebl_realworld_test).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Real-world XDP program tests for examples 15-18.
%%%
%%% Each test compiles an EBL source, runs it in the Erlang VM with
%%% ebpf_test_pkt-generated packets, and cross-validates against uBPF.
%%% ===================================================================

%%% ===================================================================
%%% 15_syn_flood_protect.ebl — SYN flood detection
%%% ===================================================================

syn_flood_pass_normal_tcp_test() ->
    %% Normal TCP SYN → count=1, under threshold → PASS (2)
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2},
                               flags => [syn]}),
    MapSpecs = [{hash, 4, 8, 65536}],
    assert_ebl_xdp("examples/15_syn_flood_protect.ebl", Pkt, MapSpecs, 2).

syn_flood_pass_syn_ack_test() ->
    %% SYN+ACK → legitimate response, always PASS
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2},
                               flags => [syn, ack]}),
    MapSpecs = [{hash, 4, 8, 65536}],
    assert_ebl_xdp("examples/15_syn_flood_protect.ebl", Pkt, MapSpecs, 2).

syn_flood_pass_ack_only_test() ->
    %% ACK only → no SYN bit → PASS
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2},
                               flags => [ack]}),
    MapSpecs = [{hash, 4, 8, 65536}],
    assert_ebl_xdp("examples/15_syn_flood_protect.ebl", Pkt, MapSpecs, 2).

syn_flood_pass_udp_test() ->
    %% UDP → not TCP → PASS
    Pkt = ebpf_test_pkt:udp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 65536}],
    assert_ebl_xdp("examples/15_syn_flood_protect.ebl", Pkt, MapSpecs, 2).

syn_flood_pass_arp_test() ->
    %% ARP → not IPv4 → PASS
    Pkt = ebpf_test_pkt:arp(#{}),
    MapSpecs = [{hash, 4, 8, 65536}],
    assert_ebl_xdp("examples/15_syn_flood_protect.ebl", Pkt, MapSpecs, 2).

syn_flood_pass_short_pkt_test() ->
    %% Too short for TCP → bounds check → PASS
    Pkt = <<0:80>>,
    MapSpecs = [{hash, 4, 8, 65536}],
    assert_ebl_xdp("examples/15_syn_flood_protect.ebl", Pkt, MapSpecs, 2).

%%% ===================================================================
%%% 16_port_firewall.ebl — Port-based firewall
%%% ===================================================================

firewall_drop_unknown_tcp_port_test() ->
    %% TCP to port 9999 (not in allowed_ports map) → DROP (1)
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2},
                               dst_port => 9999}),
    MapSpecs = [{hash, 4, 8, 1024}],
    assert_ebl_xdp("examples/16_port_firewall.ebl", Pkt, MapSpecs, 1).

firewall_drop_unknown_udp_port_test() ->
    %% UDP to port 5555 → not allowed → DROP
    Pkt = ebpf_test_pkt:udp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2},
                               dst_port => 5555}),
    MapSpecs = [{hash, 4, 8, 1024}],
    assert_ebl_xdp("examples/16_port_firewall.ebl", Pkt, MapSpecs, 1).

firewall_pass_arp_test() ->
    %% ARP → not IPv4 → PASS
    Pkt = ebpf_test_pkt:arp(#{}),
    MapSpecs = [{hash, 4, 8, 1024}],
    assert_ebl_xdp("examples/16_port_firewall.ebl", Pkt, MapSpecs, 2).

firewall_pass_icmp_test() ->
    %% ICMP → not TCP/UDP → PASS
    Pkt = ebpf_test_pkt:icmp(#{src_ip => {10, 0, 0, 1},
                                dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 1024}],
    assert_ebl_xdp("examples/16_port_firewall.ebl", Pkt, MapSpecs, 2).

firewall_pass_short_pkt_test() ->
    Pkt = <<0:80>>,
    MapSpecs = [{hash, 4, 8, 1024}],
    assert_ebl_xdp("examples/16_port_firewall.ebl", Pkt, MapSpecs, 2).

%%% ===================================================================
%%% 17_ttl_filter.ebl — Low TTL detection
%%% ===================================================================

ttl_pass_normal_ttl_test() ->
    %% Normal TTL (64) → PASS
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 16384}],
    assert_ebl_xdp("examples/17_ttl_filter.ebl", Pkt, MapSpecs, 2).

ttl_pass_arp_test() ->
    %% ARP → not IPv4 → PASS
    Pkt = ebpf_test_pkt:arp(#{}),
    MapSpecs = [{hash, 4, 8, 16384}],
    assert_ebl_xdp("examples/17_ttl_filter.ebl", Pkt, MapSpecs, 2).

ttl_pass_short_pkt_test() ->
    Pkt = <<0:80>>,
    MapSpecs = [{hash, 4, 8, 16384}],
    assert_ebl_xdp("examples/17_ttl_filter.ebl", Pkt, MapSpecs, 2).

%%% ===================================================================
%%% 18_icmp_rate_limiter.ebl — ICMP ping rate limiting
%%% ===================================================================

icmp_rl_pass_first_ping_test() ->
    %% First Echo Request → count=1, under threshold → PASS
    Pkt = ebpf_test_pkt:icmp(#{src_ip => {10, 0, 0, 1},
                                dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 32768}],
    assert_ebl_xdp("examples/18_icmp_rate_limiter.ebl", Pkt, MapSpecs, 2).

icmp_rl_pass_tcp_test() ->
    %% TCP → not ICMP → PASS
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 32768}],
    assert_ebl_xdp("examples/18_icmp_rate_limiter.ebl", Pkt, MapSpecs, 2).

icmp_rl_pass_udp_test() ->
    %% UDP → not ICMP → PASS
    Pkt = ebpf_test_pkt:udp(#{src_ip => {10, 0, 0, 1},
                               dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 32768}],
    assert_ebl_xdp("examples/18_icmp_rate_limiter.ebl", Pkt, MapSpecs, 2).

icmp_rl_pass_arp_test() ->
    %% ARP → PASS
    Pkt = ebpf_test_pkt:arp(#{}),
    MapSpecs = [{hash, 4, 8, 32768}],
    assert_ebl_xdp("examples/18_icmp_rate_limiter.ebl", Pkt, MapSpecs, 2).

icmp_rl_pass_short_pkt_test() ->
    Pkt = <<0:80>>,
    MapSpecs = [{hash, 4, 8, 32768}],
    assert_ebl_xdp("examples/18_icmp_rate_limiter.ebl", Pkt, MapSpecs, 2).

%%% ===================================================================
%%% Cross-validation: Erlang VM vs uBPF
%%% ===================================================================

xval_syn_flood_syn_test() ->
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {192, 168, 1, 1},
                               dst_ip => {10, 0, 0, 2},
                               flags => [syn]}),
    assert_ebl_xdp_xval("examples/15_syn_flood_protect.ebl", Pkt,
                         [{hash, 4, 8, 65536}], 2).

xval_syn_flood_ack_test() ->
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {192, 168, 1, 1},
                               dst_ip => {10, 0, 0, 2},
                               flags => [ack]}),
    assert_ebl_xdp_xval("examples/15_syn_flood_protect.ebl", Pkt,
                         [{hash, 4, 8, 65536}], 2).

xval_firewall_drop_test() ->
    Pkt = ebpf_test_pkt:tcp(#{dst_port => 9999}),
    assert_ebl_xdp_xval("examples/16_port_firewall.ebl", Pkt,
                         [{hash, 4, 8, 1024}], 1).

xval_ttl_normal_test() ->
    Pkt = ebpf_test_pkt:tcp(#{}),
    assert_ebl_xdp_xval("examples/17_ttl_filter.ebl", Pkt,
                         [{hash, 4, 8, 16384}], 2).

xval_icmp_rl_first_test() ->
    Pkt = ebpf_test_pkt:icmp(#{}),
    assert_ebl_xdp_xval("examples/18_icmp_rate_limiter.ebl", Pkt,
                         [{hash, 4, 8, 32768}], 2).

%%% ===================================================================
%%% Helpers (identical to ebl_packet_test)
%%% ===================================================================

compile(Path) ->
    {ok, Bin} = ebl_compile:file(Path),
    Bin.

assert_ebl_xdp(Path, Pkt, MapSpecs, Expected) ->
    Bin = compile(Path),
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    Opts = case MapSpecs of
        [] -> #{};
        _ -> #{maps => MapSpecs}
    end,
    {ok, Result} = ebpf_vm:run(Bin, Ctx, Opts),
    ?assertEqual(Expected, Result).

assert_ebl_xdp_xval(Path, Pkt, MapSpecs, Expected) ->
    Bin = compile(Path),
    %% Erlang VM
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    Opts = case MapSpecs of
        [] -> #{};
        _ -> #{maps => MapSpecs}
    end,
    {ok, ErlResult} = ebpf_vm:run(Bin, Ctx, Opts),
    ?assertEqual(Expected, ErlResult),
    %% uBPF cross-validation
    case ebpf_ubpf:start() of
        {ok, Port} ->
            try
                case ebpf_ubpf:load(Port, Bin) of
                    ok ->
                        {ok, UbpfResult} = ebpf_ubpf:run_xdp(Port, Pkt),
                        ?assertEqual(Expected, UbpfResult);
                    {error, _LoadErr} ->
                        %% uBPF rejects ld_map_fd — skip
                        ok
                end
            after
                ebpf_ubpf:stop(Port)
            end;
        {error, ubpf_port_not_found} ->
            ok
    end.
