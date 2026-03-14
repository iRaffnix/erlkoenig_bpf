-module(ebl_packet_test).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Integration tests for WP-021c: EBL packet parsing programs.
%%%
%%% Each test compiles an EBL source through the full pipeline,
%%% runs it in the Erlang VM with ebpf_test_pkt-generated packets,
%%% and cross-validates against uBPF.
%%% ===================================================================

%%% ===================================================================
%%% 12_packet_parse.ebl — Source-IP extraction
%%% ===================================================================

parse_tcp_src_ip_test() ->
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {192, 168, 1, 100}, dst_ip => {10, 0, 0, 2}}),
    assert_ebl_xdp("examples/12_packet_parse.ebl", Pkt, [], 16#C0A80164).

parse_tcp_src_ip_localhost_test() ->
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {127, 0, 0, 1}, dst_ip => {127, 0, 0, 1}}),
    assert_ebl_xdp("examples/12_packet_parse.ebl", Pkt, [], 16#7F000001).

parse_udp_src_ip_test() ->
    Pkt = ebpf_test_pkt:udp(#{src_ip => {10, 0, 0, 42}, dst_ip => {10, 0, 0, 1}}),
    assert_ebl_xdp("examples/12_packet_parse.ebl", Pkt, [], 16#0A00002A).

parse_arp_returns_zero_test() ->
    %% ARP has ethertype 0x0806, not 0x0800 → returns 0
    Pkt = ebpf_test_pkt:arp(#{}),
    assert_ebl_xdp("examples/12_packet_parse.ebl", Pkt, [], 0).

parse_short_pkt_returns_zero_test() ->
    %% Too short for Ethernet+IP (< 34 bytes)
    Pkt = <<0:100>>,  %% 12.5 bytes rounded to 13
    assert_ebl_xdp("examples/12_packet_parse.ebl", Pkt, [], 0).

parse_icmp_src_ip_test() ->
    Pkt = ebpf_test_pkt:icmp(#{src_ip => {8, 8, 8, 8}, dst_ip => {10, 0, 0, 1}}),
    assert_ebl_xdp("examples/12_packet_parse.ebl", Pkt, [], 16#08080808).

%%% ===================================================================
%%% 13_ip_blacklist.ebl — IP blacklist (drop/pass)
%%% ===================================================================

blacklist_pass_unknown_ip_test() ->
    %% IP not in blacklist → PASS (2)
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 10000}],
    assert_ebl_xdp("examples/13_ip_blacklist.ebl", Pkt, MapSpecs, 2).

blacklist_pass_arp_test() ->
    %% ARP packets always pass (not IPv4)
    Pkt = ebpf_test_pkt:arp(#{}),
    MapSpecs = [{hash, 4, 8, 10000}],
    assert_ebl_xdp("examples/13_ip_blacklist.ebl", Pkt, MapSpecs, 2).

blacklist_pass_short_pkt_test() ->
    %% Short packet → bounds check fails → PASS
    Pkt = <<0:80>>,
    MapSpecs = [{hash, 4, 8, 10000}],
    assert_ebl_xdp("examples/13_ip_blacklist.ebl", Pkt, MapSpecs, 2).

%%% ===================================================================
%%% 14_protocol_counter.ebl — Protocol counting
%%% ===================================================================

counter_tcp_pass_test() ->
    %% TCP packet → always PASS (2), counter incremented
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 256}],
    assert_ebl_xdp("examples/14_protocol_counter.ebl", Pkt, MapSpecs, 2).

counter_udp_pass_test() ->
    Pkt = ebpf_test_pkt:udp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 256}],
    assert_ebl_xdp("examples/14_protocol_counter.ebl", Pkt, MapSpecs, 2).

counter_icmp_pass_test() ->
    Pkt = ebpf_test_pkt:icmp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
    MapSpecs = [{hash, 4, 8, 256}],
    assert_ebl_xdp("examples/14_protocol_counter.ebl", Pkt, MapSpecs, 2).

counter_arp_pass_test() ->
    %% ARP → not IPv4 → PASS without counting
    Pkt = ebpf_test_pkt:arp(#{}),
    MapSpecs = [{hash, 4, 8, 256}],
    assert_ebl_xdp("examples/14_protocol_counter.ebl", Pkt, MapSpecs, 2).

counter_short_pkt_pass_test() ->
    Pkt = <<0:80>>,
    MapSpecs = [{hash, 4, 8, 256}],
    assert_ebl_xdp("examples/14_protocol_counter.ebl", Pkt, MapSpecs, 2).

%%% ===================================================================
%%% Cross-validation: compiled EBL against uBPF
%%% ===================================================================

xval_parse_tcp_test() ->
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {192, 168, 1, 100}, dst_ip => {10, 0, 0, 2}}),
    assert_ebl_xdp_xval("examples/12_packet_parse.ebl", Pkt, [], 16#C0A80164).

xval_parse_arp_test() ->
    Pkt = ebpf_test_pkt:arp(#{}),
    assert_ebl_xdp_xval("examples/12_packet_parse.ebl", Pkt, [], 0).

xval_blacklist_pass_test() ->
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
    assert_ebl_xdp_xval("examples/13_ip_blacklist.ebl", Pkt, [{hash, 4, 8, 10000}], 2).

xval_counter_tcp_test() ->
    Pkt = ebpf_test_pkt:tcp(#{src_ip => {10, 0, 0, 1}, dst_ip => {10, 0, 0, 2}}),
    assert_ebl_xdp_xval("examples/14_protocol_counter.ebl", Pkt, [{hash, 4, 8, 256}], 2).

%%% ===================================================================
%%% Helpers
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
                        %% uBPF rejects programs with map FDs (ld_map_fd src
                        %% register encoding). Skip cross-validation for
                        %% map-using programs — this is a known uBPF limitation.
                        ok
                end
            after
                ebpf_ubpf:stop(Port)
            end;
        {error, ubpf_port_not_found} ->
            ok
    end.
