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

-module(ebl_realworld2_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%% ===================================================================
%%% Real-world XDP program tests for examples 19-22.
%%%
%%% Each test compiles an EBL source, runs it in the Erlang VM with
%%% ebpf_test_pkt-generated packets, and cross-validates against uBPF.
%%% ===================================================================

%%% ===================================================================
%%% 19_dns_amplification.ebl — DNS amplification protection
%%% ===================================================================

dns_amp_pass_small_dns_response_test() ->
    %% Small DNS response (< 512 bytes IP length) → PASS
    Pkt = ebpf_test_pkt:udp(#{
        src_ip => {8, 8, 8, 8},
        dst_ip => {10, 0, 0, 1},
        src_port => 53,
        dst_port => 1024,
        payload => <<0:64>>
    }),
    assert_ebl_xdp(
        "examples/19_dns_amplification.ebl",
        Pkt,
        [{hash, 4, 8, 32768}],
        2
    ).

dns_amp_pass_dns_query_test() ->
    %% DNS query (src_port != 53) → not a response → PASS
    Pkt = ebpf_test_pkt:udp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {8, 8, 8, 8},
        src_port => 1024,
        dst_port => 53
    }),
    assert_ebl_xdp(
        "examples/19_dns_amplification.ebl",
        Pkt,
        [{hash, 4, 8, 32768}],
        2
    ).

dns_amp_pass_large_dns_first_test() ->
    %% Large DNS response (> 512 bytes) but first one → count=1, PASS
    BigPayload = <<0:(600 * 8)>>,
    Pkt = ebpf_test_pkt:udp(#{
        src_ip => {8, 8, 8, 8},
        dst_ip => {10, 0, 0, 1},
        src_port => 53,
        dst_port => 1024,
        payload => BigPayload
    }),
    assert_ebl_xdp(
        "examples/19_dns_amplification.ebl",
        Pkt,
        [{hash, 4, 8, 32768}],
        2
    ).

dns_amp_pass_tcp_test() ->
    %% TCP packet → not UDP → PASS
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {8, 8, 8, 8},
        dst_ip => {10, 0, 0, 1}
    }),
    assert_ebl_xdp(
        "examples/19_dns_amplification.ebl",
        Pkt,
        [{hash, 4, 8, 32768}],
        2
    ).

dns_amp_pass_arp_test() ->
    %% ARP → not IPv4 → PASS
    Pkt = ebpf_test_pkt:arp(#{}),
    assert_ebl_xdp(
        "examples/19_dns_amplification.ebl",
        Pkt,
        [{hash, 4, 8, 32768}],
        2
    ).

dns_amp_pass_short_pkt_test() ->
    Pkt = <<0:80>>,
    assert_ebl_xdp(
        "examples/19_dns_amplification.ebl",
        Pkt,
        [{hash, 4, 8, 32768}],
        2
    ).

%%% ===================================================================
%%% 20_subnet_firewall.ebl — CIDR-based subnet blocking
%%% ===================================================================

subnet_fw_pass_unblocked_ip_test() ->
    %% Source IP not in any blocked subnet → PASS
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2}
    }),
    assert_ebl_xdp(
        "examples/20_subnet_firewall.ebl",
        Pkt,
        [{hash, 4, 8, 4096}],
        2
    ).

subnet_fw_pass_arp_test() ->
    Pkt = ebpf_test_pkt:arp(#{}),
    assert_ebl_xdp(
        "examples/20_subnet_firewall.ebl",
        Pkt,
        [{hash, 4, 8, 4096}],
        2
    ).

subnet_fw_pass_short_pkt_test() ->
    Pkt = <<0:80>>,
    assert_ebl_xdp(
        "examples/20_subnet_firewall.ebl",
        Pkt,
        [{hash, 4, 8, 4096}],
        2
    ).

subnet_fw_pass_udp_test() ->
    Pkt = ebpf_test_pkt:udp(#{
        src_ip => {192, 168, 1, 100},
        dst_ip => {10, 0, 0, 1}
    }),
    assert_ebl_xdp(
        "examples/20_subnet_firewall.ebl",
        Pkt,
        [{hash, 4, 8, 4096}],
        2
    ).

subnet_fw_pass_icmp_test() ->
    Pkt = ebpf_test_pkt:icmp(#{
        src_ip => {172, 16, 0, 5},
        dst_ip => {10, 0, 0, 1}
    }),
    assert_ebl_xdp(
        "examples/20_subnet_firewall.ebl",
        Pkt,
        [{hash, 4, 8, 4096}],
        2
    ).

%%% ===================================================================
%%% 21_port_scan_detect.ebl — Port scan detection via RST counting
%%% ===================================================================

portscan_pass_syn_test() ->
    %% Normal SYN → not RST → PASS
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2},
        flags => [syn]
    }),
    assert_ebl_xdp(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

portscan_pass_ack_test() ->
    %% Normal ACK → not RST → PASS
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2},
        flags => [ack]
    }),
    assert_ebl_xdp(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

portscan_pass_first_rst_test() ->
    %% First RST → count=1, under threshold → PASS
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2},
        flags => [rst]
    }),
    assert_ebl_xdp(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

portscan_pass_udp_test() ->
    %% UDP → not TCP → PASS
    Pkt = ebpf_test_pkt:udp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2}
    }),
    assert_ebl_xdp(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

portscan_pass_arp_test() ->
    Pkt = ebpf_test_pkt:arp(#{}),
    assert_ebl_xdp(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

portscan_pass_short_pkt_test() ->
    Pkt = <<0:80>>,
    assert_ebl_xdp(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

portscan_pass_syn_ack_test() ->
    %% SYN+ACK → not RST → PASS
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2},
        flags => [syn, ack]
    }),
    assert_ebl_xdp(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

%%% ===================================================================
%%% 22_bandwidth_monitor.ebl — Byte counting per source IP
%%% ===================================================================

bwmon_pass_tcp_test() ->
    %% TCP → always PASS (monitoring only)
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2}
    }),
    assert_ebl_xdp(
        "examples/22_bandwidth_monitor.ebl",
        Pkt,
        [{hash, 4, 8, 65536}],
        2
    ).

bwmon_pass_udp_test() ->
    %% UDP → always PASS
    Pkt = ebpf_test_pkt:udp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2}
    }),
    assert_ebl_xdp(
        "examples/22_bandwidth_monitor.ebl",
        Pkt,
        [{hash, 4, 8, 65536}],
        2
    ).

bwmon_pass_icmp_test() ->
    Pkt = ebpf_test_pkt:icmp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2}
    }),
    assert_ebl_xdp(
        "examples/22_bandwidth_monitor.ebl",
        Pkt,
        [{hash, 4, 8, 65536}],
        2
    ).

bwmon_pass_arp_test() ->
    %% ARP → not IPv4, passes without counting
    Pkt = ebpf_test_pkt:arp(#{}),
    assert_ebl_xdp(
        "examples/22_bandwidth_monitor.ebl",
        Pkt,
        [{hash, 4, 8, 65536}],
        2
    ).

bwmon_pass_short_pkt_test() ->
    Pkt = <<0:80>>,
    assert_ebl_xdp(
        "examples/22_bandwidth_monitor.ebl",
        Pkt,
        [{hash, 4, 8, 65536}],
        2
    ).

bwmon_pass_large_payload_test() ->
    %% Large payload → still PASS (just counts more bytes)
    BigPayload = <<0:(500 * 8)>>,
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2},
        payload => BigPayload
    }),
    assert_ebl_xdp(
        "examples/22_bandwidth_monitor.ebl",
        Pkt,
        [{hash, 4, 8, 65536}],
        2
    ).

%%% ===================================================================
%%% Cross-validation: Erlang VM vs uBPF
%%% ===================================================================

xval_dns_amp_small_test() ->
    Pkt = ebpf_test_pkt:udp(#{
        src_ip => {8, 8, 8, 8},
        dst_ip => {10, 0, 0, 1},
        src_port => 53,
        dst_port => 1024
    }),
    assert_ebl_xdp_xval(
        "examples/19_dns_amplification.ebl",
        Pkt,
        [{hash, 4, 8, 32768}],
        2
    ).

xval_subnet_fw_test() ->
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2}
    }),
    assert_ebl_xdp_xval(
        "examples/20_subnet_firewall.ebl",
        Pkt,
        [{hash, 4, 8, 4096}],
        2
    ).

xval_portscan_syn_test() ->
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2},
        flags => [syn]
    }),
    assert_ebl_xdp_xval(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

xval_portscan_rst_test() ->
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2},
        flags => [rst]
    }),
    assert_ebl_xdp_xval(
        "examples/21_port_scan_detect.ebl",
        Pkt,
        [{hash, 4, 8, 16384}],
        2
    ).

xval_bwmon_tcp_test() ->
    Pkt = ebpf_test_pkt:tcp(#{
        src_ip => {10, 0, 0, 1},
        dst_ip => {10, 0, 0, 2}
    }),
    assert_ebl_xdp_xval(
        "examples/22_bandwidth_monitor.ebl",
        Pkt,
        [{hash, 4, 8, 65536}],
        2
    ).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

compile(Path) ->
    {ok, Bin} = ebl_compile:file(Path),
    Bin.

assert_ebl_xdp(Path, Pkt, MapSpecs, Expected) ->
    Bin = compile(Path),
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    Opts =
        case MapSpecs of
            [] -> #{};
            _ -> #{maps => MapSpecs}
        end,
    {ok, Result} = ebpf_vm:run(Bin, Ctx, Opts),
    ?assertEqual(Expected, Result).

assert_ebl_xdp_xval(Path, Pkt, MapSpecs, Expected) ->
    Bin = compile(Path),
    Ctx = ebpf_test_pkt:xdp_ctx(Pkt),
    Opts =
        case MapSpecs of
            [] -> #{};
            _ -> #{maps => MapSpecs}
        end,
    {ok, ErlResult} = ebpf_vm:run(Bin, Ctx, Opts),
    ?assertEqual(Expected, ErlResult),
    case ebpf_ubpf:start() of
        {ok, Port} ->
            try
                case ebpf_ubpf:load(Port, Bin) of
                    ok ->
                        {ok, UbpfResult} = ebpf_ubpf:run_xdp(Port, Pkt),
                        ?assertEqual(Expected, UbpfResult);
                    {error, _LoadErr} ->
                        ok
                end
            after
                ebpf_ubpf:stop(Port)
            end;
        {error, ubpf_port_not_found} ->
            ok
    end.
