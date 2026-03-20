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

-module(ebpf_test_pkt_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% 1. TCP packet minimum size (14+20+20 = 54)
tcp_min_size_test() ->
    Pkt = ebpf_test_pkt:tcp(#{}),
    ?assert(byte_size(Pkt) >= 54).

%% 2. UDP packet minimum size (14+20+8 = 42)
udp_min_size_test() ->
    Pkt = ebpf_test_pkt:udp(#{}),
    ?assert(byte_size(Pkt) >= 42).

%% 3. ICMP packet minimum size (14+20+8 = 42)
icmp_min_size_test() ->
    Pkt = ebpf_test_pkt:icmp(#{}),
    ?assert(byte_size(Pkt) >= 42).

%% 4. ARP packet is exactly 42 bytes (14+28)
arp_size_test() ->
    Pkt = ebpf_test_pkt:arp(#{}),
    ?assertEqual(42, byte_size(Pkt)).

%% 5. EthType at offset 12-13 is 0x0800 for IPv4
ethtype_ipv4_test() ->
    lists:foreach(
        fun(Pkt) ->
            <<_:12/binary, 16#0800:16/big, _/binary>> = Pkt
        end,
        [
            ebpf_test_pkt:tcp(#{}),
            ebpf_test_pkt:udp(#{}),
            ebpf_test_pkt:icmp(#{})
        ]
    ).

ethtype_arp_test() ->
    Pkt = ebpf_test_pkt:arp(#{}),
    <<_:12/binary, 16#0806:16/big, _/binary>> = Pkt.

%% 6. IP Protocol at offset 23
ip_protocol_tcp_test() ->
    Pkt = ebpf_test_pkt:tcp(#{}),
    <<_:23/binary, 6:8, _/binary>> = Pkt.

ip_protocol_udp_test() ->
    Pkt = ebpf_test_pkt:udp(#{}),
    <<_:23/binary, 17:8, _/binary>> = Pkt.

ip_protocol_icmp_test() ->
    Pkt = ebpf_test_pkt:icmp(#{}),
    <<_:23/binary, 1:8, _/binary>> = Pkt.

%% 7. Src/Dst Port at offset 34-37 for TCP
tcp_ports_test() ->
    Pkt = ebpf_test_pkt:tcp(#{}),
    <<_:34/binary, 12345:16/big, 80:16/big, _/binary>> = Pkt.

%% 8. IPv4 checksum verification (sum over header with checksum = 0)
ipv4_checksum_test() ->
    lists:foreach(
        fun(Pkt) ->
            <<_:14/binary, IpHdr:20/binary, _/binary>> = Pkt,
            %% Checksum over complete header (including checksum field) must be 0
            Words = [W || <<W:16/big>> <= IpHdr],
            Sum = lists:foldl(fun(W, Acc) -> Acc + W end, 0, Words),
            Folded = (Sum band 16#FFFF) + (Sum bsr 16),
            ?assertEqual(16#FFFF, Folded)
        end,
        [
            ebpf_test_pkt:tcp(#{}),
            ebpf_test_pkt:udp(#{}),
            ebpf_test_pkt:icmp(#{})
        ]
    ).

%% 9. Custom opts override defaults
custom_opts_test() ->
    Pkt = ebpf_test_pkt:tcp(#{
        src_port => 9999,
        dst_port => 443,
        src_ip => {192, 168, 1, 1},
        dst_ip => {192, 168, 1, 2}
    }),
    <<_:34/binary, 9999:16/big, 443:16/big, _/binary>> = Pkt,
    %% Check src IP at offset 26-29, dst IP at offset 30-33
    <<_:26/binary, 192:8, 168:8, 1:8, 1:8, 192:8, 168:8, 1:8, 2:8, _/binary>> = Pkt.

custom_mac_test() ->
    Mac1 = <<16#AA, 16#BB, 16#CC, 16#DD, 16#EE, 16#FF>>,
    Mac2 = <<16#11, 16#22, 16#33, 16#44, 16#55, 16#66>>,
    Pkt = ebpf_test_pkt:udp(#{src_mac => Mac1, dst_mac => Mac2}),
    <<Mac2:6/binary, Mac1:6/binary, _/binary>> = Pkt.

%% 10. Payload is appended
tcp_payload_test() ->
    Payload = <<"Hello, World!">>,
    Pkt = ebpf_test_pkt:tcp(#{payload => Payload}),
    ?assertEqual(54 + byte_size(Payload), byte_size(Pkt)),
    %% Payload is at the end
    PayloadSize = byte_size(Payload),
    TrailingBytes = binary:part(Pkt, byte_size(Pkt) - PayloadSize, PayloadSize),
    ?assertEqual(Payload, TrailingBytes).

udp_payload_test() ->
    Payload = <<"DNS query">>,
    Pkt = ebpf_test_pkt:udp(#{payload => Payload}),
    ?assertEqual(42 + byte_size(Payload), byte_size(Pkt)),
    PayloadSize = byte_size(Payload),
    TrailingBytes = binary:part(Pkt, byte_size(Pkt) - PayloadSize, PayloadSize),
    ?assertEqual(Payload, TrailingBytes).

icmp_payload_test() ->
    Payload = <<"ping data">>,
    Pkt = ebpf_test_pkt:icmp(#{payload => Payload}),
    ?assertEqual(42 + byte_size(Payload), byte_size(Pkt)),
    PayloadSize = byte_size(Payload),
    TrailingBytes = binary:part(Pkt, byte_size(Pkt) - PayloadSize, PayloadSize),
    ?assertEqual(Payload, TrailingBytes).

%% Raw frame
raw_frame_test() ->
    Payload = <<1, 2, 3, 4>>,
    Pkt = ebpf_test_pkt:raw(16#86DD, Payload),
    <<_:12/binary, 16#86DD:16/big, 1, 2, 3, 4>> = Pkt,
    ?assertEqual(14 + 4, byte_size(Pkt)).

%% TCP flags
tcp_flags_test() ->
    %% SYN+ACK: flags field at TCP header offset 12-13 (data offset + flags)
    Pkt = ebpf_test_pkt:tcp(#{flags => [syn, ack]}),
    %% TCP flags are at byte offset 47 (low 8 bits of flags)
    %% Offset 46: data_offset(4) + reserved(3) + high bit of flags(1)
    %% Offset 47: low 8 bits of flags
    <<_:47/binary, FlagByte:8, _/binary>> = Pkt,
    %% SYN=0x02, ACK=0x10 => 0x12
    ?assertEqual(16#12, FlagByte).
