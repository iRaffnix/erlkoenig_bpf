-module(ebpf_ctx_test).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% XDP context fields (struct xdp_md)
%%% ===================================================================

xdp_data_test() ->
    ?assertEqual({ok, 0, 4}, ebpf_ctx:field(xdp, <<"data">>)).

xdp_data_end_test() ->
    ?assertEqual({ok, 4, 4}, ebpf_ctx:field(xdp, <<"data_end">>)).

xdp_data_meta_test() ->
    ?assertEqual({ok, 8, 4}, ebpf_ctx:field(xdp, <<"data_meta">>)).

xdp_ingress_ifindex_test() ->
    ?assertEqual({ok, 12, 4}, ebpf_ctx:field(xdp, <<"ingress_ifindex">>)).

xdp_rx_queue_index_test() ->
    ?assertEqual({ok, 16, 4}, ebpf_ctx:field(xdp, <<"rx_queue_index">>)).

xdp_egress_ifindex_test() ->
    ?assertEqual({ok, 20, 4}, ebpf_ctx:field(xdp, <<"egress_ifindex">>)).

xdp_unknown_field_test() ->
    ?assertEqual({error, unknown_field}, ebpf_ctx:field(xdp, <<"nonexistent">>)).

xdp_field_count_test() ->
    ?assertEqual(6, length(ebpf_ctx:fields(xdp))).

%%% ===================================================================
%%% TC context fields (struct __sk_buff)
%%% ===================================================================

tc_len_test() ->
    ?assertEqual({ok, 0, 4}, ebpf_ctx:field(tc, <<"len">>)).

tc_pkt_type_test() ->
    ?assertEqual({ok, 4, 4}, ebpf_ctx:field(tc, <<"pkt_type">>)).

tc_mark_test() ->
    ?assertEqual({ok, 8, 4}, ebpf_ctx:field(tc, <<"mark">>)).

tc_protocol_test() ->
    ?assertEqual({ok, 16, 4}, ebpf_ctx:field(tc, <<"protocol">>)).

tc_data_test() ->
    ?assertEqual({ok, 76, 4}, ebpf_ctx:field(tc, <<"data">>)).

tc_data_end_test() ->
    ?assertEqual({ok, 80, 4}, ebpf_ctx:field(tc, <<"data_end">>)).

tc_local_port_test() ->
    ?assertEqual({ok, 104, 4}, ebpf_ctx:field(tc, <<"local_port">>)).

tc_unknown_field_test() ->
    ?assertEqual({error, unknown_field}, ebpf_ctx:field(tc, <<"nonexistent">>)).

tc_field_count_test() ->
    ?assertEqual(27, length(ebpf_ctx:fields(tc))).

%%% ===================================================================
%%% All fields are u32 (size = 4)
%%% ===================================================================

all_xdp_fields_are_u32_test() ->
    lists:foreach(fun({_Name, _Off, Size}) ->
        ?assertEqual(4, Size)
    end, ebpf_ctx:fields(xdp)).

all_tc_fields_are_u32_test() ->
    lists:foreach(fun({_Name, _Off, Size}) ->
        ?assertEqual(4, Size)
    end, ebpf_ctx:fields(tc)).

%%% ===================================================================
%%% Offset consistency: no gaps, monotonically increasing
%%% ===================================================================

xdp_offsets_contiguous_test() ->
    %% XDP fields should be densely packed u32s: 0, 4, 8, 12, 16, 20
    Offsets = [Off || {_, Off, _} <- ebpf_ctx:fields(xdp)],
    Expected = lists:seq(0, (length(Offsets) - 1) * 4, 4),
    ?assertEqual(Expected, Offsets).

tc_offsets_monotonic_test() ->
    %% TC __sk_buff offsets must be strictly monotonically increasing
    Offsets = [Off || {_, Off, _} <- ebpf_ctx:fields(tc)],
    pairs_ascending(Offsets).

pairs_ascending([]) -> ok;
pairs_ascending([_]) -> ok;
pairs_ascending([A, B | Rest]) ->
    ?assert(A < B),
    pairs_ascending([B | Rest]).

%%% ===================================================================
%%% cgroup and socket have at least data + data_end
%%% ===================================================================

cgroup_has_data_test() ->
    ?assertMatch({ok, _, 4}, ebpf_ctx:field(cgroup, <<"data">>)).

cgroup_has_data_end_test() ->
    ?assertMatch({ok, _, 4}, ebpf_ctx:field(cgroup, <<"data_end">>)).

socket_has_data_test() ->
    ?assertMatch({ok, _, 4}, ebpf_ctx:field(socket, <<"data">>)).

socket_has_data_end_test() ->
    ?assertMatch({ok, _, 4}, ebpf_ctx:field(socket, <<"data_end">>)).

%%% ===================================================================
%%% Cross-type: same field name can have different offsets
%%% ===================================================================

data_offset_differs_xdp_vs_tc_test() ->
    {ok, XdpOff, _} = ebpf_ctx:field(xdp, <<"data">>),
    {ok, TcOff, _} = ebpf_ctx:field(tc, <<"data">>),
    %% xdp_md.data = 0, __sk_buff.data = 76
    ?assertNotEqual(XdpOff, TcOff).

%%% ===================================================================
%%% Kernel-verified offsets for xdp_md (Linux UAPI header check)
%%% ===================================================================
%%
%% These values come from linux/bpf.h struct xdp_md:
%%   __u32 data;            // offset 0
%%   __u32 data_end;        // offset 4
%%   __u32 data_meta;       // offset 8
%%   __u32 ingress_ifindex;  // offset 12
%%   __u32 rx_queue_index;   // offset 16
%%   __u32 egress_ifindex;   // offset 20

xdp_matches_kernel_uapi_test() ->
    Expected = [
        {<<"data">>,            0},
        {<<"data_end">>,        4},
        {<<"data_meta">>,       8},
        {<<"ingress_ifindex">>, 12},
        {<<"rx_queue_index">>,  16},
        {<<"egress_ifindex">>,  20}
    ],
    lists:foreach(fun({Name, ExpOff}) ->
        {ok, Off, 4} = ebpf_ctx:field(xdp, Name),
        ?assertEqual(ExpOff, Off)
    end, Expected).
