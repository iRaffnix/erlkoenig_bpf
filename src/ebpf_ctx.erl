%% @doc Context struct layout definitions for BPF program types.
%%
%% Provides field offset and size information for accessing context
%% structures (xdp_md, __sk_buff, etc.) from BPF programs.
-module(ebpf_ctx).

-export([field/2, fields/1]).

%% @doc Look up a context field by program type and field name.
%% Returns {ok, Offset, Size} or {error, unknown_field}.
-spec field(xdp | tc | cgroup | socket, binary()) ->
    {ok, byte(), 4} | {error, unknown_field}.
field(ProgType, FieldName) ->
    case lists:keyfind(FieldName, 1, fields(ProgType)) of
        {_, Offset, Size} -> {ok, Offset, Size};
        false -> {error, unknown_field}
    end.

%% @doc Return all context fields for a program type.
%% Each entry is {Name, Offset, SizeInBytes}.
-spec fields(xdp | tc | cgroup | socket) -> [{<<_:24, _:_*8>>, byte(), 4}, ...].

%% struct xdp_md (all u32)
fields(xdp) ->
    [{<<"data">>,            0,  4},
     {<<"data_end">>,        4,  4},
     {<<"data_meta">>,       8,  4},
     {<<"ingress_ifindex">>, 12, 4},
     {<<"rx_queue_index">>,  16, 4},
     {<<"egress_ifindex">>,  20, 4}];

%% struct __sk_buff (selected fields, all u32)
fields(tc) ->
    [{<<"len">>,       0,  4},
     {<<"pkt_type">>,  4,  4},
     {<<"mark">>,      8,  4},
     {<<"queue_mapping">>, 12, 4},
     {<<"protocol">>,  16, 4},
     {<<"vlan_present">>, 20, 4},
     {<<"vlan_tci">>,  24, 4},
     {<<"vlan_proto">>, 28, 4},
     {<<"priority">>,  32, 4},
     {<<"ingress_ifindex">>, 36, 4},
     {<<"ifindex">>,   40, 4},
     {<<"tc_index">>,  44, 4},
     {<<"cb0">>,       48, 4},
     {<<"cb1">>,       52, 4},
     {<<"cb2">>,       56, 4},
     {<<"cb3">>,       60, 4},
     {<<"cb4">>,       64, 4},
     {<<"hash">>,      68, 4},
     {<<"tc_classid">>, 72, 4},
     {<<"data">>,      76, 4},
     {<<"data_end">>,  80, 4},
     {<<"napi_id">>,   84, 4},
     {<<"family">>,    88, 4},
     {<<"remote_ip4">>, 92, 4},
     {<<"local_ip4">>,  96, 4},
     {<<"remote_port">>, 100, 4},
     {<<"local_port">>,  104, 4}];

%% Placeholder for other program types
fields(cgroup) ->
    [{<<"data">>, 0, 4},
     {<<"data_end">>, 4, 4}];

fields(socket) ->
    [{<<"data">>, 0, 4},
     {<<"data_end">>, 4, 4}].
