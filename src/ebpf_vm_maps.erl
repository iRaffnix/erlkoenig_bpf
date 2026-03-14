%% @doc ETS-backed BPF map stubs for the VM.
-module(ebpf_vm_maps).

-include("ebpf_vm.hrl").

-export([create/4, destroy/1, lookup/3, update/4, delete/3]).

%% @doc Create a new map, returns {MapFd, EtsTab, MapMeta}.
-spec create(atom(), pos_integer(), pos_integer(), pos_integer()) ->
    {non_neg_integer(), ets:tid(), #map_meta{}}.
create(Type, KeySize, ValSize, MaxEntries) ->
    Tab = ets:new(bpf_map, [set, public]),
    Fd = erlang:unique_integer([positive]),
    Meta = #map_meta{type = Type, key_size = KeySize,
                     val_size = ValSize, max_entries = MaxEntries},
    {Fd, Tab, Meta}.

%% @doc Destroy a map (delete ETS table).
-spec destroy(ets:tid()) -> ok.
destroy(Tab) ->
    ets:delete(Tab),
    ok.

%% @doc Lookup key in map. Returns {ok, ValueBin} | none.
-spec lookup(ets:tid(), binary(), #map_meta{}) -> {ok, binary()} | none.
lookup(Tab, Key, #map_meta{key_size = KS}) ->
    PaddedKey = pad_to(Key, KS),
    case ets:lookup(Tab, PaddedKey) of
        [{_, Val}] -> {ok, Val};
        [] -> none
    end.

%% @doc Update key in map. Returns ok | {error, full}.
-spec update(ets:tid(), binary(), binary(), #map_meta{}) -> ok | {error, full}.
update(Tab, Key, Value, #map_meta{key_size = KS, val_size = VS, max_entries = Max}) ->
    PaddedKey = pad_to(Key, KS),
    PaddedVal = pad_to(Value, VS),
    case ets:lookup(Tab, PaddedKey) of
        [{_, _}] ->
            ets:insert(Tab, {PaddedKey, PaddedVal}),
            ok;
        [] ->
            case ets:info(Tab, size) of
                N when N >= Max -> {error, full};
                _ ->
                    ets:insert(Tab, {PaddedKey, PaddedVal}),
                    ok
            end
    end.

%% @doc Delete key from map.
-spec delete(ets:tid(), binary(), #map_meta{}) -> ok.
delete(Tab, Key, #map_meta{key_size = KS}) ->
    PaddedKey = pad_to(Key, KS),
    ets:delete(Tab, PaddedKey),
    ok.

%% Pad or truncate binary to exact size.
pad_to(Bin, Size) when byte_size(Bin) >= Size ->
    <<Result:Size/binary, _/binary>> = Bin,
    Result;
pad_to(Bin, Size) ->
    Pad = Size - byte_size(Bin),
    <<Bin/binary, 0:(Pad*8)>>.
