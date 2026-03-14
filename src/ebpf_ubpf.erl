%% @doc Erlang API for the uBPF userspace eBPF VM.
%%
%% Communicates with the ubpf_port C program via an Erlang port
%% using {packet, 4} framing.
-module(ebpf_ubpf).

-export([start/0, stop/1, load/2, run/2, run_xdp/2,
         create_map/4, reset_maps/1, map_get/3, map_dump/2]).

%% @doc Start the uBPF port process.
-spec start() -> {ok, port()} | {error, ubpf_port_not_found}.
start() ->
    PortPath = filename:join(code:priv_dir(erlkoenig_ebpf), "ubpf_port"),
    case filelib:is_file(PortPath) of
        true ->
            Port = open_port({spawn_executable, PortPath},
                             [binary, {packet, 4}, exit_status, use_stdio]),
            {ok, Port};
        false ->
            {error, ubpf_port_not_found}
    end.

%% @doc Stop the uBPF port process.
-spec stop(port()) -> ok.
stop(Port) ->
    port_command(Port, <<16#FF>>),
    port_close(Port),
    ok.

%% @doc Load BPF bytecode into the VM.
-spec load(port(), binary()) -> ok | {error, binary() | timeout}.
load(Port, Bytecode) when is_binary(Bytecode) ->
    %% Patch ld_map_fd (BPF_PSEUDO_MAP_FD) → ld64_imm for uBPF compatibility.
    Patched = ebpf_insn:patch_for_ubpf(Bytecode),
    port_command(Port, <<16#01, Patched/binary>>),
    receive
        {Port, {data, <<16#00, _/binary>>}} -> ok;
        {Port, {data, <<16#01, Msg/binary>>}} -> {error, Msg}
    after 5000 ->
        {error, timeout}
    end.

%% @doc Execute the loaded BPF program with context data.
-spec run(port(), binary()) -> {ok, non_neg_integer()} | {error, binary() | timeout}.
run(Port, CtxData) when is_binary(CtxData) ->
    port_command(Port, <<16#02, CtxData/binary>>),
    receive
        {Port, {data, <<16#02, RetVal:64/little-unsigned>>}} -> {ok, RetVal};
        {Port, {data, <<16#01, Msg/binary>>}} -> {error, Msg}
    after 5000 ->
        {error, timeout}
    end.

%% @doc Execute the loaded BPF program with XDP context.
%% The C port constructs xdp_md with correct pointers to the packet data.
-spec run_xdp(port(), binary()) -> {ok, non_neg_integer()} | {error, binary() | timeout}.
run_xdp(Port, PacketBin) when is_binary(PacketBin) ->
    port_command(Port, <<16#03, PacketBin/binary>>),
    receive
        {Port, {data, <<16#02, RetVal:64/little-unsigned>>}} -> {ok, RetVal};
        {Port, {data, <<16#01, Msg/binary>>}} -> {error, Msg}
    after 5000 ->
        {error, timeout}
    end.

%% @doc Create a hash map in the uBPF port.
%% Returns the map fd (index) assigned by the port.
-spec create_map(port(), pos_integer(), pos_integer(), pos_integer()) ->
    {ok, non_neg_integer()} | {error, binary() | timeout}.
create_map(Port, KeySize, ValSize, MaxEntries) ->
    Cmd = <<16#04, KeySize:32/little, ValSize:32/little, MaxEntries:32/little>>,
    port_command(Port, Cmd),
    receive
        {Port, {data, <<16#00, Fd:32/little-unsigned>>}} -> {ok, Fd};
        {Port, {data, <<16#01, Msg/binary>>}} -> {error, Msg}
    after 5000 ->
        {error, timeout}
    end.

%% @doc Destroy all maps in the uBPF port.
-spec reset_maps(port()) -> ok | {error, binary() | timeout}.
reset_maps(Port) ->
    port_command(Port, <<16#05>>),
    receive
        {Port, {data, <<16#00, _/binary>>}} -> ok;
        {Port, {data, <<16#01, Msg/binary>>}} -> {error, Msg}
    after 5000 ->
        {error, timeout}
    end.

%% @doc Get a single value from a map by key.
-spec map_get(port(), non_neg_integer(), binary()) ->
    {ok, binary()} | {error, binary() | timeout}.
map_get(Port, Fd, KeyBin) when is_binary(KeyBin) ->
    Cmd = <<16#06, Fd:32/little, KeyBin/binary>>,
    port_command(Port, Cmd),
    receive
        {Port, {data, <<16#00, Value/binary>>}} -> {ok, Value};
        {Port, {data, <<16#01, Msg/binary>>}} -> {error, Msg}
    after 5000 ->
        {error, timeout}
    end.

%% @doc Dump all entries from a map.
%% Returns a list of {Key, Value} binary pairs.
-spec map_dump(port(), non_neg_integer()) ->
    {ok, {non_neg_integer(), binary()}} | {error, binary() | timeout}.
map_dump(Port, Fd) ->
    Cmd = <<16#07, Fd:32/little>>,
    port_command(Port, Cmd),
    receive
        {Port, {data, <<16#00, NumEntries:32/little, Rest/binary>>}} ->
            %% Need key_size and val_size to parse — get from map_info
            %% For now, we pass them via the caller or derive from the data
            {ok, {NumEntries, Rest}};
        {Port, {data, <<16#01, Msg/binary>>}} ->
            {error, Msg}
    after 5000 ->
        {error, timeout}
    end.
