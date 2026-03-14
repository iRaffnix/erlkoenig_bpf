%% @doc Memory subsystem for the BPF VM.
%%
%% Supports region-based addressing:
%%   ctx:       0x10000000
%%   packet:    0x20000000
%%   stack:     0x30000000
%%   map_value: 0x40000000
-module(ebpf_vm_mem).

-include("ebpf_vm.hrl").

-export([read/4, write/5, resolve_region/2]).

%% @doc Read Size bytes at Addr from memory regions.
-spec read(#{atom() => binary()}, integer(), 1|2|4|8, binary()) ->
    {ok, integer()} | {error, oob}.
read(Memory, Addr, Size, Stack) ->
    case resolve_region(Addr, Stack) of
        {ok, Region, Offset} ->
            Bin = case Region of
                stack -> Stack;
                _ -> maps:get(Region, Memory, <<>>)
            end,
            BitSize = Size * 8,
            if
                Offset >= 0, Offset + Size =< byte_size(Bin) ->
                    <<_:Offset/binary, Val:BitSize/little-unsigned, _/binary>> = Bin,
                    {ok, Val};
                true ->
                    {error, oob}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Write Size bytes at Addr. Returns updated {Memory, Stack}.
-spec write(#{atom() => binary()}, integer(), 1|2|4|8, integer(), binary()) ->
    {ok, #{atom() => binary()}, binary()} | {error, oob}.
write(Memory, Addr, Size, Value, Stack) ->
    case resolve_region(Addr, Stack) of
        {ok, Region, Offset} ->
            Bin = case Region of
                stack -> Stack;
                _ -> maps:get(Region, Memory, <<>>)
            end,
            BitSize = Size * 8,
            if
                Offset >= 0, Offset + Size =< byte_size(Bin) ->
                    <<Pre:Offset/binary, _:BitSize/little, Post/binary>> = Bin,
                    NewBin = <<Pre/binary, Value:BitSize/little-unsigned, Post/binary>>,
                    case Region of
                        stack -> {ok, Memory, NewBin};
                        _ -> {ok, Memory#{Region => NewBin}, Stack}
                    end;
                true ->
                    {error, oob}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Resolve a virtual address to {Region, Offset}.
-spec resolve_region(integer(), binary()) ->
    {ok, atom(), non_neg_integer()} | {error, bad_addr}.
resolve_region(Addr, Stack) when Addr >= ?VM_STACK_BASE,
                                  Addr < ?VM_STACK_BASE + byte_size(Stack) ->
    {ok, stack, Addr - ?VM_STACK_BASE};
resolve_region(Addr, _Stack) when Addr >= ?VM_CTX_BASE,
                                   Addr < ?VM_CTX_BASE + 16#10000000 ->
    {ok, ctx, Addr - ?VM_CTX_BASE};
resolve_region(Addr, _Stack) when Addr >= ?VM_PACKET_BASE,
                                   Addr < ?VM_PACKET_BASE + 16#10000000 ->
    {ok, packet, Addr - ?VM_PACKET_BASE};
resolve_region(Addr, _Stack) when Addr >= ?VM_MAP_VALUE_BASE,
                                   Addr < ?VM_MAP_VALUE_BASE + 16#10000000 ->
    {ok, map_value, Addr - ?VM_MAP_VALUE_BASE};
resolve_region(_Addr, _Stack) ->
    {error, bad_addr}.
