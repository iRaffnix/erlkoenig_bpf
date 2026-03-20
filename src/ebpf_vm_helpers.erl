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

-module(ebpf_vm_helpers).
-moduledoc "BPF helper call simulation for the VM.".

-include("ebpf_vm.hrl").

-export([call/3]).

-doc "Dispatch helper call. Returns {ok, ReturnValue, NewState} | {error, Reason}.".
-spec call(non_neg_integer(), #vm_state{}, #{}) -> {ok, integer(), #vm_state{}} | {error, term()}.

%% Helper 1: bpf_map_lookup_elem(map_fd, key_ptr) → pointer | NULL(0)
call(
    1,
    #vm_state{
        regs = Regs,
        maps = Maps,
        map_meta = MapMeta,
        memory = Mem,
        stack = Stack
    } = St,
    _Opts
) ->
    MapFd = maps:get(1, Regs, 0),
    KeyPtr = maps:get(2, Regs, 0),
    case maps:find(MapFd, Maps) of
        {ok, Tab} ->
            Meta = maps:get(MapFd, MapMeta),
            KS = Meta#map_meta.key_size,
            case ebpf_vm_mem:read(Mem, KeyPtr, KS, Stack) of
                {ok, _} ->
                    %% Read raw key bytes
                    KeyBin = read_bytes(Mem, KeyPtr, KS, Stack),
                    case ebpf_vm_maps:lookup(Tab, KeyBin, Meta) of
                        {ok, ValBin} ->
                            %% Store value in map_value region, return pointer
                            ValAddr = ?VM_MAP_VALUE_BASE,
                            NewMem = Mem#{map_value => ValBin},
                            {ok, ValAddr, St#vm_state{memory = NewMem}};
                        none ->
                            %% NULL
                            {ok, 0, St}
                    end;
                {error, oob} ->
                    {error, {oob_key_read, KeyPtr}}
            end;
        error ->
            {error, {bad_map_fd, MapFd}}
    end;
%% Helper 2: bpf_map_update_elem(map_fd, key_ptr, val_ptr, flags) → 0 | -errno
call(
    2,
    #vm_state{
        regs = Regs,
        maps = Maps,
        map_meta = MapMeta,
        memory = Mem,
        stack = Stack
    } = St,
    _Opts
) ->
    MapFd = maps:get(1, Regs, 0),
    KeyPtr = maps:get(2, Regs, 0),
    ValPtr = maps:get(3, Regs, 0),
    case maps:find(MapFd, Maps) of
        {ok, Tab} ->
            Meta = maps:get(MapFd, MapMeta),
            KeyBin = read_bytes(Mem, KeyPtr, Meta#map_meta.key_size, Stack),
            ValBin = read_bytes(Mem, ValPtr, Meta#map_meta.val_size, Stack),
            case ebpf_vm_maps:update(Tab, KeyBin, ValBin, Meta) of
                ok -> {ok, 0, St};
                {error, full} -> {ok, -1, St}
            end;
        error ->
            {error, {bad_map_fd, MapFd}}
    end;
%% Helper 3: bpf_map_delete_elem(map_fd, key_ptr) → 0
call(
    3,
    #vm_state{
        regs = Regs,
        maps = Maps,
        map_meta = MapMeta,
        memory = Mem,
        stack = Stack
    } = St,
    _Opts
) ->
    MapFd = maps:get(1, Regs, 0),
    KeyPtr = maps:get(2, Regs, 0),
    case maps:find(MapFd, Maps) of
        {ok, Tab} ->
            Meta = maps:get(MapFd, MapMeta),
            KeyBin = read_bytes(Mem, KeyPtr, Meta#map_meta.key_size, Stack),
            ebpf_vm_maps:delete(Tab, KeyBin, Meta),
            {ok, 0, St};
        error ->
            {error, {bad_map_fd, MapFd}}
    end;
%% Helper 5: bpf_ktime_get_ns() → u64  (standard Linux helper ID)
call(5, St, _Opts) ->
    Ns = erlang:monotonic_time(nanosecond),
    {ok, Ns band 16#FFFFFFFFFFFFFFFF, St};
%% Helper 6: bpf_trace_printk() → 0  (standard Linux helper ID)
call(6, St, _Opts) ->
    {ok, 0, St};
%% Helper 14: bpf_get_smp_processor_id() → 0
call(14, St, _Opts) ->
    {ok, 0, St};
%% Helper 195: bpf_ringbuf_output(ringbuf, data, size, flags) → 0
call(195, St, _Opts) ->
    %% No-op in simulation, just succeed
    {ok, 0, St};
%% Unknown helper
call(Id, _St, _Opts) ->
    {error, {unknown_helper, Id}}.

%% Read Size raw bytes from memory at Addr.
read_bytes(Memory, Addr, Size, Stack) ->
    case ebpf_vm_mem:resolve_region(Addr, Stack) of
        {ok, Region, Offset} ->
            Bin =
                case Region of
                    stack -> Stack;
                    _ -> maps:get(Region, Memory, <<>>)
                end,
            <<_:Offset/binary, Bytes:Size/binary, _/binary>> = Bin,
            Bytes;
        _ ->
            <<0:(Size * 8)>>
    end.
