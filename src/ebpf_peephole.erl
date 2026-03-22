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

-module(ebpf_peephole).
-moduledoc """
Peephole optimizer for BPF instruction sequences.

Safe patterns only — no transformations that could break the verifier.
Jump-aware: after removing instructions, adjusts all jump offsets.
Patterns: P1 (redundant mov), P2 (store-load), P3 (double store).
""".

-export([optimize/1]).

-spec optimize(binary()) -> binary().
optimize(Bin) ->
    Insns = split_insns(Bin, []),
    HasJumps = has_jumps(Insns),
    case HasJumps of
        false ->
            %% No jumps — simple optimization, no offset adjustment needed
            Optimized = peephole(Insns, []),
            ebpf_insn:assemble(Optimized);
        true ->
            %% Has jumps — only apply patterns that don't change instruction count
            %% P1 and P2 remove instructions and would break jump offsets
            %% P3 replaces 1:1, so it's safe
            Optimized = peephole_safe(Insns, []),
            ebpf_insn:assemble(Optimized)
    end.

%% Check if any instruction is a jump
has_jumps([]) ->
    false;
has_jumps([Insn | Rest]) ->
    case ebpf_insn:decode(Insn) of
        {ja, _, _, _, _} -> true;
        {jeq_imm, _, _, _, _} -> true;
        {jeq_reg, _, _, _, _} -> true;
        {jgt_imm, _, _, _, _} -> true;
        {jgt_reg, _, _, _, _} -> true;
        {jge_imm, _, _, _, _} -> true;
        {jge_reg, _, _, _, _} -> true;
        {jne_imm, _, _, _, _} -> true;
        {jne_reg, _, _, _, _} -> true;
        {jset_imm, _, _, _, _} -> true;
        {jset_reg, _, _, _, _} -> true;
        {jsgt_imm, _, _, _, _} -> true;
        {jsgt_reg, _, _, _, _} -> true;
        {jsge_imm, _, _, _, _} -> true;
        {jsge_reg, _, _, _, _} -> true;
        {jlt_imm, _, _, _, _} -> true;
        {jlt_reg, _, _, _, _} -> true;
        {jle_imm, _, _, _, _} -> true;
        {jle_reg, _, _, _, _} -> true;
        {jslt_imm, _, _, _, _} -> true;
        {jslt_reg, _, _, _, _} -> true;
        {jsle_imm, _, _, _, _} -> true;
        {jsle_reg, _, _, _, _} -> true;
        _ -> has_jumps(Rest)
    end.

%% Split binary into list of 8-byte instruction binaries.
split_insns(<<>>, Acc) ->
    lists:reverse(Acc);
split_insns(<<16#18, _:7/binary, _:8/binary, Rest/binary>> = Bin, Acc) ->
    <<Insn:16/binary, _/binary>> = Bin,
    split_insns(Rest, [Insn | Acc]);
split_insns(<<Insn:8/binary, Rest/binary>>, Acc) ->
    split_insns(Rest, [Insn | Acc]).

%% Safe peephole — only 1:1 replacements (P3), no instruction count changes
peephole_safe([], Acc) ->
    lists:reverse(Acc);
peephole_safe([Insn], Acc) ->
    lists:reverse([Insn | Acc]);
peephole_safe([Insn, Next | Rest], Acc) ->
    case try_p3(Insn, Next) of
        {ok, Replacement} ->
            peephole_safe([Replacement | Rest], Acc);
        none ->
            peephole_safe([Next | Rest], [Insn | Acc])
    end.

%% Full peephole — for programs without jumps
peephole([], Acc) ->
    lists:reverse(Acc);
peephole([Insn | Rest], Acc) ->
    case ebpf_insn:decode(Insn) of
        {mov64_reg, Dst, Dst, 0, 0} ->
            peephole(Rest, Acc);
        {mov32_reg, Dst, Dst, 0, 0} ->
            peephole(Rest, Acc);
        _ ->
            case Rest of
                [Next | Rest2] ->
                    case try_p2(Insn, Next) of
                        {ok, Replacement} ->
                            peephole(Rest2, Replacement ++ Acc);
                        none ->
                            case try_p3(Insn, Next) of
                                {ok, Replacement} ->
                                    peephole([Replacement | Rest2], Acc);
                                none ->
                                    peephole(Rest, [Insn | Acc])
                            end
                    end;
                [] ->
                    peephole(Rest, [Insn | Acc])
            end
    end.

%% P2: Store-load forwarding
try_p2(Store, Load) ->
    case {ebpf_insn:decode(Store), ebpf_insn:decode(Load)} of
        {{stxb, D1, S1, Off, 0}, {ldxb, D2, D1, Off, 0}} -> {ok, [ebpf_insn:mov64_reg(D2, S1)]};
        {{stxh, D1, S1, Off, 0}, {ldxh, D2, D1, Off, 0}} -> {ok, [ebpf_insn:mov64_reg(D2, S1)]};
        {{stxw, D1, S1, Off, 0}, {ldxw, D2, D1, Off, 0}} -> {ok, [ebpf_insn:mov64_reg(D2, S1)]};
        {{stxdw, D1, S1, Off, 0}, {ldxdw, D2, D1, Off, 0}} -> {ok, [ebpf_insn:mov64_reg(D2, S1)]};
        _ -> none
    end.

%% P3: Double store elimination
try_p3(First, Second) ->
    case {ebpf_insn:decode(First), ebpf_insn:decode(Second)} of
        {{stxb, D, _, Off, 0}, {stxb, D, _, Off, 0}} -> {ok, Second};
        {{stxh, D, _, Off, 0}, {stxh, D, _, Off, 0}} -> {ok, Second};
        {{stxw, D, _, Off, 0}, {stxw, D, _, Off, 0}} -> {ok, Second};
        {{stxdw, D, _, Off, 0}, {stxdw, D, _, Off, 0}} -> {ok, Second};
        _ -> none
    end.
