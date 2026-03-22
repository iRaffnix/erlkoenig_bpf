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

-module(ebpf_regalloc).
-moduledoc """
Linear-scan register allocator for BPF IR.

Computes a mapping from virtual registers to physical BPF registers.
When more vregs are simultaneously live than available physical registers,
excess vregs are spilled to the BPF stack via R10 (frame pointer).
Returns {Assignment, SpillMap} where SpillMap maps vregs to stack offsets.
""".

-include("ebpf_ir.hrl").

-export([allocate/1]).

-record(interval, {
    vreg :: vreg(),
    start :: non_neg_integer(),
    stop :: non_neg_integer()
}).

-doc "Compute register assignment for all virtual registers. Returns {Assignment :: #{vreg() => preg()}, SpillMap :: #{vreg() => integer()}}.".
-spec allocate(#ir_program{}) -> {#{vreg() => preg()}, #{vreg() => integer()}}.
allocate(#ir_program{entry = Entry, blocks = Blocks}) ->
    Order = linearize(Entry, Blocks),
    {InsnMap, _TotalLen} = build_insn_map(Order, Blocks),
    Intervals0 = compute_intervals(InsnMap, Order, Blocks),
    Intervals1 = extend_for_loops(Intervals0, Order, Blocks, InsnMap),
    %% Add clobber intervals: helper calls destroy R1-R5.
    %% Synthetic intervals at each call_helper force vregs that are
    %% live across calls out of caller-saved registers.
    CallIdxs = find_call_helpers(InsnMap, Order, Blocks),
    {ClobberIvs, ClobberPC} = make_clobber_intervals(CallIdxs),
    Intervals = Intervals1 ++ ClobberIvs,
    {PreColors0, _} = pre_color(Intervals),
    PreColors = maps:merge(PreColors0, ClobberPC),
    %% Compute initial spill slot offset to avoid colliding with
    %% IR-generated stack slots (map keys/values stored on stack).
    MaxStackDepth = find_max_stack_depth(Order, Blocks),
    InitSlot = (MaxStackDepth + 7) div 8,
    %% First try: 8 regs (R1-R5, R7-R9)
    Sorted = lists:sort(
        fun(#interval{start = A}, #interval{start = B}) -> A =< B end,
        Intervals
    ),
    {Assign1, Spills1} = linear_scan(Sorted, PreColors, [7, 8, 9, 1, 2, 3, 4, 5], InitSlot),
    case maps:size(Spills1) of
        0 ->
            {Assign1, Spills1};
        _ ->
            %% Spills needed: re-run with R5 reserved as scratch
            linear_scan(Sorted, PreColors, [7, 8, 9, 1, 2, 3, 4], InitSlot)
    end.

%%% ===================================================================
%%% Block linearization
%%% ===================================================================

linearize(Entry, Blocks) ->
    linearize_bfs([Entry], #{}, Blocks, []).

linearize_bfs([], _Visited, _Blocks, Acc) ->
    lists:reverse(Acc);
linearize_bfs([Label | Rest], Visited, Blocks, Acc) ->
    case maps:is_key(Label, Visited) of
        true ->
            linearize_bfs(Rest, Visited, Blocks, Acc);
        false ->
            case maps:find(Label, Blocks) of
                {ok, Block} ->
                    Succs = term_succs(Block#ir_block.term),
                    linearize_bfs(
                        Rest ++ Succs,
                        Visited#{Label => true},
                        Blocks,
                        [Label | Acc]
                    );
                error ->
                    linearize_bfs(Rest, Visited#{Label => true}, Blocks, Acc)
            end
    end.

term_succs({br, L}) -> [L];
term_succs({cond_br, _, T, F}) -> [T, F];
term_succs({exit, _}) -> [];
term_succs(unreachable) -> [].

%%% ===================================================================
%%% Build instruction map
%%% ===================================================================

build_insn_map(Order, Blocks) ->
    lists:foldl(
        fun(Label, {Map, Idx}) ->
            Block = maps:get(Label, Blocks),
            Len = length(Block#ir_block.instrs) + 1,
            {Map#{Label => {Idx, Idx + Len - 1}}, Idx + Len}
        end,
        {#{}, 0},
        Order
    ).

%%% ===================================================================
%%% Compute live intervals
%%% ===================================================================

compute_intervals(InsnMap, Order, Blocks) ->
    Ranges = lists:foldl(
        fun(Label, Acc) ->
            {StartIdx, _} = maps:get(Label, InsnMap),
            Block = maps:get(Label, Blocks),
            Acc2 = lists:foldl(
                fun({Offset, Instr}, A) ->
                    Idx = StartIdx + Offset,
                    A2 = update_range_if_vreg(Instr#ir_instr.dst, Idx, A),
                    lists:foldl(
                        fun(Arg, A3) ->
                            update_range_if_vreg(Arg, Idx, A3)
                        end,
                        A2,
                        Instr#ir_instr.args
                    )
                end,
                Acc,
                lists:zip(
                    lists:seq(0, length(Block#ir_block.instrs) - 1),
                    Block#ir_block.instrs
                )
            ),
            TermIdx = StartIdx + length(Block#ir_block.instrs),
            update_term_ranges(Block#ir_block.term, TermIdx, Acc2)
        end,
        #{},
        Order
    ),
    [#interval{vreg = V, start = S, stop = E} || {V, {S, E}} <- maps:to_list(Ranges)].

update_range(VReg, Idx, Map) ->
    case maps:find(VReg, Map) of
        {ok, {Start, End}} -> Map#{VReg => {min(Start, Idx), max(End, Idx)}};
        error -> Map#{VReg => {Idx, Idx}}
    end.

update_range_if_vreg({v, _} = R, Idx, Map) -> update_range(R, Idx, Map);
update_range_if_vreg(v_ctx, Idx, Map) -> update_range(v_ctx, Idx, Map);
update_range_if_vreg(v_fp, Idx, Map) -> update_range(v_fp, Idx, Map);
update_range_if_vreg(v_ret, Idx, Map) -> update_range(v_ret, Idx, Map);
update_range_if_vreg(_, _, Map) -> Map.

update_term_ranges({cond_br, {cmp, _, L, R}, _, _}, Idx, Map) ->
    Map2 = update_range_if_vreg(L, Idx, Map),
    update_range_if_vreg(R, Idx, Map2);
update_term_ranges({cond_br, Reg, _, _}, Idx, Map) ->
    update_range_if_vreg(Reg, Idx, Map);
update_term_ranges({exit, Reg}, Idx, Map) ->
    update_range_if_vreg(Reg, Idx, Map);
update_term_ranges(_, _, Map) ->
    Map.

%%% ===================================================================
%%% Extend intervals for loops
%%% ===================================================================

extend_for_loops(Intervals, Order, Blocks, InsnMap) ->
    BackEdges = lists:foldl(
        fun(Label, Acc) ->
            Block = maps:get(Label, Blocks),
            {SrcStart, _} = maps:get(Label, InsnMap),
            SrcEnd = SrcStart + length(Block#ir_block.instrs),
            lists:foldl(
                fun(Target, A) ->
                    case maps:find(Target, InsnMap) of
                        {ok, {TgtStart, _}} when TgtStart =< SrcEnd -> [{TgtStart, SrcEnd} | A];
                        _ -> A
                    end
                end,
                Acc,
                term_succs(Block#ir_block.term)
            )
        end,
        [],
        Order
    ),
    lists:map(
        fun(#interval{} = I) ->
            lists:foldl(
                fun({LoopStart, LoopEnd}, Iv) ->
                    case Iv#interval.start =< LoopEnd andalso Iv#interval.stop >= LoopStart of
                        true ->
                            Iv#interval{
                                start = min(Iv#interval.start, LoopStart),
                                stop = max(Iv#interval.stop, LoopEnd)
                            };
                        false ->
                            Iv
                    end
                end,
                I,
                BackEdges
            )
        end,
        Intervals
    ).

%%% ===================================================================
%%% Pre-coloring
%%% ===================================================================

pre_color(Intervals) ->
    VRegs = [I#interval.vreg || I <- Intervals],
    PC0 = #{},
    PC1 =
        case lists:member(v_ret, VRegs) of
            true -> PC0#{v_ret => 0};
            false -> PC0
        end,
    PC2 =
        case lists:member(v_ctx, VRegs) of
            true -> PC1#{v_ctx => 6};
            false -> PC1
        end,
    PC3 =
        case lists:member(v_fp, VRegs) of
            true -> PC2#{v_fp => 10};
            false -> PC2
        end,
    {PC3, maps:values(PC3)}.

%%% ===================================================================
%%% Linear scan with proper spilling
%%% ===================================================================

linear_scan(SortedIntervals, PreColors, AvailRegs, InitSlot) ->
    %% Separate into: fixed pre-colors (v_ret, v_ctx, v_fp),
    %% clobber intervals (deferred activation), and normal intervals.
    {ToAlloc, PreAssign} = lists:partition(
        fun(#interval{vreg = V}) -> not maps:is_key(V, PreColors) end,
        SortedIntervals
    ),
    {ClobberPre, FixedPre} = lists:partition(
        fun
            (#interval{vreg = {clobber, _, _}}) -> true;
            (_) -> false
        end,
        PreAssign
    ),
    InitAssignment = PreColors,
    FixedActive = [{I, maps:get(I#interval.vreg, PreColors)} || I <- FixedPre],
    %% Remove fixed pre-colored regs from available pool
    FixedRegs = lists:usort([R || {_, R} <- FixedActive]),
    FreeRegs = [R || R <- AvailRegs, not lists:member(R, FixedRegs)],
    %% Sort pending clobbers by start time for deferred activation
    PendingClobbers = lists:sort(
        fun(#interval{start = A}, #interval{start = B}) -> A =< B end,
        ClobberPre
    ),
    Pending = [{I, maps:get(I#interval.vreg, PreColors)} || I <- PendingClobbers],
    scan(ToAlloc, InitAssignment, FixedActive, FreeRegs, #{}, InitSlot, Pending).

scan([], Assignment, _Active, _Free, Spills, _NextSlot, _Pending) ->
    {Assignment, Spills};
scan(
    [#interval{vreg = VReg} = I | Rest],
    Assignment,
    Active,
    Free,
    Spills,
    NextSlot,
    Pending
) ->
    {Active2, Free2} = expire(Active, I#interval.start, Free),
    %% Activate pending clobbers whose start <= current point.
    %% This removes their registers from Free and evicts conflicting
    %% non-fixed intervals (spilling them to stack).
    {Active3, Free3, Pending2, Spills2, NextSlot2} =
        activate_clobbers(
            Pending,
            I#interval.start,
            Active2,
            Free2,
            Assignment,
            Spills,
            NextSlot
        ),
    case Free3 of
        [Reg | Free4] ->
            scan(
                Rest,
                Assignment#{VReg => Reg},
                [{I, Reg} | Active3],
                Free4,
                Spills2,
                NextSlot2,
                Pending2
            );
        [] ->
            %% No free registers — spill the longest-lived active interval
            case find_longest(Active3) of
                {SpillI, SpillReg, Active4} when SpillI#interval.stop > I#interval.stop ->
                    %% Spill the longer-lived interval, give its register to current
                    SpillSlot = -(NextSlot2 + 1) * 8,
                    scan(
                        Rest,
                        Assignment#{VReg => SpillReg},
                        [{I, SpillReg} | Active4],
                        [],
                        Spills2#{SpillI#interval.vreg => SpillSlot},
                        NextSlot2 + 1,
                        Pending2
                    );
                _ ->
                    %% Spill current interval (shortest remaining)
                    SpillSlot = -(NextSlot2 + 1) * 8,
                    scan(
                        Rest,
                        Assignment,
                        Active3,
                        [],
                        Spills2#{VReg => SpillSlot},
                        NextSlot2 + 1,
                        Pending2
                    )
            end
    end.

%% Activate clobber intervals whose start time <= Point.
%% For each clobber: remove its register from Free; if a non-fixed
%% active interval holds that register, evict it to a spill slot.
activate_clobbers([], _Point, Active, Free, _Assign, Spills, NextSlot) ->
    {Active, Free, [], Spills, NextSlot};
activate_clobbers(
    [{#interval{start = S} = CI, CReg} | Rest],
    Point,
    Active,
    Free,
    Assign,
    Spills,
    NextSlot
) when S =< Point ->
    Free2 = Free -- [CReg],
    %% Check if a non-fixed active interval currently holds CReg
    {Active2, Spills2, NextSlot2} =
        evict_from_reg(Active, CReg, Spills, NextSlot),
    Active3 = [{CI, CReg} | Active2],
    activate_clobbers(Rest, Point, Active3, Free2, Assign, Spills2, NextSlot2);
activate_clobbers(Pending, _Point, Active, Free, _Assign, Spills, NextSlot) ->
    {Active, Free, Pending, Spills, NextSlot}.

%% If a non-fixed active interval holds the given register, spill it.
evict_from_reg(Active, Reg, Spills, NextSlot) ->
    case
        lists:partition(
            fun({#interval{vreg = V}, R}) ->
                R =:= Reg andalso not is_fixed_vreg(V)
            end,
            Active
        )
    of
        {[], _} ->
            {Active, Spills, NextSlot};
        {[{EvictI, _} | _], Remaining} ->
            SpillSlot = -(NextSlot + 1) * 8,
            {Remaining, Spills#{EvictI#interval.vreg => SpillSlot}, NextSlot + 1}
    end.

expire(Active, Point, Free) ->
    {Expired, Remaining} = lists:partition(
        fun({#interval{stop = Stop}, _}) -> Stop < Point end, Active
    ),
    %% Never return pre-colored registers (R0, R6, R10) to the free pool.
    %% They belong to fixed vregs (v_ret, v_ctx, v_fp) and must not be
    %% reassigned to normal virtual registers.
    ReturnedRegs = [
        R
     || {#interval{vreg = V}, R} <- Expired,
        not is_fixed_vreg(V)
    ],
    {Remaining, Free ++ ReturnedRegs}.

find_longest([]) ->
    none;
find_longest(Active) ->
    %% Find the non-pre-colored interval with the latest stop.
    %% Exclude pre-colored and clobber vregs — they must keep their register.
    Candidates = [
        {I, R}
     || {I, R} <- Active,
        not is_fixed_vreg(I#interval.vreg)
    ],
    case Candidates of
        [] ->
            none;
        _ ->
            {MaxI, MaxR} = lists:foldl(
                fun({I, R}, {BI, BR}) ->
                    case I#interval.stop > BI#interval.stop of
                        true -> {I, R};
                        false -> {BI, BR}
                    end
                end,
                hd(Candidates),
                tl(Candidates)
            ),
            Active2 = [
                {I, R}
             || {I, R} <- Active,
                I#interval.vreg =/= MaxI#interval.vreg
            ],
            {MaxI, MaxR, Active2}
    end.

is_fixed_vreg(v_ret) -> true;
is_fixed_vreg(v_ctx) -> true;
is_fixed_vreg(v_fp) -> true;
is_fixed_vreg({clobber, _, _}) -> true;
is_fixed_vreg(_) -> false.

%%% ===================================================================
%%% Call-helper clobber analysis
%%%
%%% BPF helper calls (call_helper) clobber registers R1-R5.
%%% We inject synthetic single-point intervals pre-colored to R1-R5
%%% at each call site. This prevents the linear scan from assigning
%%% any other live vreg to caller-saved registers across calls.
%%% ===================================================================

find_call_helpers(InsnMap, Order, Blocks) ->
    lists:foldl(
        fun(Label, Acc) ->
            {StartIdx, _} = maps:get(Label, InsnMap),
            Block = maps:get(Label, Blocks),
            Instrs = Block#ir_block.instrs,
            lists:foldl(
                fun({Offset, Instr}, A) ->
                    case Instr#ir_instr.op of
                        call_helper -> [StartIdx + Offset | A];
                        _ -> A
                    end
                end,
                Acc,
                lists:zip(lists:seq(0, length(Instrs) - 1), Instrs)
            )
        end,
        [],
        Order
    ).

%% Build clobber intervals as RANGES rather than single points.
%% For consecutive calls at indices [10, 20, 30], each clobber interval
%% extends from its call index to one less than the NEXT call index:
%%   Call 10: R1-R5 blocked [10, 19]
%%   Call 20: R1-R5 blocked [20, 29]
%%   Call 30: R1-R5 blocked [30, 30] (last call, no next)
%%
%% This prevents the linear scan from assigning variables to caller-saved
%% registers R1-R5 in the gap between consecutive helper calls. Variables
%% that live across multiple calls are forced into callee-saved R7-R9,
%% or spilled to stack with a stable spill slot.
make_clobber_intervals(CallIdxs) ->
    Sorted = lists:sort(CallIdxs),
    make_clobber_ranges(Sorted, {[], #{}}).

make_clobber_ranges([], Acc) ->
    Acc;
make_clobber_ranges([Idx], {IvAcc, PCAcc}) ->
    %% Last (or only) call: point interval
    lists:foldl(
        fun(R, {IA, PA}) ->
            VReg = {clobber, Idx, R},
            Iv = #interval{vreg = VReg, start = Idx, stop = Idx},
            {[Iv | IA], PA#{VReg => R}}
        end,
        {IvAcc, PCAcc},
        [1, 2, 3, 4, 5]
    );
make_clobber_ranges([Idx, Next | Rest], {IvAcc, PCAcc}) ->
    %% Range: block R1-R5 from this call until just before the next call
    Stop = Next - 1,
    {IvAcc2, PCAcc2} = lists:foldl(
        fun(R, {IA, PA}) ->
            VReg = {clobber, Idx, R},
            Iv = #interval{vreg = VReg, start = Idx, stop = Stop},
            {[Iv | IA], PA#{VReg => R}}
        end,
        {IvAcc, PCAcc},
        [1, 2, 3, 4, 5]
    ),
    make_clobber_ranges([Next | Rest], {IvAcc2, PCAcc2}).

%%% ===================================================================
%%% Stack depth analysis
%%%
%%% Find the deepest IR-generated stack offset so that regalloc spill
%%% slots don't collide with IR stack usage (map key/value storage).
%%% ===================================================================

find_max_stack_depth(Order, Blocks) ->
    lists:foldl(
        fun(Label, Depth) ->
            Block = maps:get(Label, Blocks),
            lists:foldl(
                fun(#ir_instr{args = Args}, D) ->
                    lists:foldl(
                        fun
                            ({stack_off, Off}, D2) -> max(D2, -Off);
                            (_, D2) -> D2
                        end,
                        D,
                        Args
                    )
                end,
                Depth,
                Block#ir_block.instrs
            )
        end,
        0,
        Order
    ).
