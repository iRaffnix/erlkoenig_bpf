%% @doc IR → BPF bytecode generation.
%%
%% Two-pass approach with register assignment from regalloc.
%% Supports spilled registers via R10 stack slots with R5 as scratch.
-module(ebpf_codegen).

-include("ebpf_ir.hrl").

-export([codegen/1, codegen/2, codegen/3]).

-define(JA_PH(Target), {ja_ph, Target}).
-define(JEQ_PH(Reg, TrueL, FalseL), {jeq_ph, Reg, TrueL, FalseL}).
-define(JCMP_PH(CmpOp, L, R, TrueL, FalseL), {jcmp_ph, CmpOp, L, R, TrueL, FalseL}).
-define(SCRATCH, 5).  %% R5 used as scratch for spill/reload

%% @doc Generate BPF bytecode with default register mapping, no spills.
codegen(Prog) ->
    codegen(Prog, #{}, #{}).

%% @doc Generate BPF bytecode with register map, no spills.
codegen(Prog, RegMap) ->
    codegen(Prog, RegMap, #{}).

%% @doc Generate BPF bytecode with register map and spill map.
codegen(#ir_program{entry = Entry, blocks = Blocks}, RegMap, SpillMap) ->
    Ctx = #{regmap => RegMap, spillmap => SpillMap},
    Order = linearize(Entry, Blocks),
    %% Emit mov r6, r1 prolog: save ctx pointer to callee-saved register
    Prolog = [ebpf_insn:mov64_reg(6, 1)],
    PrologLen = length(Prolog),
    {RevInsns, BlockStarts, _} = lists:foldl(fun(Label, {Acc, Starts, Idx}) ->
        Block = maps:get(Label, Blocks),
        BodyInsns = emit_body(Block#ir_block.instrs, Ctx),
        TermInsns = emit_term_ph(Block#ir_block.term, Ctx),
        All = BodyInsns ++ TermInsns,
        Len = insn_slot_count(All),
        {lists:reverse(All) ++ Acc, Starts#{Label => Idx}, Idx + Len}
    end, {[], #{}, PrologLen}, Order),
    AllInsns = Prolog ++ lists:reverse(RevInsns),
    Patched = patch(AllInsns, 0, BlockStarts, Ctx),
    ebpf_insn:assemble(Patched).

%%% ===================================================================
%%% Block linearization
%%% ===================================================================

linearize(Entry, Blocks) ->
    linearize_bfs([Entry], #{}, Blocks, []).

linearize_bfs([], _Visited, _Blocks, Acc) ->
    lists:reverse(Acc);
linearize_bfs([Label | Rest], Visited, Blocks, Acc) ->
    case maps:is_key(Label, Visited) of
        true -> linearize_bfs(Rest, Visited, Blocks, Acc);
        false ->
            case maps:find(Label, Blocks) of
                {ok, Block} ->
                    Succs = terminator_succs(Block#ir_block.term),
                    linearize_bfs(Rest ++ Succs, Visited#{Label => true},
                                  Blocks, [Label | Acc]);
                error ->
                    linearize_bfs(Rest, Visited#{Label => true}, Blocks, Acc)
            end
    end.

terminator_succs({br, L}) -> [L];
terminator_succs({cond_br, _, T, F}) -> [T, F];
terminator_succs({exit, _}) -> [];
terminator_succs(unreachable) -> [].

%%% ===================================================================
%%% Body emission with spill handling
%%% ===================================================================

emit_body(Instrs, Ctx) ->
    lists:flatmap(fun(I) -> emit_instr_spill(I, Ctx) end, Instrs).

%% Wrap emit_instr with spill reload/store.
%% Handles the case where both dst and args are spilled (R5 scratch conflict).
emit_instr_spill(#ir_instr{op = call_helper, dst = Dst, args = [{fn, Name} | ArgRegs]} = _I, Ctx) ->
    SM = maps:get(spillmap, Ctx),
    DstSpilled = is_vreg(Dst) andalso maps:is_key(Dst, SM),
    HelperId = helper_id(Name),
    %% For call_helper, load spilled args directly into target registers
    %% (R1-R5) instead of going through SCRATCH. This avoids the
    %% single-scratch-register bottleneck when multiple args are spilled.
    Numbered = lists:zip(lists:seq(1, length(ArgRegs)), ArgRegs),
    {SpilledPairs, NonSpilledPairs} = lists:partition(
        fun({_, Arg}) -> is_vreg(Arg) andalso maps:is_key(Arg, SM) end,
        Numbered),
    %% Non-spilled args: use parallel_move (handles register-to-register)
    NonSpilledMoves = [{R, case is_integer(A) of true -> {imm, A}; false -> phys(A, Ctx) end}
                       || {R, A} <- NonSpilledPairs],
    FilteredMoves = [{D, S} || {D, S} <- NonSpilledMoves, not is_identity(D, S)],
    ParallelMovs = parallel_move(FilteredMoves),
    %% Spilled args: load from stack directly into target register.
    %% Must come AFTER parallel_move to avoid clobbering sources.
    SpilledLoads = [ebpf_insn:ldxdw(R, 10, maps:get(A, SM))
                    || {R, A} <- SpilledPairs],
    %% Call instruction
    CallInsn = ebpf_insn:call(HelperId),
    %% Move result from R0 into destination
    PDst = case DstSpilled of true -> ?SCRATCH; false -> phys(Dst, Ctx) end,
    ResultMov = case PDst of 0 -> []; _ -> [ebpf_insn:mov64_reg(PDst, 0)] end,
    Stores = case DstSpilled of
        true -> [ebpf_insn:stxdw(10, maps:get(Dst, SM), ?SCRATCH)];
        false -> []
    end,
    ParallelMovs ++ SpilledLoads ++ [CallInsn] ++ ResultMov ++ Stores;
emit_instr_spill(#ir_instr{dst = Dst, args = Args} = I, Ctx) ->
    SM = maps:get(spillmap, Ctx),
    DstSpilled = is_vreg(Dst) andalso maps:is_key(Dst, SM),
    %% Count spilled args
    SpilledArgs = [{Idx, A} || {Idx, A} <- lists:zip(lists:seq(1, length(Args)), Args),
                               is_vreg(A), maps:is_key(A, SM)],
    NumSpilled = length(SpilledArgs),
    %% Reload first spilled arg (for standard path)
    Reloads = lists:flatmap(fun({_, SA}) ->
        Off = maps:get(SA, SM),
        [ebpf_insn:ldxdw(?SCRATCH, 10, Off)]
    end, lists:sublist(SpilledArgs, 1)),
    Result = case {DstSpilled, NumSpilled, I#ir_instr.op, Args} of
        %% Dst spilled + 2nd arg spilled: R5 conflict!
        %% mov R5, phys(A1) would clobber the reloaded 2nd arg in R5.
        {true, 1, Op, [A1, A2]} when Op =/= mov ->
            case is_vreg(A2) andalso maps:is_key(A2, SM) of
                true ->
                    %% 2nd arg is the spilled one → R5 conflict
                    A2Off = maps:get(A2, SM),
                    PA1 = phys(A1, Ctx),
                    [ebpf_insn:ldxdw(?SCRATCH, 10, A2Off) |
                     emit_spilled_dst_alu(Op, PA1, ?SCRATCH)];
                false ->
                    %% 1st arg is spilled → mov R5,R5 is no-op, safe
                    Reloads ++ emit_instr(I, Ctx)
            end;
        %% Both args spilled + dst spilled: use R0 as second scratch
        {true, N, Op, [A1, A2]} when N >= 2, Op =/= mov ->
            A1Off = maps:get(A1, SM),
            A2Off = maps:get(A2, SM),
            [ebpf_insn:ldxdw(?SCRATCH, 10, A1Off),
             ebpf_insn:mov64_reg(0, ?SCRATCH),
             ebpf_insn:ldxdw(?SCRATCH, 10, A2Off)
             | emit_alu_op(Op, 0, ?SCRATCH)]
            ++ [ebpf_insn:mov64_reg(?SCRATCH, 0)];
        %% Both args spilled, dst NOT spilled
        {false, N, Op, [A1, A2]} when N >= 2, Op =/= mov ->
            Off1 = maps:get(A1, SM),
            Off2 = maps:get(A2, SM),
            PDst = phys(Dst, Ctx),
            [ebpf_insn:ldxdw(?SCRATCH, 10, Off1),
             ebpf_insn:mov64_reg(PDst, ?SCRATCH),
             ebpf_insn:ldxdw(?SCRATCH, 10, Off2)
             | emit_alu_op(Op, PDst, ?SCRATCH)];
        %% Standard path: no R5 conflict
        _ ->
            Reloads ++ emit_instr(I, Ctx)
    end,
    %% Store spilled dst after the instruction
    Stores = case DstSpilled of
        true ->
            DstOff = maps:get(Dst, SM),
            [ebpf_insn:stxdw(10, DstOff, ?SCRATCH)];
        false -> []
    end,
    Result ++ Stores.

%% Emit ALU for spilled-dst case: compute A1_phys op R5, result in R5.
%% R5 holds the spilled 2nd arg. For commutative ops, R5 op A1 = A1 op R5.
%% For non-commutative ops (sub/div/mod), use R0 as temp.
emit_spilled_dst_alu(Op, PA1, Scratch) ->
    case is_commutative_alu(Op) of
        true ->
            emit_alu_op(Op, Scratch, PA1);
        false ->
            %% Need PA1 op Scratch, result in Scratch
            [ebpf_insn:mov64_reg(0, PA1) |
             emit_alu_op(Op, 0, Scratch)]
            ++ [ebpf_insn:mov64_reg(Scratch, 0)]
    end.

is_commutative_alu(add) -> true;
is_commutative_alu(mul) -> true;
is_commutative_alu(and_op) -> true;
is_commutative_alu(or_op) -> true;
is_commutative_alu(xor_op) -> true;
is_commutative_alu(_) -> false.

emit_instr(#ir_instr{op = mov, dst = Dst, args = [Src]}, Ctx) when is_integer(Src) ->
    [ebpf_insn:mov64_imm(phys(Dst, Ctx), Src)];
emit_instr(#ir_instr{op = mov, dst = Dst, args = [Src]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(Src, Ctx))];

emit_instr(#ir_instr{op = mov32, dst = Dst, args = [Src]}, Ctx) when is_integer(Src) ->
    [ebpf_insn:mov32_imm(phys(Dst, Ctx), Src)];

emit_instr(#ir_instr{op = add, dst = Dst, args = [Src, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(Src, Ctx)),
     ebpf_insn:add64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = add, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:add64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = sub, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:sub64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = sub, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:sub64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = mul, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:mul64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = mul, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:mul64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = 'div', dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:div64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = 'div', dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:div64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = mod, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:mod64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = mod, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:mod64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = and_op, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:and64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = and_op, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:and64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = or_op, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:or64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = or_op, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:or64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = xor_op, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:xor64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = xor_op, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:xor64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = lsh, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:lsh64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = lsh, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:lsh64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = rsh, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:rsh64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = rsh, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:rsh64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = arsh, dst = Dst, args = [A, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:arsh64_imm(phys(Dst, Ctx), Imm)];
emit_instr(#ir_instr{op = arsh, dst = Dst, args = [A, B]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(A, Ctx)),
     ebpf_insn:arsh64_reg(phys(Dst, Ctx), phys(B, Ctx))];

emit_instr(#ir_instr{op = neg, dst = Dst, args = [Src]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(Src, Ctx)),
     ebpf_insn:neg64(phys(Dst, Ctx))];

emit_instr(#ir_instr{op = not_op, dst = Dst, args = [Src]}, Ctx) ->
    [ebpf_insn:mov64_reg(phys(Dst, Ctx), phys(Src, Ctx)),
     ebpf_insn:xor64_imm(phys(Dst, Ctx), 1)];

emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {ctx_field, Offset, 4}]}, Ctx) ->
    %% 32-bit context field load: ldxw dst, [R6+offset]
    [ebpf_insn:ldxw(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {ctx_field, Offset, 8}]}, Ctx) ->
    %% 64-bit context field load: ldxdw dst, [R6+offset]
    [ebpf_insn:ldxdw(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {struct_field, _Name, Offset, 1}]}, Ctx) ->
    [ebpf_insn:ldxb(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {struct_field, _Name, Offset, 2}]}, Ctx) ->
    [ebpf_insn:ldxh(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {struct_field, _Name, Offset, 4}]}, Ctx) ->
    [ebpf_insn:ldxw(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {struct_field, _Name, Offset, 8}]}, Ctx) ->
    [ebpf_insn:ldxdw(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {pkt_read, Offset, 1}]}, Ctx) ->
    [ebpf_insn:ldxb(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {pkt_read, Offset, 2}]}, Ctx) ->
    [ebpf_insn:ldxh(phys(Dst, Ctx), phys(Base, Ctx), Offset)];
emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, {pkt_read, Offset, 4}]}, Ctx) ->
    [ebpf_insn:ldxw(phys(Dst, Ctx), phys(Base, Ctx), Offset)];

emit_instr(#ir_instr{op = load, dst = Dst, args = [Base, _Field]}, Ctx) ->
    [ebpf_insn:ldxdw(phys(Dst, Ctx), phys(Base, Ctx), 0)];

emit_instr(#ir_instr{op = store, dst = none, args = [Base, {struct_field, _Name, Offset, 1}, Val]}, Ctx) ->
    [ebpf_insn:stxb(phys(Base, Ctx), Offset, phys(Val, Ctx))];
emit_instr(#ir_instr{op = store, dst = none, args = [Base, {struct_field, _Name, Offset, 2}, Val]}, Ctx) ->
    [ebpf_insn:stxh(phys(Base, Ctx), Offset, phys(Val, Ctx))];
emit_instr(#ir_instr{op = store, dst = none, args = [Base, {struct_field, _Name, Offset, 4}, Val]}, Ctx) ->
    [ebpf_insn:stxw(phys(Base, Ctx), Offset, phys(Val, Ctx))];
emit_instr(#ir_instr{op = store, dst = none, args = [Base, {struct_field, _Name, Offset, 8}, Val]}, Ctx) ->
    [ebpf_insn:stxdw(phys(Base, Ctx), Offset, phys(Val, Ctx))];
emit_instr(#ir_instr{op = store, dst = none, args = [Base, {stack_off, Off}, Val],
                     type = {scalar, u32}}, Ctx) ->
    [ebpf_insn:stxw(phys(Base, Ctx), Off, phys(Val, Ctx))];
emit_instr(#ir_instr{op = store, dst = none, args = [Base, {stack_off, Off}, Val]}, Ctx) ->
    [ebpf_insn:stxdw(phys(Base, Ctx), Off, phys(Val, Ctx))];
emit_instr(#ir_instr{op = store, dst = none, args = [Base, _Off, Val]}, Ctx) ->
    [ebpf_insn:stxdw(phys(Base, Ctx), 0, phys(Val, Ctx))];

emit_instr(#ir_instr{op = store_imm, dst = none, args = [Base, _Off, Imm]}, Ctx) when is_integer(Imm) ->
    [ebpf_insn:stdw(phys(Base, Ctx), 0, Imm)];

emit_instr(#ir_instr{op = call_helper, dst = Dst, args = [{fn, Name} | ArgRegs]}, Ctx) ->
    HelperId = helper_id(Name),
    %% Move arguments into R1-R5 (BPF calling convention)
    ArgMovs = emit_call_args(ArgRegs, 1, Ctx),
    %% Emit the call instruction
    CallInsn = ebpf_insn:call(HelperId),
    %% Move result from R0 into destination register
    PDst = phys(Dst, Ctx),
    ResultMov = case PDst of
        0 -> [];  %% Already in R0
        _ -> [ebpf_insn:mov64_reg(PDst, 0)]
    end,
    ArgMovs ++ [CallInsn] ++ ResultMov;

emit_instr(#ir_instr{op = ld_map_fd, dst = Dst, args = [Fd]}, Ctx) ->
    [ebpf_insn:ld_map_fd(phys(Dst, Ctx), Fd)];

emit_instr(#ir_instr{op = endian_be, dst = Dst, args = [16]}, Ctx) ->
    [ebpf_insn:be16(phys(Dst, Ctx))];
emit_instr(#ir_instr{op = endian_be, dst = Dst, args = [32]}, Ctx) ->
    [ebpf_insn:be32(phys(Dst, Ctx))];
emit_instr(#ir_instr{op = endian_be, dst = Dst, args = [64]}, Ctx) ->
    [ebpf_insn:be64(phys(Dst, Ctx))];

emit_instr(#ir_instr{op = nop}, _Ctx) -> [];
emit_instr(#ir_instr{op = phi}, _Ctx) -> [];
emit_instr(#ir_instr{op = bounds_check}, _Ctx) -> [];
emit_instr(#ir_instr{op = null_check}, _Ctx) -> [];
emit_instr(_, _Ctx) -> [].

%%% ===================================================================
%%% Terminator placeholders
%%% ===================================================================

emit_term_ph({exit, Reg}, Ctx) ->
    SM = maps:get(spillmap, Ctx),
    case is_vreg(Reg) andalso maps:is_key(Reg, SM) of
        true ->
            Off = maps:get(Reg, SM),
            [ebpf_insn:ldxdw(0, 10, Off), ebpf_insn:exit_insn()];
        false ->
            case phys(Reg, Ctx) of
                0 -> [ebpf_insn:exit_insn()];
                R -> [ebpf_insn:mov64_reg(0, R), ebpf_insn:exit_insn()]
            end
    end;
emit_term_ph({br, Target}, _Ctx) ->
    [?JA_PH(Target)];
emit_term_ph({cond_br, {cmp, CmpOp, L, R}, TrueL, FalseL}, Ctx) ->
    %% Emit spill reloads for L and/or R before the jump placeholder.
    %% Spilled operands are loaded into scratch registers so the
    %% placeholder can reference them by physical register.
    SM = maps:get(spillmap, Ctx),
    LSpilled = is_vreg(L) andalso maps:is_key(L, SM),
    RSpilled = is_vreg(R) andalso maps:is_key(R, SM),
    {Reloads, L2, R2} = case {LSpilled, RSpilled} of
        {false, false} ->
            {[], L, R};
        {true, false} ->
            %% L spilled → reload into SCRATCH (R5)
            Off = maps:get(L, SM),
            {[ebpf_insn:ldxdw(?SCRATCH, 10, Off)], {phys_override, ?SCRATCH}, R};
        {false, true} ->
            %% R spilled → reload into SCRATCH (R5)
            Off = maps:get(R, SM),
            {[ebpf_insn:ldxdw(?SCRATCH, 10, Off)], L, {phys_override, ?SCRATCH}};
        {true, true} ->
            %% Both spilled → L into R0, R into SCRATCH (R5)
            LO = maps:get(L, SM),
            RO = maps:get(R, SM),
            {[ebpf_insn:ldxdw(0, 10, LO),
              ebpf_insn:ldxdw(?SCRATCH, 10, RO)],
             {phys_override, 0}, {phys_override, ?SCRATCH}}
    end,
    Reloads ++ [?JCMP_PH(CmpOp, L2, R2, TrueL, FalseL), ?JA_PH(TrueL)];
emit_term_ph({cond_br, Reg, TrueL, FalseL}, Ctx) ->
    %% Reload spilled boolean register before conditional jump
    SM = maps:get(spillmap, Ctx),
    case is_vreg(Reg) andalso maps:is_key(Reg, SM) of
        true ->
            Off = maps:get(Reg, SM),
            Reloads = [ebpf_insn:ldxdw(?SCRATCH, 10, Off)],
            Reloads ++ [?JEQ_PH({phys_override, ?SCRATCH}, TrueL, FalseL), ?JA_PH(TrueL)];
        false ->
            [?JEQ_PH(Reg, TrueL, FalseL), ?JA_PH(TrueL)]
    end;
emit_term_ph(unreachable, _Ctx) ->
    [ebpf_insn:mov64_imm(0, 0), ebpf_insn:exit_insn()].

%%% ===================================================================
%%% Jump patching
%%% ===================================================================

patch([], _Idx, _Starts, _Ctx) -> [];
patch([?JA_PH(Target) | Rest], Idx, Starts, Ctx) ->
    TargetIdx = maps:get(Target, Starts),
    Off = TargetIdx - (Idx + 1),
    [ebpf_insn:ja(Off) | patch(Rest, Idx + 1, Starts, Ctx)];
patch([?JEQ_PH(Reg, _TrueL, FalseL) | Rest], Idx, Starts, Ctx) ->
    FalseIdx = maps:get(FalseL, Starts),
    FalseOff = FalseIdx - (Idx + 1),
    [ebpf_insn:jeq_imm(resolve_reg(Reg, Ctx), 0, FalseOff) | patch(Rest, Idx + 1, Starts, Ctx)];
patch([?JCMP_PH(CmpOp, L, R, _TrueL, FalseL) | Rest], Idx, Starts, Ctx) ->
    FalseIdx = maps:get(FalseL, Starts),
    FalseOff = FalseIdx - (Idx + 1),
    %% Emit negated condition: jump to FalseL when comparison fails
    NegOp = negate_cmp(CmpOp),
    Insn = emit_jmp(NegOp, resolve_reg(L, Ctx), resolve_reg(R, Ctx), FalseOff),
    [Insn | patch(Rest, Idx + 1, Starts, Ctx)];
patch([Insn | Rest], Idx, Starts, Ctx) ->
    [Insn | patch(Rest, Idx + insn_slots(Insn), Starts, Ctx)].

%%% ===================================================================
%%% Instruction slot counting (ld_map_fd = 16 bytes = 2 BPF slots)
%%% ===================================================================

%% Count total BPF instruction slots for a list of instructions.
insn_slot_count(Insns) ->
    lists:sum([insn_slots(I) || I <- Insns]).

%% A 16-byte binary (ld_imm64/ld_map_fd) occupies 2 BPF instruction slots.
insn_slots(B) when is_binary(B), byte_size(B) =:= 16 -> 2;
insn_slots(_) -> 1.

%%% ===================================================================
%%% Comparison jump helpers
%%% ===================================================================

%% Negate a comparison: used to jump to FalseL when condition fails.
negate_cmp(eq) -> ne;
negate_cmp(ne) -> eq;
negate_cmp(gt) -> le;
negate_cmp(ge) -> lt;
negate_cmp(lt) -> ge;
negate_cmp(le) -> gt.

%% Emit a BPF conditional jump (register-register, 64-bit unsigned).
emit_jmp(eq, Dst, Src, Off) -> ebpf_insn:jeq_reg(Dst, Src, Off);
emit_jmp(ne, Dst, Src, Off) -> ebpf_insn:jne_reg(Dst, Src, Off);
emit_jmp(gt, Dst, Src, Off) -> ebpf_insn:jgt_reg(Dst, Src, Off);
emit_jmp(ge, Dst, Src, Off) -> ebpf_insn:jge_reg(Dst, Src, Off);
emit_jmp(lt, Dst, Src, Off) -> ebpf_insn:jlt_reg(Dst, Src, Off);
emit_jmp(le, Dst, Src, Off) -> ebpf_insn:jle_reg(Dst, Src, Off).

%%% ===================================================================
%%% Register mapping
%%% ===================================================================

%% resolve_reg: used by patch to resolve operands that may be {phys_override, N}
%% (already loaded into a physical register by emit_term_ph spill handling).
resolve_reg({phys_override, N}, _Ctx) -> N;
resolve_reg(Reg, Ctx) -> phys(Reg, Ctx).

phys(Reg, #{spillmap := SM} = Ctx) ->
    case is_vreg(Reg) andalso maps:is_key(Reg, SM) of
        true -> ?SCRATCH;  %% Spilled vreg uses scratch register
        false -> phys_lookup(Reg, Ctx)
    end.

phys_lookup(v_ret, #{regmap := RM}) -> maps:get(v_ret, RM, 0);
phys_lookup(v_ctx, #{regmap := RM}) -> maps:get(v_ctx, RM, 1);
phys_lookup(v_fp, #{regmap := RM})  -> maps:get(v_fp, RM, 10);
phys_lookup({v, N} = VReg, #{regmap := RM}) ->
    case maps:find(VReg, RM) of
        {ok, R} -> R;
        error -> (N rem 9) + 1
    end;
phys_lookup(N, _Ctx) when is_integer(N) -> N.

is_vreg({v, _}) -> true;
is_vreg(v_ctx) -> true;
is_vreg(v_fp) -> true;
is_vreg(v_ret) -> true;
is_vreg(_) -> false.

%%% ===================================================================
%%% ALU op emission (for two-spilled-arg case)
%%% ===================================================================

%%% ===================================================================
%%% Helper call support
%%% ===================================================================

%% Emit mov instructions to load arguments into R1-R5.
%% Uses a parallel move algorithm to avoid clobbering source registers.
%% R0 is used as scratch since the call instruction overwrites it anyway.
emit_call_args(ArgRegs, StartReg, Ctx) ->
    Pairs = emit_call_args_pairs(ArgRegs, StartReg, Ctx),
    %% Remove identity moves (src already in correct dst)
    Moves = [{D, S} || {D, S} <- Pairs, not is_identity(D, S)],
    parallel_move(Moves).

%% Parallel move: emit moves such that no source is clobbered before use.
%% Strategy: repeatedly emit moves whose DESTINATION is NOT used as a SOURCE
%% by any other remaining move. When stuck (cycle), break using R0 as temp.
parallel_move(Moves) ->
    parallel_move(Moves, []).

parallel_move([], Acc) ->
    lists:reverse(Acc);
parallel_move(Moves, Acc) ->
    %% Collect all sources that other moves still need
    AllSrcs = [S || {_, S} <- Moves, not is_imm(S)],
    %% A move is ready if its destination is NOT a source of any remaining move
    %% (i.e., writing to that destination won't clobber a value we still need)
    {Ready, Blocked} = lists:partition(fun({D, _S}) ->
        not lists:member(D, AllSrcs)
    end, Moves),
    case Ready of
        [{D, S} | Rest] ->
            %% Emit one ready move and recurse
            parallel_move(Rest ++ Blocked, [emit_one_arg(D, S) | Acc]);
        [] ->
            %% All moves are blocked (cycle). Break it using R0 as temp.
            [{D, S} | Rest] = Moves,
            %% Save S to R0, update all references to S to use R0
            Rest2 = [{Dd, case Ss of S -> 0; _ -> Ss end} || {Dd, Ss} <- Rest],
            parallel_move(Rest2 ++ [{D, 0}],
                          [ebpf_insn:mov64_reg(0, S) | Acc])
    end.

is_imm({imm, _}) -> true;
is_imm(_) -> false.

is_identity(D, D) -> true;
is_identity(_, _) -> false.

emit_call_args_pairs([], _, _Ctx) -> [];
emit_call_args_pairs(_, RegNum, _Ctx) when RegNum > 5 -> [];
emit_call_args_pairs([Arg | Rest], RegNum, Ctx) ->
    Src = case is_integer(Arg) of
        true -> {imm, Arg};
        false -> phys(Arg, Ctx)
    end,
    [{RegNum, Src} | emit_call_args_pairs(Rest, RegNum + 1, Ctx)].

emit_one_arg(Dst, {imm, Val}) -> ebpf_insn:mov64_imm(Dst, Val);
emit_one_arg(Dst, Src) -> ebpf_insn:mov64_reg(Dst, Src).

%% Map helper function name (binary) to BPF helper ID.
helper_id(<<"map_lookup_elem">>) -> 1;
helper_id(<<"map_update_elem">>) -> 2;
helper_id(<<"map_delete_elem">>) -> 3;
helper_id(<<"ktime_get_ns">>)    -> 5;
helper_id(<<"trace_printk">>)    -> 6;
helper_id(<<"get_smp_processor_id">>) -> 14;
helper_id(<<"redirect">>)        -> 23;
helper_id(<<"skb_load_bytes">>)  -> 26;
helper_id(<<"ringbuf_output">>)  -> 130;
helper_id(Name) when is_binary(Name) ->
    %% Unknown helper: use 0 as fallback (will fail at runtime)
    0;
helper_id(Name) when is_atom(Name) ->
    helper_id(atom_to_binary(Name, utf8)).

emit_alu_op(add, Dst, Src) -> [ebpf_insn:add64_reg(Dst, Src)];
emit_alu_op(sub, Dst, Src) -> [ebpf_insn:sub64_reg(Dst, Src)];
emit_alu_op(mul, Dst, Src) -> [ebpf_insn:mul64_reg(Dst, Src)];
emit_alu_op('div', Dst, Src) -> [ebpf_insn:div64_reg(Dst, Src)];
emit_alu_op(mod, Dst, Src) -> [ebpf_insn:mod64_reg(Dst, Src)];
emit_alu_op(and_op, Dst, Src) -> [ebpf_insn:and64_reg(Dst, Src)];
emit_alu_op(or_op, Dst, Src) -> [ebpf_insn:or64_reg(Dst, Src)];
emit_alu_op(xor_op, Dst, Src) -> [ebpf_insn:xor64_reg(Dst, Src)];
emit_alu_op(lsh, Dst, Src) -> [ebpf_insn:lsh64_reg(Dst, Src)];
emit_alu_op(rsh, Dst, Src) -> [ebpf_insn:rsh64_reg(Dst, Src)];
emit_alu_op(arsh, Dst, Src) -> [ebpf_insn:arsh64_reg(Dst, Src)];
emit_alu_op(_, _Dst, _Src) -> [].
