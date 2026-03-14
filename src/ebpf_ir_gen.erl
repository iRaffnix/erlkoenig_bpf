%% @doc AST → IR lowering.
%%
%% Converts a typed EBL AST into the register-based IR defined in ebpf_ir.hrl.
-module(ebpf_ir_gen).

-include("ebl_ast.hrl").
-include("ebpf_ir.hrl").

-export([generate/1]).

-record(gen, {
    prog_type :: xdp | tc | cgroup | socket,
    blocks = #{} :: #{label() => #ir_block{}},
    current_block = entry :: label(),
    current_instrs = [] :: [#ir_instr{}],
    current_term = undefined :: terminator() | undefined,
    vars = #{} :: #{binary() => reg()},
    maps = #{} :: #{binary() => non_neg_integer()},
    fns  = #{} :: #{binary() => label()},
    next_reg = 1 :: non_neg_integer(),
    next_label = 1 :: non_neg_integer(),
    reg_types = #{} :: #{reg() => ir_type()},
    source_map = #{} :: #{},
    %% Stack of {ContinueLabel, BreakLabel} for nested loops
    loop_stack = [] :: [{label(), label()}],
    %% Struct type definitions: #{Name => [{FieldName, Offset, Size}]}
    structs = #{} :: #{binary() => [{binary(), non_neg_integer(), non_neg_integer()}]},
    %% Current stack usage (positive, growing counter; negate for R10 offset)
    stack_offset = 0 :: non_neg_integer()
}).

%% @doc Generate IR from a parsed program.
generate(#program{type = PT, name = Name, fns = Fns, maps = Maps, types = Types}) ->
    Gen0 = #gen{prog_type = PT},
    %% Register struct layouts
    Gen0b = register_structs(Types, Gen0),
    %% Register maps
    Gen1 = register_ir_maps(Maps, Gen0b),
    %% Generate entry function (first fn named "main" or first fn)
    MainFn = find_main(Fns),
    Gen2 = gen_fn(MainFn, Gen1),
    %% Seal current block
    Gen3 = seal_block(Gen2),
    #ir_program{
        prog_type = PT,
        name = Name,
        maps = [],
        entry = entry,
        blocks = Gen3#gen.blocks,
        reg_types = Gen3#gen.reg_types,
        next_reg = Gen3#gen.next_reg,
        next_label = Gen3#gen.next_label,
        source_map = Gen3#gen.source_map
    }.

find_main(Fns) ->
    case [F || #fn_decl{name = <<"main">>} = F <- Fns] of
        [Main | _] -> Main;
        [] -> hd(Fns)
    end.

register_structs([], Gen) -> Gen;
register_structs([#type_decl{name = Name, fields = Fields} | Rest], Gen) ->
    Layout = compute_struct_layout(Fields),
    Gen2 = Gen#gen{structs = (Gen#gen.structs)#{Name => Layout}},
    register_structs(Rest, Gen2).

%% Compute field offsets with natural alignment.
%% Returns [{FieldName, Offset, Size}].
compute_struct_layout(Fields) ->
    {Layout, _} = lists:foldl(fun({FName, FType}, {Acc, Off}) ->
        Size = type_size(FType),
        Align = Size,
        AlignedOff = (Off + Align - 1) div Align * Align,
        {[{FName, AlignedOff, Size} | Acc], AlignedOff + Size}
    end, {[], 0}, Fields),
    lists:reverse(Layout).

%% Return byte size for a type expression (from AST).
type_size({prim, u8})  -> 1;
type_size({prim, i8})  -> 1;
type_size({prim, u16}) -> 2;
type_size({prim, i16}) -> 2;
type_size({prim, u32}) -> 4;
type_size({prim, i32}) -> 4;
type_size({prim, bool}) -> 4;
type_size({prim, u64}) -> 8;
type_size({prim, i64}) -> 8;
type_size({prim, action}) -> 4;
type_size({named, _})  -> 8;  %% Pointer-sized default for nested structs
type_size(_)           -> 8.  %% Default to 8 bytes

register_ir_maps([], Gen) -> Gen;
register_ir_maps([#map_decl{name = Name} | Rest], Gen) ->
    Fd = maps:size(Gen#gen.maps),
    Gen2 = Gen#gen{maps = (Gen#gen.maps)#{Name => Fd}},
    register_ir_maps(Rest, Gen2).

%%% ===================================================================
%%% Function generation
%%% ===================================================================

gen_fn(#fn_decl{params = Params, body = Body}, Gen) ->
    %% Entry block
    Gen2 = Gen#gen{current_block = entry, current_instrs = []},
    %% Bind ctx parameter to v_ctx
    Gen3 = case Params of
        [{PName, _} | _] ->
            Gen2#gen{vars = (Gen2#gen.vars)#{PName => v_ctx},
                     reg_types = (Gen2#gen.reg_types)#{v_ctx => {ptr, ctx}}};
        [] -> Gen2
    end,
    %% Generate body
    Gen4 = gen_stmts(Body, Gen3),
    %% If no explicit exit, add default return 0
    case has_terminator(Gen4) of
        true -> Gen4;
        false ->
            R0 = v_ret,
            Gen5 = emit(Gen4, #ir_instr{op = mov, dst = R0,
                                         args = [0], type = {scalar, u64}}),
            add_terminator({exit, R0}, Gen5)
    end.

%%% ===================================================================
%%% Statement generation
%%% ===================================================================

gen_stmts([], Gen) -> Gen;
gen_stmts([Stmt | Rest], Gen) ->
    Gen2 = gen_stmt(Stmt, Gen),
    case has_terminator(Gen2) of
        true -> Gen2;  %% Don't generate dead code after return/exit
        false -> gen_stmts(Rest, Gen2)
    end.

gen_stmt({let_stmt, {var_pat, Name}, Expr, _Loc}, Gen) ->
    {Reg, Gen2} = gen_expr(Expr, Gen),
    Gen2#gen{vars = (Gen2#gen.vars)#{Name => Reg}};

gen_stmt({let_stmt, {wildcard}, Expr, _Loc}, Gen) ->
    {_Reg, Gen2} = gen_expr(Expr, Gen),
    Gen2;

gen_stmt({let_stmt, _, Expr, _Loc}, Gen) ->
    {_Reg, Gen2} = gen_expr(Expr, Gen),
    Gen2;

gen_stmt({assign_stmt, {var, Name, _}, Expr, Loc}, Gen) ->
    {Reg, Gen2} = gen_expr(Expr, Gen),
    %% Copy result back to original register (needed for loops without SSA/phi)
    case maps:find(Name, Gen2#gen.vars) of
        {ok, OrigReg} when OrigReg =/= Reg ->
            Gen3 = emit(Gen2, #ir_instr{op = mov, dst = OrigReg, args = [Reg],
                                          type = {scalar, u64}, loc = Loc}),
            Gen3;  %% Keep vars pointing to OrigReg
        _ ->
            Gen2#gen{vars = (Gen2#gen.vars)#{Name => Reg}}
    end;

gen_stmt({assign_stmt, _, Expr, _Loc}, Gen) ->
    {_Reg, Gen2} = gen_expr(Expr, Gen),
    Gen2;

gen_stmt({return_stmt, Expr, Loc}, Gen) ->
    {Reg, Gen2} = gen_expr(Expr, Gen),
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = v_ret, args = [Reg],
                                  type = {scalar, u64}, loc = Loc}),
    add_terminator({exit, v_ret}, Gen3);

gen_stmt({if_stmt, Cond, Then, Elifs, Else, _Loc}, Gen) ->
    gen_if(Cond, Then, Elifs, Else, Gen);

gen_stmt({for_stmt, VarName, From, To, Body, _Loc}, Gen) ->
    gen_for(VarName, From, To, Body, Gen);

gen_stmt({match_stmt, Expr, Arms, _Loc}, Gen) ->
    gen_match(Expr, Arms, Gen);

gen_stmt({break_stmt, Loc}, #gen{loop_stack = []} = _Gen) ->
    error({compile_error, {break_outside_loop, Loc}});
gen_stmt({break_stmt, _}, #gen{loop_stack = [{_ContLabel, BreakLabel} | _]} = Gen) ->
    Gen2 = add_terminator({br, BreakLabel}, Gen),
    %% Start unreachable block for any dead code after break
    DeadLabel = fresh_label(Gen2),
    Gen3 = Gen2#gen{next_label = label_num(DeadLabel) + 1},
    Gen4 = seal_block(Gen3),
    start_block(DeadLabel, Gen4);

gen_stmt({continue_stmt, Loc}, #gen{loop_stack = []} = _Gen) ->
    error({compile_error, {continue_outside_loop, Loc}});
gen_stmt({continue_stmt, _}, #gen{loop_stack = [{ContLabel, _BreakLabel} | _]} = Gen) ->
    Gen2 = add_terminator({br, ContLabel}, Gen),
    %% Start unreachable block for any dead code after continue
    DeadLabel = fresh_label(Gen2),
    Gen3 = Gen2#gen{next_label = label_num(DeadLabel) + 1},
    Gen4 = seal_block(Gen3),
    start_block(DeadLabel, Gen4);

gen_stmt({expr_stmt, Expr, _Loc}, Gen) ->
    {_Reg, Gen2} = gen_expr(Expr, Gen),
    Gen2.

%%% ===================================================================
%%% If generation
%%% ===================================================================

gen_if(Cond, Then, Elifs, Else, Gen) ->
    %% Pre-allocate the join label
    JoinLabel = fresh_label(Gen),
    Gen1 = Gen#gen{next_label = label_num(JoinLabel) + 1},
    %% Generate the first if-branch, then chain through elifs to else
    gen_if_chain(Cond, Then, Elifs, Else, JoinLabel, Gen1).

%% Generate one condition check + body, then chain to remaining elifs/else
gen_if_chain(Cond, Then, Elifs, Else, JoinLabel, Gen) ->
    {CondTerm, Gen2} = gen_condition(Cond, Gen),
    ThenLabel = fresh_label(Gen2),
    NextLabel = fresh_label_after(ThenLabel),
    Gen3 = Gen2#gen{next_label = label_num(NextLabel) + 1},
    Term = case CondTerm of
        {cmp, CmpOp, LReg, RReg} ->
            {cond_br, {cmp, CmpOp, LReg, RReg}, ThenLabel, NextLabel};
        {reg, CondReg} ->
            {cond_br, CondReg, ThenLabel, NextLabel}
    end,
    Gen4 = add_terminator(Term, Gen3),
    Gen5 = seal_block(Gen4),
    %% Then block
    Gen6 = start_block(ThenLabel, Gen5),
    Gen7 = gen_stmts(Then, Gen6),
    Gen8 = case has_terminator(Gen7) of
        true -> Gen7;
        false -> add_terminator({br, JoinLabel}, Gen7)
    end,
    Gen9 = seal_block(Gen8),
    %% Next: either elif chain or else block
    Gen10 = start_block(NextLabel, Gen9),
    case Elifs of
        [{ElifCond, ElifBody} | RestElifs] ->
            %% Recurse: the current NextLabel block becomes the check for the next elif
            Gen11 = gen_if_chain(ElifCond, ElifBody, RestElifs, Else, JoinLabel, Gen10),
            Gen11;
        [] ->
            %% Final else block (may be empty)
            Gen11 = gen_stmts(Else, Gen10),
            Gen12 = case has_terminator(Gen11) of
                true -> Gen11;
                false -> add_terminator({br, JoinLabel}, Gen11)
            end,
            Gen13 = seal_block(Gen12),
            start_block(JoinLabel, Gen13)
    end.

%%% ===================================================================
%%% Condition generation (for if-statements)
%%% ===================================================================

%% Detect comparison binops and return {cmp, Op, LReg, RReg} directly,
%% avoiding the broken sub-based approach.  Non-comparison conditions
%% fall through to gen_expr and return {reg, Reg} for zero/non-zero.
gen_condition({binop, Op, Left, Right, _Loc}, Gen) when
      Op =:= '=='; Op =:= '!='; Op =:= '<'; Op =:= '>';
      Op =:= '<='; Op =:= '>=' ->
    {LReg, Gen2} = gen_expr(Left, Gen),
    {RReg, Gen3} = gen_expr(Right, Gen2),
    CmpOp = cmp_op(Op),
    {{cmp, CmpOp, LReg, RReg}, Gen3};
gen_condition(Cond, Gen) ->
    {Reg, Gen2} = gen_expr(Cond, Gen),
    {{reg, Reg}, Gen2}.

cmp_op('==') -> eq;
cmp_op('!=') -> ne;
cmp_op('<')  -> lt;
cmp_op('>')  -> gt;
cmp_op('<=') -> le;
cmp_op('>=') -> ge.

%%% ===================================================================
%%% For-loop generation
%%% ===================================================================

gen_for(VarName, From, To, Body, Gen) ->
    {FromReg, Gen2} = gen_expr(From, Gen),
    {ToReg, Gen3} = gen_expr(To, Gen2),
    HeaderLabel = fresh_label(Gen3),
    BodyLabel = fresh_label_after(HeaderLabel),
    LatchLabel = fresh_label_after(BodyLabel),
    ExitLabel = fresh_label_after(LatchLabel),
    Gen4 = Gen3#gen{next_label = label_num(ExitLabel) + 1},
    %% Initialize: iter = from, count = to - from
    IterReg = fresh_reg(Gen4),
    Gen5 = Gen4#gen{next_reg = Gen4#gen.next_reg + 1},
    Gen6 = emit(Gen5, #ir_instr{op = mov, dst = IterReg, args = [FromReg],
                                  type = {scalar, u64}}),
    CountReg = fresh_reg(Gen6),
    Gen7 = Gen6#gen{next_reg = Gen6#gen.next_reg + 1,
                    vars = (Gen6#gen.vars)#{VarName => IterReg}},
    Gen8 = emit(Gen7, #ir_instr{op = sub, dst = CountReg,
                                  args = [ToReg, FromReg],
                                  type = {scalar, u64}}),
    Gen9 = add_terminator({br, HeaderLabel}, Gen8),
    Gen10 = seal_block(Gen9),
    %% Loop header: if count != 0 → body, else → exit
    Gen11 = start_block(HeaderLabel, Gen10),
    Gen12 = add_terminator({cond_br, CountReg, BodyLabel, ExitLabel}, Gen11),
    Gen13 = seal_block(Gen12),
    %% Body block — push loop context for break/continue
    OldStack = Gen13#gen.loop_stack,
    Gen14 = start_block(BodyLabel,
                        Gen13#gen{loop_stack = [{LatchLabel, ExitLabel} | OldStack]}),
    Gen15 = gen_stmts(Body, Gen14),
    Gen16 = case has_terminator(Gen15) of
        true -> Gen15;
        false -> add_terminator({br, LatchLabel}, Gen15)
    end,
    Gen17 = seal_block(Gen16),
    %% Latch block: increment iter, decrement count, jump back to header
    Gen18 = start_block(LatchLabel, Gen17),
    Gen19 = emit(Gen18, #ir_instr{op = add, dst = IterReg,
                                    args = [IterReg, 1],
                                    type = {scalar, u64}}),
    Gen20 = emit(Gen19, #ir_instr{op = sub, dst = CountReg,
                                    args = [CountReg, 1],
                                    type = {scalar, u64}}),
    Gen21 = add_terminator({br, HeaderLabel}, Gen20),
    Gen22 = seal_block(Gen21),
    %% Exit block — restore loop stack
    start_block(ExitLabel, Gen22#gen{loop_stack = OldStack}).

%%% ===================================================================
%%% Match generation
%%% ===================================================================

gen_match(Expr, Arms, Gen) ->
    {ExprReg, Gen2} = gen_expr(Expr, Gen),
    JoinLabel = fresh_label(Gen2),
    Gen3 = Gen2#gen{next_label = label_num(JoinLabel) + 1},
    Gen4 = gen_match_arms(ExprReg, Arms, JoinLabel, Gen3),
    start_block(JoinLabel, Gen4).

gen_match_arms(_ExprReg, [], JoinLabel, Gen) ->
    %% Default: branch to join
    Gen2 = add_terminator({br, JoinLabel}, Gen),
    seal_block(Gen2);
gen_match_arms(ExprReg, [{Pat, Body} | Rest], JoinLabel, Gen) ->
    ArmLabel = fresh_label(Gen),
    NextLabel = fresh_label_after(ArmLabel),
    Gen2 = Gen#gen{next_label = label_num(NextLabel) + 1},
    %% Condition check (simplified: compare with pattern literal)
    case Pat of
        {lit_pat, Val} ->
            %% Load the literal value into a register for comparison
            ValReg = fresh_reg(Gen2),
            Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
            Gen4 = emit(Gen3, #ir_instr{op = mov, dst = ValReg,
                                          args = [Val],
                                          type = {scalar, u64}}),
            %% Use native comparison: if ExprReg != Val → NextLabel, else ArmLabel
            Gen5 = add_terminator({cond_br, {cmp, ne, ExprReg, ValReg},
                                   NextLabel, ArmLabel}, Gen4),
            Gen6 = seal_block(Gen5);
        {var_pat, Name} ->
            Gen3 = Gen2#gen{vars = (Gen2#gen.vars)#{Name => ExprReg}},
            Gen4 = add_terminator({br, ArmLabel}, Gen3),
            Gen6 = seal_block(Gen4);
        {wildcard} ->
            Gen4 = add_terminator({br, ArmLabel}, Gen2),
            Gen6 = seal_block(Gen4);
        _ ->
            Gen4 = add_terminator({br, ArmLabel}, Gen2),
            Gen6 = seal_block(Gen4)
    end,
    %% Arm body
    Gen7 = start_block(ArmLabel, Gen6),
    Gen8 = gen_stmts(Body, Gen7),
    Gen9 = case has_terminator(Gen8) of
        true -> Gen8;
        false -> add_terminator({br, JoinLabel}, Gen8)
    end,
    Gen10 = seal_block(Gen9),
    %% Next arm
    Gen11 = start_block(NextLabel, Gen10),
    gen_match_arms(ExprReg, Rest, JoinLabel, Gen11).

%%% ===================================================================
%%% Expression generation
%%% ===================================================================

gen_expr({integer_lit, Val, Loc}, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [Val],
                                  type = {scalar, u64}, loc = Loc}),
    Gen4 = set_reg_type(Dst, {scalar, u64}, Gen3),
    {Dst, Gen4};

gen_expr({bool_lit, true, Loc}, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [1],
                                  type = {scalar, bool}, loc = Loc}),
    {Dst, Gen3};

gen_expr({bool_lit, false, Loc}, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                  type = {scalar, bool}, loc = Loc}),
    {Dst, Gen3};

gen_expr({atom_lit, Name, Loc}, Gen) ->
    Val = action_value(Name, Gen#gen.prog_type),
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [Val],
                                  type = action, loc = Loc}),
    {Dst, Gen3};

gen_expr({var, Name, _Loc}, Gen) ->
    case maps:find(Name, Gen#gen.vars) of
        {ok, Reg} -> {Reg, Gen};
        error ->
            Dst = fresh_reg(Gen),
            Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
            Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                          type = {scalar, u64}}),
            {Dst, Gen3}
    end;

gen_expr({binop, Op, Left, Right, Loc}, Gen) ->
    {LReg, Gen2} = gen_expr(Left, Gen),
    {RReg, Gen3} = gen_expr(Right, Gen2),
    Dst = fresh_reg(Gen3),
    Gen4 = Gen3#gen{next_reg = Gen3#gen.next_reg + 1},
    IROp = binop_to_ir(Op),
    Gen5 = emit(Gen4, #ir_instr{op = IROp, dst = Dst, args = [LReg, RReg],
                                  type = {scalar, u64}, loc = Loc}),
    {Dst, Gen5};

gen_expr({unop, '-', Expr, Loc}, Gen) ->
    {Reg, Gen2} = gen_expr(Expr, Gen),
    Dst = fresh_reg(Gen2),
    Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
    Gen4 = emit(Gen3, #ir_instr{op = neg, dst = Dst, args = [Reg],
                                  type = {scalar, u64}, loc = Loc}),
    {Dst, Gen4};

gen_expr({unop, '!', Expr, Loc}, Gen) ->
    {Reg, Gen2} = gen_expr(Expr, Gen),
    Dst = fresh_reg(Gen2),
    Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
    Gen4 = emit(Gen3, #ir_instr{op = not_op, dst = Dst, args = [Reg],
                                  type = {scalar, bool}, loc = Loc}),
    {Dst, Gen4};

gen_expr({unop, '~', Expr, Loc}, Gen) ->
    {Reg, Gen2} = gen_expr(Expr, Gen),
    Dst = fresh_reg(Gen2),
    Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
    Gen4 = emit(Gen3, #ir_instr{op = xor_op, dst = Dst,
                                  args = [Reg, -1],
                                  type = {scalar, u64}, loc = Loc}),
    {Dst, Gen4};

gen_expr({call, Name, Args, Loc}, Gen) when
      Name =:= <<"map_lookup">>; Name =:= <<"lookup">>;
      Name =:= <<"map_update">>; Name =:= <<"update">>;
      Name =:= <<"map_delete">>; Name =:= <<"delete">> ->
    gen_map_op(Name, Args, Loc, Gen);
gen_expr({call, Name, Args, _Loc}, Gen) when
      Name =:= <<"read_u8">>; Name =:= <<"read_u16">>; Name =:= <<"read_u32">>;
      Name =:= <<"read_u16_be">>; Name =:= <<"read_u32_be">> ->
    gen_pkt_read(Name, Args, Gen);
gen_expr({call, Name, Args, Loc}, Gen) ->
    {ArgRegs, Gen2} = gen_exprs(Args, Gen),
    Dst = fresh_reg(Gen2),
    Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
    Gen4 = emit(Gen3, #ir_instr{op = call_helper, dst = Dst,
                                  args = [{fn, Name} | ArgRegs],
                                  type = {scalar, u64}, loc = Loc}),
    {Dst, Gen4};

gen_expr({field_access, Obj, Field, Loc}, Gen) ->
    {ObjReg, Gen2} = gen_expr(Obj, Gen),
    Dst = fresh_reg(Gen2),
    Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
    %% Check if this is a context field access (ObjReg == v_ctx)
    case ObjReg of
        v_ctx ->
            case ebpf_ctx:field(Gen3#gen.prog_type, Field) of
                {ok, Offset, Size} ->
                    Type = case Size of S when S =< 4 -> {scalar, u32}; _ -> {scalar, u64} end,
                    Gen4 = emit(Gen3, #ir_instr{op = load, dst = Dst,
                                                  args = [v_ctx, {ctx_field, Offset, Size}],
                                                  type = Type, loc = Loc}),
                    {Dst, Gen4};
                {error, unknown_field} ->
                    Gen4 = emit(Gen3, #ir_instr{op = load, dst = Dst,
                                                  args = [ObjReg, {field, Field}],
                                                  type = {scalar, u64}, loc = Loc}),
                    {Dst, Gen4}
            end;
        _ ->
            case lookup_struct_field(ObjReg, Field, Gen3) of
                {ok, Offset, Size} ->
                    Type = case Size of
                        1 -> {scalar, u8};
                        2 -> {scalar, u16};
                        4 -> {scalar, u32};
                        8 -> {scalar, u64};
                        _ -> {scalar, u64}
                    end,
                    Gen4 = emit(Gen3, #ir_instr{op = load, dst = Dst,
                                                  args = [ObjReg, {struct_field, Field, Offset, Size}],
                                                  type = Type, loc = Loc}),
                    {Dst, Gen4};
                error ->
                    Gen4 = emit(Gen3, #ir_instr{op = load, dst = Dst,
                                                  args = [ObjReg, {field, Field}],
                                                  type = {scalar, u64}, loc = Loc}),
                    {Dst, Gen4}
            end
    end;

gen_expr({method_call, Obj, Method, Args, Loc}, Gen) ->
    gen_expr({call, Method, [Obj | Args], Loc}, Gen);

gen_expr({struct_lit, TypeName, Fields, _Loc}, Gen) ->
    case maps:find(TypeName, Gen#gen.structs) of
        {ok, Layout} ->
            %% Compute total struct size from layout
            StructSize = struct_total_size(Layout),
            %% Align struct size to 8 bytes for stack alignment
            AlignedSize = (StructSize + 7) div 8 * 8,
            %% Allocate stack space via alloc_stack (unified convention)
            {StructBaseOff, Gen2} = alloc_stack(AlignedSize, Gen),
            %% Dst = pointer to struct (R10 + base_offset)
            Dst = fresh_reg(Gen2),
            Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
            Gen4 = emit(Gen3, #ir_instr{op = add, dst = Dst,
                                          args = [v_fp, StructBaseOff],
                                          type = {ptr, stack}}),
            %% Store each field at its computed offset
            Gen5 = lists:foldl(fun({FName, FExpr}, G) ->
                {FReg, G2} = gen_expr(FExpr, G),
                case lists:keyfind(FName, 1, Layout) of
                    {_, FOffset, FSize} ->
                        emit(G2, #ir_instr{op = store, dst = none,
                                             args = [Dst, {struct_field, FName, FOffset, FSize}, FReg],
                                             type = {scalar, u64}});
                    false ->
                        G2  %% Unknown field, skip
                end
            end, Gen4, Fields),
            %% Set the register type so field_access can look up the struct layout
            Gen6 = set_reg_type(Dst, {named, TypeName}, Gen5),
            {Dst, Gen6};
        error ->
            %% Unknown struct type: fallback to old behavior
            Dst = fresh_reg(Gen),
            Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
            Gen3 = lists:foldl(fun({_FN, FExpr}, G) ->
                {_FReg, G2} = gen_expr(FExpr, G),
                G2
            end, Gen2, Fields),
            Gen4 = emit(Gen3, #ir_instr{op = mov, dst = Dst, args = [0],
                                          type = {scalar, u64}}),
            {Dst, Gen4}
    end;

gen_expr({sizeof_expr, TypeExpr, Loc}, Gen) ->
    Size = type_size(TypeExpr),
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [Size],
                                  type = {scalar, u64}, loc = Loc}),
    {Dst, Gen3};

gen_expr({some_expr, Inner, _Loc}, Gen) ->
    gen_expr(Inner, Gen);

gen_expr({none_expr, _Loc}, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                  type = {option, {scalar, u64}}}),
    {Dst, Gen3};

gen_expr({index, Obj, Idx, Loc}, Gen) ->
    {ObjReg, Gen2} = gen_expr(Obj, Gen),
    {IdxReg, Gen3} = gen_expr(Idx, Gen2),
    Dst = fresh_reg(Gen3),
    Gen4 = Gen3#gen{next_reg = Gen3#gen.next_reg + 1},
    Gen5 = emit(Gen4, #ir_instr{op = load, dst = Dst,
                                  args = [ObjReg, IdxReg],
                                  type = {scalar, u64}, loc = Loc}),
    {Dst, Gen5};

gen_expr(_, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                  type = {scalar, u64}}),
    {Dst, Gen3}.

gen_exprs(Exprs, Gen) ->
    lists:foldl(fun(E, {Regs, G}) ->
        {R, G2} = gen_expr(E, G),
        {Regs ++ [R], G2}
    end, {[], Gen}, Exprs).

%%% ===================================================================
%%% Packet read built-ins
%%% ===================================================================

%% read_u8(ptr, offset)   → ldxb  [ptr + offset]
%% read_u16(ptr, offset)  → ldxh  [ptr + offset]       (host byte order)
%% read_u32(ptr, offset)  → ldxw  [ptr + offset]       (host byte order)
%% read_u16_be(ptr, offset) → ldxh + be16              (network byte order)
%% read_u32_be(ptr, offset) → ldxw + be32              (network byte order)
gen_pkt_read(Name, [PtrArg, OffArg], Gen) ->
    {PtrReg, Gen2} = gen_expr(PtrArg, Gen),
    {Size, NeedSwap} = pkt_read_params(Name),
    %% Offset must be a compile-time constant (integer literal)
    Offset = case OffArg of
        {integer_lit, V, _} -> V;
        _ -> error({compile_error, {non_constant_offset, Name}})
    end,
    Dst = fresh_reg(Gen2),
    Gen3 = Gen2#gen{next_reg = Gen2#gen.next_reg + 1},
    Type = case Size of 1 -> {scalar, u8}; 2 -> {scalar, u16}; 4 -> {scalar, u32} end,
    Gen4 = emit(Gen3, #ir_instr{op = load, dst = Dst,
                                  args = [PtrReg, {pkt_read, Offset, Size}],
                                  type = Type}),
    case NeedSwap of
        false ->
            {Dst, Gen4};
        {be, Bits} ->
            Gen5 = emit(Gen4, #ir_instr{op = endian_be, dst = Dst,
                                          args = [Bits], type = Type}),
            {Dst, Gen5}
    end;
gen_pkt_read(_Name, _Args, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                  type = {scalar, u64}}),
    {Dst, Gen3}.

pkt_read_params(<<"read_u8">>)     -> {1, false};
pkt_read_params(<<"read_u16">>)    -> {2, false};
pkt_read_params(<<"read_u32">>)    -> {4, false};
pkt_read_params(<<"read_u16_be">>) -> {2, {be, 16}};
pkt_read_params(<<"read_u32_be">>) -> {4, {be, 32}}.

%%% ===================================================================
%%% Map operation lowering
%%% ===================================================================

%% Resolve map name from the first argument (variable referring to a declared map).
resolve_map_name({var, Name, _}, Gen) ->
    case maps:find(Name, Gen#gen.maps) of
        {ok, Fd} -> {ok, Name, Fd};
        error -> error
    end;
resolve_map_name({atom_lit, Name, _}, Gen) ->
    case maps:find(Name, Gen#gen.maps) of
        {ok, Fd} -> {ok, Name, Fd};
        error -> error
    end;
resolve_map_name(_, _Gen) ->
    error.

%% Normalize map op names: lookup/map_lookup -> lookup, etc.
normalize_map_op(<<"map_lookup">>) -> lookup;
normalize_map_op(<<"lookup">>)     -> lookup;
normalize_map_op(<<"map_update">>) -> update;
normalize_map_op(<<"update">>)     -> update;
normalize_map_op(<<"map_delete">>) -> delete;
normalize_map_op(<<"delete">>)     -> delete.

%% Allocate stack space.  stack_offset is a positive, monotonically
%% growing counter.  Returns {NegOffset, NewGen} where NegOffset is the
%% negative offset from R10 (frame pointer), e.g. -8 means [R10-8].
alloc_stack(Size, Gen) ->
    NewOff = Gen#gen.stack_offset + Size,
    {-NewOff, Gen#gen{stack_offset = NewOff}}.

%% Generate IR for map operations.
gen_map_op(Name, Args, _Loc, Gen) ->
    Op = normalize_map_op(Name),
    case Op of
        lookup -> gen_map_lookup(Args, Gen);
        update -> gen_map_update(Args, Gen);
        delete -> gen_map_delete(Args, Gen)
    end.

%% map_lookup(map, key) -> result (value or 0)
%%
%% Generated sequence:
%%   stxw [v_fp + key_off], key_reg
%%   ld_map_fd map_fd_reg, map_id
%%   mov key_ptr_reg, v_fp; add key_ptr_reg, key_off
%%   call_helper 1 (map_lookup_elem)
%%   NULL check: if result == 0 -> 0, else load value from pointer
gen_map_lookup([MapArg, KeyArg], Gen) ->
    {ok, _MapName, MapFd} = resolve_map_name(MapArg, Gen),
    {KeyReg, Gen2} = gen_expr(KeyArg, Gen),
    %% Allocate stack for key (4 bytes)
    {KeyOff, Gen3} = alloc_stack(4, Gen2),
    %% Store key on stack
    Gen4 = emit(Gen3, #ir_instr{op = store, dst = none,
                                  args = [v_fp, {stack_off, KeyOff}, KeyReg],
                                  type = {scalar, u32}}),
    %% Load map FD
    MapFdReg = fresh_reg(Gen4),
    Gen5 = Gen4#gen{next_reg = Gen4#gen.next_reg + 1},
    Gen6 = emit(Gen5, #ir_instr{op = ld_map_fd, dst = MapFdReg,
                                  args = [MapFd], type = {scalar, u64}}),
    %% Compute key pointer
    KeyPtrReg = fresh_reg(Gen6),
    Gen7 = Gen6#gen{next_reg = Gen6#gen.next_reg + 1},
    Gen8 = emit(Gen7, #ir_instr{op = mov, dst = KeyPtrReg, args = [v_fp],
                                  type = {ptr, stack}}),
    Gen9 = emit(Gen8, #ir_instr{op = add, dst = KeyPtrReg,
                                  args = [KeyPtrReg, KeyOff],
                                  type = {ptr, stack}}),
    %% Call helper 1: map_lookup_elem(map_fd, key_ptr)
    CallDst = fresh_reg(Gen9),
    Gen10 = Gen9#gen{next_reg = Gen9#gen.next_reg + 1},
    Gen11 = emit(Gen10, #ir_instr{op = call_helper, dst = CallDst,
                                    args = [{fn, <<"map_lookup_elem">>},
                                            MapFdReg, KeyPtrReg],
                                    type = {ptr, map_value}}),
    %% NULL check with branching
    NullLabel = fresh_label(Gen11),
    ValueLabel = fresh_label_after(NullLabel),
    JoinLabel = fresh_label_after(ValueLabel),
    Gen12 = Gen11#gen{next_label = label_num(JoinLabel) + 1},
    %% Result register (shared across branches)
    ResultReg = fresh_reg(Gen12),
    Gen13 = Gen12#gen{next_reg = Gen12#gen.next_reg + 1},
    %% Initialize result to 0 (default for NULL case)
    Gen14 = emit(Gen13, #ir_instr{op = mov, dst = ResultReg, args = [0],
                                    type = {scalar, u64}}),
    %% Zero register for comparison
    ZeroReg = fresh_reg(Gen14),
    Gen15 = Gen14#gen{next_reg = Gen14#gen.next_reg + 1},
    Gen16 = emit(Gen15, #ir_instr{op = mov, dst = ZeroReg, args = [0],
                                    type = {scalar, u64}}),
    %% Branch: if CallDst == 0 -> NullLabel, else -> ValueLabel
    Gen17 = add_terminator({cond_br, {cmp, eq, CallDst, ZeroReg},
                            NullLabel, ValueLabel}, Gen16),
    Gen18 = seal_block(Gen17),
    %% Value block: load value from pointer
    Gen19 = start_block(ValueLabel, Gen18),
    Gen20 = emit(Gen19, #ir_instr{op = load, dst = ResultReg,
                                    args = [CallDst, {ctx_field, 0, 8}],
                                    type = {scalar, u64}}),
    Gen21 = add_terminator({br, JoinLabel}, Gen20),
    Gen22 = seal_block(Gen21),
    %% Null block: result already 0
    Gen23 = start_block(NullLabel, Gen22),
    Gen24 = add_terminator({br, JoinLabel}, Gen23),
    Gen25 = seal_block(Gen24),
    %% Join block
    Gen26 = start_block(JoinLabel, Gen25),
    {ResultReg, Gen26};
gen_map_lookup(_, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                  type = {scalar, u64}}),
    {Dst, Gen3}.

%% map_update(map, key, value) -> 0 on success
gen_map_update([MapArg, KeyArg, ValArg], Gen) ->
    {ok, _MapName, MapFd} = resolve_map_name(MapArg, Gen),
    {KeyReg, Gen2} = gen_expr(KeyArg, Gen),
    {ValReg, Gen3} = gen_expr(ValArg, Gen2),
    {KeyOff, Gen4} = alloc_stack(4, Gen3),
    {ValOff, Gen5} = alloc_stack(8, Gen4),
    %% Store key and value on stack
    Gen6 = emit(Gen5, #ir_instr{op = store, dst = none,
                                  args = [v_fp, {stack_off, KeyOff}, KeyReg],
                                  type = {scalar, u32}}),
    Gen7 = emit(Gen6, #ir_instr{op = store, dst = none,
                                  args = [v_fp, {stack_off, ValOff}, ValReg],
                                  type = {scalar, u64}}),
    %% Load map FD
    MapFdReg = fresh_reg(Gen7),
    Gen8 = Gen7#gen{next_reg = Gen7#gen.next_reg + 1},
    Gen9 = emit(Gen8, #ir_instr{op = ld_map_fd, dst = MapFdReg,
                                  args = [MapFd], type = {scalar, u64}}),
    %% Key pointer
    KeyPtrReg = fresh_reg(Gen9),
    Gen10 = Gen9#gen{next_reg = Gen9#gen.next_reg + 1},
    Gen11 = emit(Gen10, #ir_instr{op = mov, dst = KeyPtrReg, args = [v_fp],
                                    type = {ptr, stack}}),
    Gen12 = emit(Gen11, #ir_instr{op = add, dst = KeyPtrReg,
                                    args = [KeyPtrReg, KeyOff],
                                    type = {ptr, stack}}),
    %% Value pointer
    ValPtrReg = fresh_reg(Gen12),
    Gen13 = Gen12#gen{next_reg = Gen12#gen.next_reg + 1},
    Gen14 = emit(Gen13, #ir_instr{op = mov, dst = ValPtrReg, args = [v_fp],
                                    type = {ptr, stack}}),
    Gen15 = emit(Gen14, #ir_instr{op = add, dst = ValPtrReg,
                                    args = [ValPtrReg, ValOff],
                                    type = {ptr, stack}}),
    %% Flags = 0 (BPF_ANY)
    FlagsReg = fresh_reg(Gen15),
    Gen16 = Gen15#gen{next_reg = Gen15#gen.next_reg + 1},
    Gen17 = emit(Gen16, #ir_instr{op = mov, dst = FlagsReg, args = [0],
                                    type = {scalar, u64}}),
    %% Call helper 2
    Dst = fresh_reg(Gen17),
    Gen18 = Gen17#gen{next_reg = Gen17#gen.next_reg + 1},
    Gen19 = emit(Gen18, #ir_instr{op = call_helper, dst = Dst,
                                    args = [{fn, <<"map_update_elem">>},
                                            MapFdReg, KeyPtrReg, ValPtrReg, FlagsReg],
                                    type = {scalar, u64}}),
    {Dst, Gen19};
gen_map_update(_, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                  type = {scalar, u64}}),
    {Dst, Gen3}.

%% map_delete(map, key) -> 0 on success
gen_map_delete([MapArg, KeyArg], Gen) ->
    {ok, _MapName, MapFd} = resolve_map_name(MapArg, Gen),
    {KeyReg, Gen2} = gen_expr(KeyArg, Gen),
    {KeyOff, Gen3} = alloc_stack(4, Gen2),
    Gen4 = emit(Gen3, #ir_instr{op = store, dst = none,
                                  args = [v_fp, {stack_off, KeyOff}, KeyReg],
                                  type = {scalar, u32}}),
    MapFdReg = fresh_reg(Gen4),
    Gen5 = Gen4#gen{next_reg = Gen4#gen.next_reg + 1},
    Gen6 = emit(Gen5, #ir_instr{op = ld_map_fd, dst = MapFdReg,
                                  args = [MapFd], type = {scalar, u64}}),
    KeyPtrReg = fresh_reg(Gen6),
    Gen7 = Gen6#gen{next_reg = Gen6#gen.next_reg + 1},
    Gen8 = emit(Gen7, #ir_instr{op = mov, dst = KeyPtrReg, args = [v_fp],
                                  type = {ptr, stack}}),
    Gen9 = emit(Gen8, #ir_instr{op = add, dst = KeyPtrReg,
                                  args = [KeyPtrReg, KeyOff],
                                  type = {ptr, stack}}),
    Dst = fresh_reg(Gen9),
    Gen10 = Gen9#gen{next_reg = Gen9#gen.next_reg + 1},
    Gen11 = emit(Gen10, #ir_instr{op = call_helper, dst = Dst,
                                    args = [{fn, <<"map_delete_elem">>},
                                            MapFdReg, KeyPtrReg],
                                    type = {scalar, u64}}),
    {Dst, Gen11};
gen_map_delete(_, Gen) ->
    Dst = fresh_reg(Gen),
    Gen2 = Gen#gen{next_reg = Gen#gen.next_reg + 1},
    Gen3 = emit(Gen2, #ir_instr{op = mov, dst = Dst, args = [0],
                                  type = {scalar, u64}}),
    {Dst, Gen3}.

%%% ===================================================================
%%% Block management
%%% ===================================================================

fresh_reg(#gen{next_reg = N}) -> {v, N}.

fresh_label(#gen{next_label = N}) -> {label, N}.
fresh_label_after({label, N}) -> {label, N + 1}.
label_num({label, N}) -> N.

emit(Gen, Instr) ->
    Gen#gen{current_instrs = Gen#gen.current_instrs ++ [Instr]}.

has_terminator(#gen{current_term = undefined}) -> false;
has_terminator(#gen{}) -> true.

add_terminator(Term, Gen) ->
    Gen#gen{current_term = Term}.

seal_block(#gen{current_block = Label, current_instrs = Instrs,
                current_term = Term0, blocks = Blocks} = Gen) ->
    Term = case Term0 of undefined -> unreachable; _ -> Term0 end,
    Block = #ir_block{label = Label, instrs = Instrs, term = Term},
    Gen#gen{blocks = Blocks#{Label => Block},
            current_instrs = [], current_term = undefined}.

start_block(Label, Gen) ->
    Gen#gen{current_block = Label, current_instrs = [],
            current_term = undefined}.

set_reg_type(Reg, Type, #gen{reg_types = RT} = Gen) ->
    Gen#gen{reg_types = RT#{Reg => Type}}.

%% Compute total size of a struct from its layout.
struct_total_size([]) -> 0;
struct_total_size(Layout) ->
    lists:max([Offset + Size || {_, Offset, Size} <- Layout]).

%% Look up a struct field given a register that holds a struct pointer.
%% Returns {ok, Offset, Size} or error.
lookup_struct_field(Reg, Field, #gen{reg_types = RT, structs = Structs}) ->
    case maps:find(Reg, RT) of
        {ok, {named, TypeName}} ->
            case maps:find(TypeName, Structs) of
                {ok, Layout} ->
                    case lists:keyfind(Field, 1, Layout) of
                        {_, Offset, Size} -> {ok, Offset, Size};
                        false -> error
                    end;
                error -> error
            end;
        {ok, {ptr, {struct, TypeName}}} ->
            case maps:find(TypeName, Structs) of
                {ok, Layout} ->
                    case lists:keyfind(Field, 1, Layout) of
                        {_, Offset, Size} -> {ok, Offset, Size};
                        false -> error
                    end;
                error -> error
            end;
        _ -> error
    end.

%%% ===================================================================
%%% Operator mapping
%%% ===================================================================

binop_to_ir('+') -> add;
binop_to_ir('-') -> sub;
binop_to_ir('*') -> mul;
binop_to_ir('/') -> 'div';
binop_to_ir('%') -> mod;
binop_to_ir('&') -> and_op;
binop_to_ir('|') -> or_op;
binop_to_ir('^') -> xor_op;
binop_to_ir('<<') -> lsh;
binop_to_ir('>>') -> rsh;
binop_to_ir('==') -> sub;   %% Compare via subtract (cond_br on zero)
binop_to_ir('!=') -> sub;
binop_to_ir('<') -> sub;
binop_to_ir('>') -> sub;
binop_to_ir('<=') -> sub;
binop_to_ir('>=') -> sub;
binop_to_ir('&&') -> and_op;
binop_to_ir('||') -> or_op;
binop_to_ir(_) -> mov.

action_value(<<"drop">>,     xdp) -> ?XDP_DROP;
action_value(<<"pass">>,     xdp) -> ?XDP_PASS;
action_value(<<"tx">>,       xdp) -> ?XDP_TX;
action_value(<<"redirect">>, xdp) -> ?XDP_REDIRECT;
action_value(<<"aborted">>,  xdp) -> ?XDP_ABORTED;
action_value(<<"ok">>,       tc)  -> ?TC_OK;
action_value(<<"shot">>,     tc)  -> ?TC_SHOT;
action_value(<<"drop">>,     tc)  -> ?TC_SHOT;
action_value(<<"pass">>,     tc)  -> ?TC_OK;
action_value(<<"allow">>,    cgroup) -> 1;
action_value(<<"deny">>,     cgroup) -> 0;
action_value(<<"pass">>,     _)   -> 0;
action_value(<<"drop">>,     _)   -> 1;
action_value(_, _) -> 0.
