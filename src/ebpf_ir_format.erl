%% @doc Pretty-printer for the BPF IR.
%%
%% Formats #ir_program{} into human-readable text suitable for
%% display in the debugger UI.
-module(ebpf_ir_format).

-include("ebpf_ir.hrl").

-export([format/1, format_program/1]).

%% @doc Format an IR program as a list of {BlockLabel, [{InsnIndex, Text}]}.
-spec format(#ir_program{}) -> list().
format(#ir_program{entry = Entry, blocks = Blocks}) ->
    Order = linearize(Entry, Blocks),
    lists:map(fun(Label) ->
        Block = maps:get(Label, Blocks),
        Instrs = lists:zip(lists:seq(0, length(Block#ir_block.instrs) - 1),
                           Block#ir_block.instrs),
        FormattedInstrs = lists:map(fun({_Idx, I}) ->
            format_instr(I)
        end, Instrs),
        Term = format_term(Block#ir_block.term),
        #{label => format_label(Label),
          instrs => FormattedInstrs,
          term => Term}
    end, Order).

%% @doc Format an IR program as a single binary string.
-spec format_program(#ir_program{}) -> binary().
format_program(IR) ->
    Blocks = format(IR),
    Lines = lists:flatmap(fun(#{label := Label, instrs := Instrs, term := Term}) ->
        Header = <<Label/binary, ":">>,
        InstrLines = [<<"  ", I/binary>> || I <- Instrs, I =/= <<>>],
        TermLine = <<"  ", Term/binary>>,
        [Header | InstrLines] ++ [TermLine, <<>>]
    end, Blocks),
    iolist_to_binary(lists:join(<<"\n">>, Lines)).

%%% ===================================================================
%%% Instruction formatting
%%% ===================================================================

format_instr(#ir_instr{op = nop}) -> <<>>;
format_instr(#ir_instr{op = phi}) -> <<>>;
format_instr(#ir_instr{op = bounds_check}) -> <<>>;
format_instr(#ir_instr{op = null_check}) -> <<>>;

format_instr(#ir_instr{op = mov, dst = Dst, args = [Src]}) ->
    iolist_to_binary(io_lib:format("~s = ~s", [fmt_reg(Dst), fmt_arg(Src)]));

format_instr(#ir_instr{op = mov32, dst = Dst, args = [Src]}) ->
    iolist_to_binary(io_lib:format("~s = (u32) ~s", [fmt_reg(Dst), fmt_arg(Src)]));

format_instr(#ir_instr{op = Op, dst = Dst, args = [A, B]})
  when Op =:= add; Op =:= sub; Op =:= mul; Op =:= 'div'; Op =:= mod;
       Op =:= and_op; Op =:= or_op; Op =:= xor_op; Op =:= lsh; Op =:= rsh; Op =:= arsh ->
    iolist_to_binary(io_lib:format("~s = ~s ~s ~s",
        [fmt_reg(Dst), fmt_arg(A), fmt_alu_op(Op), fmt_arg(B)]));

format_instr(#ir_instr{op = neg, dst = Dst, args = [Src]}) ->
    iolist_to_binary(io_lib:format("~s = -~s", [fmt_reg(Dst), fmt_arg(Src)]));

format_instr(#ir_instr{op = not_op, dst = Dst, args = [Src]}) ->
    iolist_to_binary(io_lib:format("~s = !~s", [fmt_reg(Dst), fmt_arg(Src)]));

format_instr(#ir_instr{op = load, dst = Dst, args = [Base, {ctx_field, Off, Size}]}) ->
    iolist_to_binary(io_lib:format("~s = load~B [~s + ~B]  // ctx",
        [fmt_reg(Dst), Size * 8, fmt_reg(Base), Off]));

format_instr(#ir_instr{op = load, dst = Dst, args = [Base, {struct_field, Name, Off, Size}]}) ->
    iolist_to_binary(io_lib:format("~s = load~B [~s + ~B]  // .~s",
        [fmt_reg(Dst), Size * 8, fmt_reg(Base), Off, Name]));

format_instr(#ir_instr{op = load, dst = Dst, args = [Base, {pkt_read, Off, Size}]}) ->
    iolist_to_binary(io_lib:format("~s = pkt_read~B [~s + ~B]",
        [fmt_reg(Dst), Size * 8, fmt_reg(Base), Off]));

format_instr(#ir_instr{op = load, dst = Dst, args = [Base, _]}) ->
    iolist_to_binary(io_lib:format("~s = load64 [~s]", [fmt_reg(Dst), fmt_reg(Base)]));

format_instr(#ir_instr{op = store, args = [Base, {struct_field, Name, Off, Size}, Val]}) ->
    iolist_to_binary(io_lib:format("store~B [~s + ~B], ~s  // .~s",
        [Size * 8, fmt_reg(Base), Off, fmt_arg(Val), Name]));

format_instr(#ir_instr{op = store, args = [Base, {stack_off, Off}, Val], type = {scalar, u32}}) ->
    iolist_to_binary(io_lib:format("store32 [~s + ~B], ~s  // stack",
        [fmt_reg(Base), Off, fmt_arg(Val)]));

format_instr(#ir_instr{op = store, args = [Base, {stack_off, Off}, Val]}) ->
    iolist_to_binary(io_lib:format("store64 [~s + ~B], ~s  // stack",
        [fmt_reg(Base), Off, fmt_arg(Val)]));

format_instr(#ir_instr{op = store, args = [Base, _Off, Val]}) ->
    iolist_to_binary(io_lib:format("store64 [~s], ~s", [fmt_reg(Base), fmt_arg(Val)]));

format_instr(#ir_instr{op = store_imm, args = [Base, _Off, Imm]}) ->
    iolist_to_binary(io_lib:format("store64 [~s], ~s", [fmt_reg(Base), fmt_arg(Imm)]));

format_instr(#ir_instr{op = call_helper, dst = Dst, args = [{fn, Name} | Args]}) ->
    ArgStr = lists:join(", ", [fmt_arg(A) || A <- Args]),
    iolist_to_binary(io_lib:format("~s = ~s(~s)",
        [fmt_reg(Dst), Name, ArgStr]));

format_instr(#ir_instr{op = ld_map_fd, dst = Dst, args = [Fd]}) ->
    iolist_to_binary(io_lib:format("~s = map_fd(~B)", [fmt_reg(Dst), Fd]));

format_instr(#ir_instr{op = endian_be, dst = Dst, args = [Width]}) ->
    iolist_to_binary(io_lib:format("~s = be~B(~s)", [fmt_reg(Dst), Width, fmt_reg(Dst)]));

format_instr(#ir_instr{op = Op, dst = Dst, args = Args}) ->
    ArgStr = lists:join(", ", [fmt_arg(A) || A <- Args]),
    iolist_to_binary(io_lib:format("~s = ~p(~s)", [fmt_reg(Dst), Op, ArgStr])).

%%% ===================================================================
%%% Terminator formatting
%%% ===================================================================

format_term({exit, Reg}) ->
    iolist_to_binary(io_lib:format("return ~s", [fmt_reg(Reg)]));
format_term({br, Label}) ->
    iolist_to_binary(io_lib:format("br ~s", [format_label(Label)]));
format_term({cond_br, {cmp, CmpOp, L, R}, TrueL, FalseL}) ->
    iolist_to_binary(io_lib:format("if ~s ~s ~s then ~s else ~s",
        [fmt_reg(L), fmt_cmp(CmpOp), fmt_reg(R),
         format_label(TrueL), format_label(FalseL)]));
format_term({cond_br, Reg, TrueL, FalseL}) ->
    iolist_to_binary(io_lib:format("if ~s then ~s else ~s",
        [fmt_reg(Reg), format_label(TrueL), format_label(FalseL)]));
format_term(unreachable) ->
    <<"unreachable">>.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

format_label(entry) -> <<"entry">>;
format_label({label, N}) ->
    iolist_to_binary(io_lib:format("L~B", [N])).

fmt_reg(v_ctx) -> <<"v_ctx">>;
fmt_reg(v_fp)  -> <<"v_fp">>;
fmt_reg(v_ret) -> <<"v_ret">>;
fmt_reg({v, N}) ->
    iolist_to_binary(io_lib:format("v~B", [N]));
fmt_reg(none) -> <<"_">>;
fmt_reg(N) when is_integer(N) ->
    iolist_to_binary(io_lib:format("r~B", [N])).

fmt_arg(V) when is_integer(V), V >= 0, V =< 255 ->
    integer_to_binary(V);
fmt_arg(V) when is_integer(V), V >= 0 ->
    iolist_to_binary(io_lib:format("0x~.16B", [V]));
fmt_arg(V) when is_integer(V) ->
    iolist_to_binary(io_lib:format("-~B", [-V]));
fmt_arg({fn, Name}) ->
    Name;
fmt_arg({ctx_field, Off, Size}) ->
    iolist_to_binary(io_lib:format("ctx[~B:~B]", [Off, Size]));
fmt_arg({struct_field, Name, _Off, _Size}) ->
    <<"."/utf8, Name/binary>>;
fmt_arg({pkt_read, Off, Size}) ->
    iolist_to_binary(io_lib:format("pkt[~B:~B]", [Off, Size]));
fmt_arg({stack_off, Off}) ->
    iolist_to_binary(io_lib:format("stack[~B]", [Off]));
fmt_arg(Reg) ->
    fmt_reg(Reg).

fmt_alu_op(add) -> <<"+">>;
fmt_alu_op(sub) -> <<"-">>;
fmt_alu_op(mul) -> <<"*">>;
fmt_alu_op('div') -> <<"/">>;
fmt_alu_op(mod) -> <<"%">>;
fmt_alu_op(and_op) -> <<"&">>;
fmt_alu_op(or_op) -> <<"|">>;
fmt_alu_op(xor_op) -> <<"^">>;
fmt_alu_op(lsh) -> <<"<<">>;
fmt_alu_op(rsh) -> <<">>">>;
fmt_alu_op(arsh) -> <<">>>">>.

fmt_cmp(eq) -> <<"==">>;
fmt_cmp(ne) -> <<"!=">>;
fmt_cmp(gt) -> <<">">>;
fmt_cmp(ge) -> <<">=">>;
fmt_cmp(lt) -> <<"<">>;
fmt_cmp(le) -> <<"<=">>.

%%% ===================================================================
%%% Block linearization (same order as codegen)
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
                    Succs = term_succs(Block#ir_block.term),
                    linearize_bfs(Rest ++ Succs, Visited#{Label => true},
                                  Blocks, [Label | Acc]);
                error ->
                    linearize_bfs(Rest, Visited#{Label => true}, Blocks, Acc)
            end
    end.

term_succs({br, L}) -> [L];
term_succs({cond_br, _, T, F}) -> [T, F];
term_succs({exit, _}) -> [];
term_succs(unreachable) -> [].
