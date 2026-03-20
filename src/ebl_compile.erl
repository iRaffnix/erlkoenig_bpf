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

-module(ebl_compile).
-moduledoc """
End-to-end EBL compilation pipeline.

Source binary -> Lex -> Parse -> TypeCheck -> IR Gen -> Codegen -> Peephole -> BPF binary.
""".

-include("ebl_ast.hrl").
-include("ebpf_ir.hrl").

-export([compile/1, compile/2, file/1, file/2, compile_debug/1]).

file(Path) ->
    file(Path, #{}).
file(Path, Opts) ->
    case file:read_file(Path) of
        {ok, Source} -> compile(Source, Opts);
        {error, Reason} -> {error, {file, Reason}}
    end.

compile(Source) ->
    compile(Source, #{}).
-doc "Compile returning all intermediate artifacts for the debugger.".
compile_debug(Source) ->
    maybe
        {ok, Tokens} ?= ebl_lexer:tokenize(Source),
        {ok, AST} ?= ebl_parser:parse(Tokens),
        {ok, TypedAST} ?= ebl_typecheck:check(AST),
        IR = ebpf_ir_gen:generate(TypedAST),
        {RegMap, SpillMap} = ebpf_regalloc:allocate(IR),
        Bin = ebpf_codegen:codegen(IR, RegMap, SpillMap),
        IRBlocks = ebpf_ir_format:format(IR),
        SourceMap = build_source_map(IR),
        {ok, #{
            binary => Bin,
            ir => IRBlocks,
            regmap => RegMap,
            spillmap => SpillMap,
            source_map => SourceMap
        }}
    else
        {error, Err} ->
            {error, #{
                raw => Err,
                formatted => ebl_error_format:format(Err),
                json => ebl_error_format:format_json(Err)
            }}
    end.

%% Build a source map from IR instruction locations.
%% Returns #{InstrIndex => {Line, Col}} for instructions that have loc set.
build_source_map(#ir_program{blocks = Blocks}) ->
    %% Flatten all blocks in order and collect loc from each instruction
    BlockList = lists:sort(
        fun(A, B) ->
            block_order(element(2, A)) =< block_order(element(2, B))
        end,
        maps:to_list(Blocks)
    ),
    {Map, _} = lists:foldl(
        fun({_Label, Block}, {Acc, Idx}) ->
            lists:foldl(
                fun(#ir_instr{loc = Loc}, {A, I}) ->
                    case Loc of
                        {L, C} when is_integer(L) ->
                            {A#{I => {L, C}}, I + 1};
                        _ ->
                            {A, I + 1}
                    end
                end,
                {Acc, Idx},
                Block#ir_block.instrs
            )
        end,
        {#{}, 0},
        BlockList
    ),
    Map.

block_order(entry) -> -1;
block_order({label, N}) -> N.

compile(Source, Opts) ->
    maybe
        {ok, Tokens} ?= ebl_lexer:tokenize(Source),
        {ok, AST} ?= ebl_parser:parse(Tokens),
        _ =
            case AST#program.type of
                xdp ->
                    ok;
                Other ->
                    io:format(
                        "Warning: ~p programs are deprecated, "
                        "only XDP is supported~n",
                        [Other]
                    )
            end,
        {ok, TypedAST} ?= ebl_typecheck:check(AST),
        IR = ebpf_ir_gen:generate(TypedAST),
        {RegMap, SpillMap} = ebpf_regalloc:allocate(IR),
        Bin = ebpf_codegen:codegen(IR, RegMap, SpillMap),
        Bin2 =
            case maps:get(peephole, Opts, true) of
                true -> ebpf_peephole:optimize(Bin);
                false -> Bin
            end,
        {ok, Bin2}
    else
        {error, _} = Err -> Err
    end.
