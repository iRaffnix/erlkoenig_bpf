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

%% @doc Tests for the uBPF port bridge (ebpf_ubpf).
-module(ebl_ubpf_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% Check if the ubpf_port binary is available.
port_available() ->
    try
        PortPath = filename:join(code:priv_dir(erlkoenig_ebpf), "ubpf_port"),
        filelib:is_file(PortPath)
    catch
        _:_ -> false
    end.

%% Helper: run a test function with a fresh port, skip if unavailable.
with_port(TestFun) ->
    case port_available() of
        false ->
            {skip, "ubpf_port not available"};
        true ->
            fun() ->
                {ok, Port} = ebpf_ubpf:start(),
                try
                    TestFun(Port)
                after
                    catch ebpf_ubpf:stop(Port)
                end
            end
    end.

%% Test 1: Port starts successfully.
start_test_() ->
    with_port(fun(Port) ->
        ?assert(is_port(Port))
    end).

%% Test 2: mov r0, 42; exit -> 42
mov_r0_42_test_() ->
    with_port(fun(Port) ->
        Code = ebpf_insn:assemble([
            ebpf_insn:mov64_imm(0, 42),
            ebpf_insn:exit_insn()
        ]),
        ?assertEqual(ok, ebpf_ubpf:load(Port, Code)),
        ?assertEqual({ok, 42}, ebpf_ubpf:run(Port, <<>>))
    end).

%% Test 3: XDP_PASS = 2
xdp_pass_test_() ->
    with_port(fun(Port) ->
        Code = ebpf_insn:assemble([
            ebpf_insn:mov64_imm(0, 2),
            ebpf_insn:exit_insn()
        ]),
        ?assertEqual(ok, ebpf_ubpf:load(Port, Code)),
        ?assertEqual({ok, 2}, ebpf_ubpf:run(Port, <<>>))
    end).

%% Test 4: Arithmetic: mov r0, 10; add r0, 32; exit -> 42
arithmetic_test_() ->
    with_port(fun(Port) ->
        Code = ebpf_insn:assemble([
            ebpf_insn:mov64_imm(0, 10),
            ebpf_insn:add64_imm(0, 32),
            ebpf_insn:exit_insn()
        ]),
        ?assertEqual(ok, ebpf_ubpf:load(Port, Code)),
        ?assertEqual({ok, 42}, ebpf_ubpf:run(Port, <<>>))
    end).

%% Test 5: Invalid bytecode -> error
invalid_bytecode_test_() ->
    with_port(fun(Port) ->
        Result = ebpf_ubpf:load(Port, <<16#DE, 16#AD>>),
        ?assertMatch({error, _}, Result)
    end).

%% Test 6: Reload program (LOAD replaces previous)
reload_program_test_() ->
    with_port(fun(Port) ->
        Code1 = ebpf_insn:assemble([
            ebpf_insn:mov64_imm(0, 1),
            ebpf_insn:exit_insn()
        ]),
        Code2 = ebpf_insn:assemble([
            ebpf_insn:mov64_imm(0, 99),
            ebpf_insn:exit_insn()
        ]),
        ?assertEqual(ok, ebpf_ubpf:load(Port, Code1)),
        ?assertEqual({ok, 1}, ebpf_ubpf:run(Port, <<>>)),
        %% Load new program, should replace old one
        ?assertEqual(ok, ebpf_ubpf:load(Port, Code2)),
        ?assertEqual({ok, 99}, ebpf_ubpf:run(Port, <<>>))
    end).

%% Test 7: Compile EBL source and run in uBPF
ebl_compile_test_() ->
    with_port(fun(Port) ->
        Src = <<
            "xdp test do\n"
            "  fn main(ctx) -> action do\n"
            "    return :pass\n"
            "  end\n"
            "end"
        >>,
        {ok, Code} = ebl_compile:compile(Src),
        ?assertEqual(ok, ebpf_ubpf:load(Port, Code)),
        {ok, Result} = ebpf_ubpf:run(Port, <<0:128>>),
        ?assertEqual(2, Result)
    end).
