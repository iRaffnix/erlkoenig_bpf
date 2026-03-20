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

-module(ebpf_debugger_web).
-moduledoc """
Minimal HTTP server for the BPF visual debugger.

Zero dependencies -- uses gen_tcp directly. Serves the single-page
debugger frontend and provides a JSON API for compile/step/run/reset.
""".

-export([start/0, start/1, stop/0]).

-define(DEFAULT_PORT, 8080).

%% Session state stored in ETS
-record(session, {
    id :: binary(),
    %% #debug_state{} from ebpf_vm_debug
    debug_state :: term(),
    source :: binary(),
    source_map :: map(),
    disasm :: list(),
    map_specs :: list(),
    %% erlang:system_time(second)
    created :: integer()
}).

-doc "Start the debugger web server on port 8080.".
start() -> start(?DEFAULT_PORT).

-doc "Start the debugger web server on a given port.".
-spec start(pos_integer()) -> {ok, pid()}.
start(Port) ->
    _ = ets:new(debugger_sessions, [named_table, public, {keypos, #session.id}]),
    %% Long-lived process that owns debug session ETS map tables.
    %% HTTP handler processes are short-lived and would destroy tables on exit.
    OwnerPid = spawn_link(fun ets_owner_loop/0),
    register(ebpf_debugger_ets_owner, OwnerPid),
    Pid = spawn_link(fun() -> listen(Port) end),
    register(ebpf_debugger, Pid),
    io:format("~n=== EBL/BPF Debugger ===~n"),
    io:format("    http://localhost:~B~n~n", [Port]),
    {ok, Pid}.

-doc "Stop the debugger.".
stop() ->
    case whereis(ebpf_debugger) of
        undefined -> ok;
        Pid -> exit(Pid, shutdown)
    end,
    catch ets:delete(debugger_sessions),
    ok.

%%% ===================================================================
%%% ETS owner process — keeps map tables alive across HTTP requests
%%% ===================================================================

ets_owner_loop() ->
    receive
        {'ETS-TRANSFER', _Tab, _FromPid, debug_map} ->
            ets_owner_loop();
        {destroy_table, Tab} ->
            catch ets:delete(Tab),
            ets_owner_loop();
        stop ->
            ok
    end.

%%% ===================================================================
%%% TCP listener / acceptor
%%% ===================================================================

listen(Port) ->
    {ok, LSock} = gen_tcp:listen(Port, [
        binary,
        {active, false},
        {reuseaddr, true},
        {packet, http_bin},
        {backlog, 32}
    ]),
    accept_loop(LSock).

accept_loop(LSock) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    spawn(fun() -> handle_connection(Sock) end),
    accept_loop(LSock).

%%% ===================================================================
%%% HTTP request handling
%%% ===================================================================

handle_connection(Sock) ->
    case gen_tcp:recv(Sock, 0, 10000) of
        {ok, {http_request, Method, {abs_path, Path}, _Vsn}} ->
            Headers = recv_headers(Sock, []),
            ContentLength = proplists:get_value('Content-Length', Headers, <<"0">>),
            CL = binary_to_integer(ContentLength),
            Body =
                case CL > 0 of
                    true ->
                        ok = inet:setopts(Sock, [{packet, raw}]),
                        {ok, B} = gen_tcp:recv(Sock, CL, 5000),
                        B;
                    false ->
                        <<>>
                end,
            {Status, RespHeaders, RespBody} = route(Method, Path, Body),
            ok = send_response(Sock, Status, RespHeaders, RespBody),
            gen_tcp:close(Sock);
        _ ->
            gen_tcp:close(Sock)
    end.

recv_headers(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, {http_header, _, Key, _, Value}} ->
            recv_headers(Sock, [{Key, Value} | Acc]);
        {ok, http_eoh} ->
            Acc;
        _ ->
            Acc
    end.

send_response(Sock, Status, Headers, Body) ->
    StatusLine = io_lib:format("HTTP/1.1 ~B ~s\r\n", [Status, status_text(Status)]),
    AllHeaders = [
        {<<"Content-Length">>, integer_to_binary(byte_size(Body))},
        {<<"Connection">>, <<"close">>}
        | Headers
    ],
    HeaderLines = [[K, <<": ">>, V, <<"\r\n">>] || {K, V} <- AllHeaders],
    ok = inet:setopts(Sock, [{packet, raw}]),
    ok = gen_tcp:send(Sock, [StatusLine, HeaderLines, <<"\r\n">>, Body]).

status_text(200) -> <<"OK">>;
status_text(404) -> <<"Not Found">>;
status_text(500) -> <<"Internal Server Error">>.

%%% ===================================================================
%%% Router
%%% ===================================================================

route('GET', <<"/">>, _Body) ->
    serve_static(<<"index.html">>);
route('GET', <<"/static/", File/binary>>, _Body) ->
    serve_static(File);
route('POST', <<"/api/compile">>, Body) ->
    api_compile(Body);
route('POST', <<"/api/init">>, Body) ->
    api_init(Body);
route('POST', <<"/api/step">>, Body) ->
    api_step(Body);
route('POST', <<"/api/run">>, Body) ->
    api_run(Body);
route('POST', <<"/api/reset">>, Body) ->
    api_reset(Body);
route('POST', <<"/api/run_to_breakpoint">>, Body) ->
    api_run_to_breakpoint(Body);
route('GET', <<"/api/examples">>, _Body) ->
    api_examples();
route('GET', <<"/api/example/", Name/binary>>, _Body) ->
    api_load_example(Name);
route('POST', <<"/api/check">>, Body) ->
    api_check(Body);
route(_, _, _) ->
    {404, [{<<"Content-Type">>, <<"application/json">>}], encode_json(#{error => <<"not found">>})}.

%%% ===================================================================
%%% API handlers
%%% ===================================================================

api_compile(Body) ->
    try
        Params = decode_json(Body),
        Source = maps:get(<<"source">>, Params),
        Language = maps:get(<<"language">>, Params, <<"ebl">>),
        CompileResult =
            case Language of
                <<"elixir">> -> compile_elixir_debug(Source);
                _ -> ebl_compile:compile_debug(Source)
            end,
        case CompileResult of
            {ok, #{binary := Bin, ir := IRBlocks}} ->
                Disasm = ebpf_disasm:disassemble_explained(Bin),
                DisasmList = [
                    #{
                        pc => PC,
                        text => Text,
                        explain_short => maps:get(short, Expl),
                        explain_detail => maps:get(detail, Expl),
                        explain_category => maps:get(category, Expl)
                    }
                 || {PC, Text, Expl} <- Disasm
                ],
                MapSpecs = extract_map_specs(Source),
                json_ok(#{
                    instructions => DisasmList,
                    insn_count => length(DisasmList),
                    ir => format_ir_blocks(IRBlocks),
                    map_specs => format_map_specs(MapSpecs)
                });
            {error, Err} ->
                json_ok(format_compile_error(Err))
        end
    catch
        C:E:St ->
            json_error(io_lib:format("~p:~p ~p", [C, E, St]))
    end.

api_init(Body) ->
    try
        Params = decode_json(Body),
        Source = maps:get(<<"source">>, Params),
        Language = maps:get(<<"language">>, Params, <<"ebl">>),
        PacketHex = maps:get(<<"packet_hex">>, Params, <<>>),
        Packet = hex_to_bin(PacketHex),
        CompileResult =
            case Language of
                <<"elixir">> -> compile_elixir_debug(Source);
                _ -> ebl_compile:compile_debug(Source)
            end,
        case CompileResult of
            {ok, #{binary := Bin, ir := IRBlocks} = DebugInfo} ->
                MapSpecs = extract_map_specs(Source),
                SourceMap = maps:get(source_map, DebugInfo, #{}),
                Ctx = ebpf_test_pkt:xdp_ctx(Packet),
                Owner = whereis(ebpf_debugger_ets_owner),
                {ok, DS} = ebpf_vm_debug:init(Bin, Ctx, MapSpecs, Owner),
                Disasm = ebpf_disasm:disassemble_explained(Bin),
                DisasmList = [
                    #{
                        pc => PC,
                        text => Text,
                        explain_short => maps:get(short, Expl),
                        explain_detail => maps:get(detail, Expl),
                        explain_category => maps:get(category, Expl)
                    }
                 || {PC, Text, Expl} <- Disasm
                ],
                SessionId = gen_session_id(),
                Session = #session{
                    id = SessionId,
                    debug_state = DS,
                    source = Source,
                    source_map = SourceMap,
                    disasm = DisasmList,
                    map_specs = MapSpecs,
                    created = erlang:system_time(second)
                },
                ets:insert(debugger_sessions, Session),
                State = ebpf_vm_debug:get_state(DS),
                json_ok(#{
                    session_id => SessionId,
                    instructions => DisasmList,
                    ir => format_ir_blocks(IRBlocks),
                    state => State,
                    source_map => format_source_map(SourceMap),
                    map_specs => format_map_specs(MapSpecs)
                });
            {error, Err} ->
                json_ok(format_compile_error(Err))
        end
    catch
        C:E:St ->
            json_error(io_lib:format("~p:~p ~p", [C, E, St]))
    end.

api_step(Body) ->
    with_session(Body, fun(Session) ->
        DS = ebpf_vm_debug:step(Session#session.debug_state),
        ets:insert(debugger_sessions, Session#session{debug_state = DS}),
        json_ok(#{state => ebpf_vm_debug:get_state(DS)})
    end).

api_run(Body) ->
    with_session(Body, fun(Session) ->
        DS = ebpf_vm_debug:run_to_end(Session#session.debug_state),
        ets:insert(debugger_sessions, Session#session{debug_state = DS}),
        json_ok(#{state => ebpf_vm_debug:get_state(DS)})
    end).

api_reset(Body) ->
    with_session(Body, fun(Session) ->
        %% Destroy old map tables
        ebpf_vm_debug:destroy(Session#session.debug_state),
        Source = Session#session.source,
        Params = decode_json(Body),
        PacketHex = maps:get(<<"packet_hex">>, Params, <<>>),
        Packet = hex_to_bin(PacketHex),
        MapSpecs = Session#session.map_specs,
        {ok, #{binary := Bin}} = ebl_compile:compile_debug(Source),
        Ctx = ebpf_test_pkt:xdp_ctx(Packet),
        Owner = whereis(ebpf_debugger_ets_owner),
        {ok, DS} = ebpf_vm_debug:init(Bin, Ctx, MapSpecs, Owner),
        ets:insert(debugger_sessions, Session#session{debug_state = DS}),
        json_ok(#{state => ebpf_vm_debug:get_state(DS)})
    end).

api_run_to_breakpoint(Body) ->
    with_session(Body, fun(Session) ->
        Params = decode_json(Body),
        BPList = maps:get(<<"breakpoints">>, Params, []),
        BPs = sets:from_list(BPList, [{version, 2}]),
        DS = ebpf_vm_debug:run_to_breakpoint(Session#session.debug_state, BPs),
        ets:insert(debugger_sessions, Session#session{debug_state = DS}),
        json_ok(#{state => ebpf_vm_debug:get_state(DS)})
    end).

api_examples() ->
    ExDir = "examples",
    case file:list_dir(ExDir) of
        {ok, Files} ->
            EblFiles = lists:sort([
                list_to_binary(F)
             || F <- Files,
                filename:extension(F) =:= ".ebl"
            ]),
            json_ok(#{examples => EblFiles});
        {error, _} ->
            json_ok(#{examples => []})
    end.

api_load_example(Name) ->
    %% Prevent directory traversal
    SafeName = filename:basename(binary_to_list(Name)),
    Path = filename:join("examples", SafeName),
    case file:read_file(Path) of
        {ok, Content} ->
            json_ok(#{source => Content});
        {error, _} ->
            json_ok(#{error => <<"example not found">>})
    end.

api_check(Body) ->
    try
        Params = decode_json(Body),
        Source = maps:get(<<"source">>, Params),
        maybe
            {ok, Tokens} ?= ebl_lexer:tokenize(Source),
            {ok, AST} ?= ebl_parser:parse(Tokens),
            {ok, _} ?= ebl_typecheck:check(AST),
            json_ok(#{status => <<"ok">>, errors => []})
        else
            {error, Errs} when is_list(Errs) ->
                ErrList = [ebl_error_format:format_json(E) || E <- Errs],
                json_ok(#{
                    status => <<"error">>,
                    phase => <<"typecheck">>,
                    errors => ErrList
                });
            {error, Err} ->
                %% Lex or parse error (single error, not a list)
                json_ok(#{
                    status => <<"error">>,
                    phase => <<"compile">>,
                    errors => [ebl_error_format:format_json(Err)]
                })
        end
    catch
        C:E:St ->
            json_error(io_lib:format("~p:~p ~p", [C, E, St]))
    end.

%%% ===================================================================
%%% Elixir DSL compilation
%%% ===================================================================

%% Compile Elixir DSL source to debug artifacts.
%% Delegates to the Elixir DSL module which evaluates the code and
%% compiles through the standard pipeline.
-dialyzer({nowarn_function, compile_elixir_debug/1}).
compile_elixir_debug(Source) ->
    try
        'Elixir.ErlkoenigEbpfDsl':compile_debug_string(Source)
    catch
        C:E ->
            Msg = iolist_to_binary(io_lib:format("~p:~p", [C, E])),
            {error, #{
                formatted => Msg,
                json => #{
                    message => Msg,
                    line => 0,
                    col => 0,
                    phase => <<"elixir">>
                }
            }}
    end.

%%% ===================================================================
%%% Session helpers
%%% ===================================================================

with_session(Body, Fun) ->
    try
        Params = decode_json(Body),
        SessionId = maps:get(<<"session_id">>, Params),
        case ets:lookup(debugger_sessions, SessionId) of
            [Session] -> Fun(Session);
            [] -> json_ok(#{error => <<"session not found">>})
        end
    catch
        C:E:St ->
            json_error(io_lib:format("~p:~p ~p", [C, E, St]))
    end.

gen_session_id() ->
    Bytes = crypto:strong_rand_bytes(16),
    iolist_to_binary([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bytes]).

%%% ===================================================================
%%% Static file serving
%%% ===================================================================

serve_static(File) ->
    %% Prevent directory traversal
    SafeFile = filename:basename(binary_to_list(File)),
    DocRoot = filename:join(code:priv_dir(erlkoenig_ebpf), "debugger"),
    Path = filename:join(DocRoot, SafeFile),
    case file:read_file(Path) of
        {ok, Content} ->
            CT = content_type(SafeFile),
            {200, [{<<"Content-Type">>, CT}], Content};
        {error, _} ->
            {404, [{<<"Content-Type">>, <<"text/plain">>}], <<"not found">>}
    end.

content_type(File) ->
    case filename:extension(File) of
        ".html" -> <<"text/html; charset=utf-8">>;
        ".css" -> <<"text/css">>;
        ".js" -> <<"application/javascript">>;
        ".json" -> <<"application/json">>;
        ".svg" -> <<"image/svg+xml">>;
        _ -> <<"application/octet-stream">>
    end.

%%% ===================================================================
%%% JSON encoding/decoding — delegates to OTP 28 stdlib json module
%%% ===================================================================

encode_json(Term) ->
    iolist_to_binary(json:encode(prepare_for_json(Term))).

decode_json(Bin) ->
    json:decode(Bin).

%% Prepare Erlang terms for json:encode/1 (atoms → binaries, undefined → null).
prepare_for_json(M) when is_map(M) ->
    maps:fold(
        fun(K, V, Acc) ->
            Key =
                case is_atom(K) of
                    true -> atom_to_binary(K, utf8);
                    false -> K
                end,
            Acc#{Key => prepare_for_json(V)}
        end,
        #{},
        M
    );
prepare_for_json(L) when is_list(L) ->
    [prepare_for_json(E) || E <- L];
prepare_for_json(undefined) ->
    null;
prepare_for_json(A) when is_atom(A) ->
    A;
prepare_for_json(V) ->
    V.

%%% ===================================================================
%%% JSON response helpers
%%% ===================================================================

json_ok(Data) ->
    {200,
        [
            {<<"Content-Type">>, <<"application/json">>},
            {<<"Access-Control-Allow-Origin">>, <<"*">>}
        ],
        encode_json(Data)}.

json_error(Msg) ->
    {500, [{<<"Content-Type">>, <<"application/json">>}],
        encode_json(#{error => iolist_to_binary(Msg)})}.

%%% ===================================================================
%%% Map spec extraction from source
%%% ===================================================================

extract_map_specs(Source) ->
    Lines = binary:split(Source, <<"\n">>, [global]),
    lists:filtermap(
        fun(Line) ->
            Trimmed = string:trim(Line),
            case binary:match(Trimmed, <<"map :">>) of
                {0, _} ->
                    parse_map_line(Trimmed);
                _ ->
                    case binary:match(Trimmed, <<"map :">>) of
                        nomatch -> false;
                        _ -> parse_map_line(Trimmed)
                    end
            end
        end,
        Lines
    ).

parse_map_line(Line) ->
    try
        %% Extract key size, value size, max_entries from map declaration
        %% Format: map :name, type, key: typeK, value: typeV, max_entries: N
        KS = type_size(extract_field(Line, <<"key:">>)),
        VS = type_size(extract_field(Line, <<"value:">>)),
        ME = extract_int_field(Line, <<"max_entries:">>),
        {true, {hash, KS, VS, ME}}
    catch
        _:_ ->
            false
    end.

extract_field(Line, Prefix) ->
    case binary:split(Line, Prefix) of
        [_, Rest] ->
            Trimmed = string:trim(Rest, leading),
            case binary:split(Trimmed, <<",">>) of
                [Field, _] -> string:trim(Field);
                [Field] -> string:trim(Field)
            end;
        _ ->
            error(not_found)
    end.

extract_int_field(Line, Prefix) ->
    Val = extract_field(Line, Prefix),
    binary_to_integer(string:trim(Val)).

type_size(<<"u8">>) -> 1;
type_size(<<"u16">>) -> 2;
type_size(<<"u32">>) -> 4;
type_size(<<"u64">>) -> 8;
type_size(<<"i8">>) -> 1;
type_size(<<"i16">>) -> 2;
type_size(<<"i32">>) -> 4;
type_size(<<"i64">>) -> 8;
type_size(_) -> 4.

format_ir_blocks(Blocks) ->
    lists:map(
        fun(#{label := Label, instrs := Instrs, term := Term}) ->
            #{
                label => Label,
                instrs => Instrs,
                term => Term
            }
        end,
        Blocks
    ).

format_map_specs(Specs) ->
    lists:map(
        fun({Type, KS, VS, ME}) ->
            #{type => Type, key_size => KS, val_size => VS, max_entries => ME}
        end,
        Specs
    ).

format_compile_error(#{formatted := Formatted, json := Json}) ->
    #{
        error => iolist_to_binary(Formatted),
        error_detail => Json
    };
format_compile_error(Err) ->
    #{error => iolist_to_binary(io_lib:format("~p", [Err]))}.

format_source_map(Map) when is_map(Map) ->
    maps:fold(
        fun(PC, {L, C}, Acc) ->
            Acc#{integer_to_binary(PC) => #{line => L, col => C}}
        end,
        #{},
        Map
    ).

%%% ===================================================================
%%% Hex conversion
%%% ===================================================================

hex_to_bin(<<>>) ->
    <<>>;
hex_to_bin(HexStr) ->
    Cleaned = binary:replace(HexStr, [<<" ">>, <<"\n">>, <<"\r">>], <<>>, [global]),
    hex_decode(Cleaned, <<>>).

hex_decode(<<>>, Acc) ->
    Acc;
hex_decode(<<Hi, Lo, Rest/binary>>, Acc) ->
    Byte = (hex_digit(Hi) bsl 4) bor hex_digit(Lo),
    hex_decode(Rest, <<Acc/binary, Byte>>).

hex_digit(C) when C >= $0, C =< $9 -> C - $0;
hex_digit(C) when C >= $a, C =< $f -> C - $a + 10;
hex_digit(C) when C >= $A, C =< $F -> C - $A + 10.
