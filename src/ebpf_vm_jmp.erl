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

-module(ebpf_vm_jmp).
-moduledoc "Jump condition evaluation for the BPF VM.".

-export([eval/4]).

-define(MASK32, 16#FFFFFFFF).

-doc "Evaluate a jump condition. Returns true if the branch should be taken.".
-spec eval(atom(), integer(), integer(), 64 | 32) -> boolean().
eval(Op, DstVal, SrcVal, Width) ->
    {A, B} =
        case Width of
            64 -> {DstVal, SrcVal};
            32 -> {DstVal band ?MASK32, SrcVal band ?MASK32}
        end,
    cmp(Op, A, B, Width).

cmp(jeq, A, B, _W) -> A =:= B;
%% unsigned
cmp(jgt, A, B, _W) -> A > B;
%% unsigned
cmp(jge, A, B, _W) -> A >= B;
cmp(jset, A, B, _W) -> (A band B) =/= 0;
cmp(jne, A, B, _W) -> A =/= B;
cmp(jsgt, A, B, W) -> to_signed(A, W) > to_signed(B, W);
cmp(jsge, A, B, W) -> to_signed(A, W) >= to_signed(B, W);
%% unsigned
cmp(jlt, A, B, _W) -> A < B;
%% unsigned
cmp(jle, A, B, _W) -> A =< B;
cmp(jslt, A, B, W) -> to_signed(A, W) < to_signed(B, W);
cmp(jsle, A, B, W) -> to_signed(A, W) =< to_signed(B, W).

to_signed(V, 64) when V >= (1 bsl 63) -> V - (1 bsl 64);
to_signed(V, 32) when V >= (1 bsl 31) -> V - (1 bsl 32);
to_signed(V, _) -> V.
