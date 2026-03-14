%% @doc Jump condition evaluation for the BPF VM.
-module(ebpf_vm_jmp).

-export([eval/4]).

-define(MASK32, 16#FFFFFFFF).

%% @doc Evaluate a jump condition. Returns true if the branch should be taken.
-spec eval(atom(), integer(), integer(), 64 | 32) -> boolean().
eval(Op, DstVal, SrcVal, Width) ->
    {A, B} = case Width of
        64 -> {DstVal, SrcVal};
        32 -> {DstVal band ?MASK32, SrcVal band ?MASK32}
    end,
    cmp(Op, A, B, Width).

cmp(jeq,  A, B, _W) -> A =:= B;
cmp(jgt,  A, B, _W) -> A > B;     %% unsigned
cmp(jge,  A, B, _W) -> A >= B;    %% unsigned
cmp(jset, A, B, _W) -> (A band B) =/= 0;
cmp(jne,  A, B, _W) -> A =/= B;
cmp(jsgt, A, B,  W) -> to_signed(A, W) > to_signed(B, W);
cmp(jsge, A, B,  W) -> to_signed(A, W) >= to_signed(B, W);
cmp(jlt,  A, B, _W) -> A < B;     %% unsigned
cmp(jle,  A, B, _W) -> A =< B;    %% unsigned
cmp(jslt, A, B,  W) -> to_signed(A, W) < to_signed(B, W);
cmp(jsle, A, B,  W) -> to_signed(A, W) =< to_signed(B, W).

to_signed(V, 64) when V >= (1 bsl 63) -> V - (1 bsl 64);
to_signed(V, 32) when V >= (1 bsl 31) -> V - (1 bsl 32);
to_signed(V, _) -> V.
