%% ebpf_vm.hrl — VM state and instruction records for the pure Erlang BPF VM
-ifndef(EBPF_VM_HRL).
-define(EBPF_VM_HRL, true).

%% Decoded instruction (from ebpf_vm_decode)
-record(vm_insn, {
    op  :: atom() | {unknown, byte()},
    dst :: 0..10,
    src :: 0..10,
    off :: integer(),
    imm :: integer()
}).

%% Map metadata
-record(map_meta, {
    type        :: hash | array | lru_hash | percpu_hash |
                   percpu_array | ringbuf | prog_array,
    key_size    :: pos_integer(),
    val_size    :: pos_integer(),
    max_entries :: pos_integer()
}).

%% VM execution state
-record(vm_state, {
    regs          = #{} :: #{0..10 => integer()},
    pc            = 0   :: non_neg_integer(),
    stack         = <<0:(512*8)>> :: binary(),   %% 512 bytes, zero-init
    insns         :: array:array(#vm_insn{}),
    insn_count    = 0   :: non_neg_integer(),
    memory        = #{} :: #{atom() => binary()},  %% ctx, packet, stack, map_value
    maps          = #{} :: #{non_neg_integer() => ets:tid()},
    map_meta      = #{} :: #{non_neg_integer() => #map_meta{}},
    insn_limit    = 1000000 :: non_neg_integer(),
    insn_executed = 0   :: non_neg_integer(),
    trace         = false :: boolean(),
    trace_log     = []  :: [term()]
}).

%% Memory region base addresses
-define(VM_CTX_BASE,       16#10000000).
-define(VM_PACKET_BASE,    16#20000000).
-define(VM_STACK_BASE,     16#30000000).
-define(VM_MAP_VALUE_BASE, 16#40000000).

%% Stack size
-define(VM_STACK_SIZE, 512).

-endif. %% EBPF_VM_HRL
