defmodule ErlkoenigEbpfDsl.Builder do
  @moduledoc """
  Translates Elixir AST into EBL AST tuples for the Erlang compiler pipeline.
  """

  @type state :: %{
    name: binary(),
    maps: [tuple()],
    types: [tuple()],
    consts: [tuple()],
    fns: [tuple()],
    main: tuple() | nil
  }

  @loc {0, 0}

  def new(name) when is_binary(name), do: %{name: name, maps: [], types: [], consts: [], fns: [], main: nil}
  def new(name) when is_atom(name), do: new(Atom.to_string(name))

  def add_map(state, name, kind, opts) do
    map_decl = {:map_decl, to_bin(name), kind,
                type_expr(opts[:key]), type_expr(opts[:value]),
                opts[:max_entries], @loc}
    %{state | maps: state.maps ++ [map_decl]}
  end

  def set_main(state, quoted_body, opts \\ []) do
    auto_bounds = Keyword.get(opts, :auto_bounds, true)
    stmts = translate_block(quoted_body)

    stmts = if auto_bounds do
      maybe_insert_bounds_check(quoted_body, stmts)
    else
      stmts
    end

    fn_decl = {:fn_decl, "main",
               [{"ctx", :undefined}],
               {:prim, :action}, stmts, @loc}
    %{state | main: fn_decl}
  end

  @doc """
  Set main with protocol-level abstraction.
  Generates data bindings, bounds check, protocol guards, and field bindings.
  The user's block runs only when the protocol matches; non-matching → :pass.
  """
  def set_main_protocol(state, protocol, quoted_body) do
    user_stmts = translate_block(quoted_body)
    preamble = protocol_preamble(protocol)
    all_stmts = wrap_with_preamble(preamble, user_stmts)

    fn_decl = {:fn_decl, "main",
               [{"ctx", :undefined}],
               {:prim, :action}, all_stmts, @loc}
    %{state | main: fn_decl}
  end

  def to_ast(%{main: nil}), do: raise("No main function defined")
  def to_ast(state) do
    {:program, :xdp, to_bin(state.name), :undefined,
     state.types, Enum.reverse(state.maps), state.consts,
     state.fns ++ [state.main]}
  end

  # ── Type expressions ──

  defp type_expr(:u8), do: {:prim, :u8}
  defp type_expr(:u16), do: {:prim, :u16}
  defp type_expr(:u32), do: {:prim, :u32}
  defp type_expr(:u64), do: {:prim, :u64}
  defp type_expr(:i8), do: {:prim, :i8}
  defp type_expr(:i16), do: {:prim, :i16}
  defp type_expr(:i32), do: {:prim, :i32}
  defp type_expr(:i64), do: {:prim, :i64}
  defp type_expr(:bool), do: {:prim, :bool}
  defp type_expr(:action), do: {:prim, :action}
  defp type_expr(name) when is_atom(name), do: {:named, to_bin(name)}
  defp type_expr(name) when is_binary(name), do: {:named, name}

  # ── Block translation ──

  defp translate_block({:__block__, _, stmts}), do: Enum.map(stmts, &translate_stmt/1)
  defp translate_block(single), do: [translate_stmt(single)]

  # ── Statement translation ──

  defp translate_stmt({:=, _meta, [{name, _, ctx}, expr]}) when is_atom(name) and is_atom(ctx) do
    {:let_stmt, {:var_pat, to_bin(name)}, translate_expr(expr), @loc}
  end

  defp translate_stmt({:if, _meta, [cond_expr, branches]}) do
    then_block = translate_block(Keyword.get(branches, :do, nil))
    else_block = case Keyword.get(branches, :else) do
      nil -> []
      block -> translate_block(block)
    end
    {:if_stmt, translate_expr(cond_expr), then_block, [], else_block, @loc}
  end

  defp translate_stmt({:for, _meta, [{:<-, _, [{var, _, ctx}, {:.., _, [from, to]}]}, [do: body]]}) when is_atom(var) and is_atom(ctx) do
    {:for_stmt, to_bin(var), translate_expr(from), translate_expr(to),
     translate_block(body), @loc}
  end

  defp translate_stmt({:case, _meta, [expr, [do: arms]]}) do
    translated_arms = Enum.map(arms, fn {:->, _, [[pattern], body]} ->
      {translate_pattern(pattern), translate_block(body)}
    end)
    {:match_stmt, translate_expr(expr), translated_arms, @loc}
  end

  defp translate_stmt(:pass), do: {:return_stmt, {:atom_lit, "pass", @loc}, @loc}
  defp translate_stmt(:drop), do: {:return_stmt, {:atom_lit, "drop", @loc}, @loc}
  defp translate_stmt(:tx), do: {:return_stmt, {:atom_lit, "tx", @loc}, @loc}
  defp translate_stmt(:aborted), do: {:return_stmt, {:atom_lit, "aborted", @loc}, @loc}

  defp translate_stmt({:return, _meta, [expr]}) do
    {:return_stmt, translate_expr(expr), @loc}
  end

  defp translate_stmt(expr) do
    {:expr_stmt, translate_expr(expr), @loc}
  end

  # ── Expression translation ──

  defp translate_expr(n) when is_integer(n), do: {:integer_lit, n, @loc}
  defp translate_expr(true), do: {:bool_lit, true, @loc}
  defp translate_expr(false), do: {:bool_lit, false, @loc}
  defp translate_expr(:pass), do: {:atom_lit, "pass", @loc}
  defp translate_expr(:drop), do: {:atom_lit, "drop", @loc}
  defp translate_expr(:tx), do: {:atom_lit, "tx", @loc}
  defp translate_expr(:redirect), do: {:atom_lit, "redirect", @loc}
  defp translate_expr(:aborted), do: {:atom_lit, "aborted", @loc}

  defp translate_expr({name, _meta, ctx}) when is_atom(name) and is_atom(ctx) do
    {:var, to_bin(name), @loc}
  end

  # Field access: obj.field
  defp translate_expr({{:., _, [obj, field]}, _meta, []}) when is_atom(field) do
    {:field_access, translate_expr(obj), to_bin(field), @loc}
  end

  # Function call
  defp translate_expr({name, _meta, args}) when is_atom(name) and is_list(args) do
    case classify_call(name) do
      {:binop, op} ->
        [left, right] = args
        {:binop, op, translate_expr(left), translate_expr(right), @loc}
      {:unop, op} ->
        [arg] = args
        {:unop, op, translate_expr(arg), @loc}
      :call ->
        {:call, to_bin(name), Enum.map(args, &translate_expr/1), @loc}
    end
  end

  defp translate_expr(other) do
    raise "Unsupported expression in DSL: #{inspect(other)}"
  end

  # ── Pattern translation ──

  defp translate_pattern({:_, _, _}), do: {:wildcard}
  defp translate_pattern(n) when is_integer(n), do: {:lit_pat, n}
  defp translate_pattern(true), do: {:lit_pat, true}
  defp translate_pattern(false), do: {:lit_pat, false}
  defp translate_pattern({name, _, ctx}) when is_atom(name) and is_atom(ctx), do: {:var_pat, to_bin(name)}

  # ── Auto bounds check ──

  @read_sizes %{
    :read_u8 => 1, :read_u16 => 2, :read_u32 => 4,
    :read_u16_be => 2, :read_u32_be => 4
  }

  # Find user's `data = ctx.data` and `data_end = ctx.data_end` bindings,
  # scan for read_* calls to compute min packet length, and insert a
  # bounds check right after the data_end binding.
  # Does nothing if there are no read_* calls or no data/data_end bindings.
  defp maybe_insert_bounds_check(quoted_body, translated_stmts) do
    min_len = scan_min_packet_length(quoted_body)
    if min_len == 0, do: translated_stmts, else: insert_after_data_end(translated_stmts, min_len)
  end

  defp insert_after_data_end([], _min_len), do: []

  defp insert_after_data_end(
    [{:let_stmt, {:var_pat, "data_end"}, _, _} = data_end_stmt | rest],
    min_len
  ) do
    bounds_check =
      {:if_stmt,
       {:binop, :>, {:binop, :+, {:var, "data", @loc}, {:integer_lit, min_len, @loc}, @loc},
        {:var, "data_end", @loc}, @loc},
       [{:return_stmt, {:atom_lit, "pass", @loc}, @loc}],
       [], [], @loc}

    [data_end_stmt, bounds_check | rest]
  end

  defp insert_after_data_end([stmt | rest], min_len) do
    [stmt | insert_after_data_end(rest, min_len)]
  end

  # Walk quoted Elixir AST to find all read_* calls and return the
  # minimum packet length needed (max of offset + read_size).
  defp scan_min_packet_length(ast), do: scan_reads(ast, 0)

  defp scan_reads({func, _, args}, acc) when is_atom(func) and is_list(args) do
    acc = case Map.get(@read_sizes, func) do
      nil -> acc
      size ->
        case args do
          [_, offset] when is_integer(offset) -> max(acc, offset + size)
          _ -> acc
        end
    end
    Enum.reduce(args, acc, &scan_reads/2)
  end

  defp scan_reads({_, _, children}, acc) when is_list(children) do
    Enum.reduce(children, acc, &scan_reads/2)
  end

  defp scan_reads({a, b}, acc), do: scan_reads(b, scan_reads(a, acc))

  defp scan_reads(list, acc) when is_list(list) do
    Enum.reduce(list, acc, &scan_reads/2)
  end

  defp scan_reads(_other, acc), do: acc

  # ── Protocol preambles ──
  # Each returns {min_bytes, guard_stmts, field_bindings}
  # guard_stmts: [{condition, early_return_action}]
  # field_bindings: [{var_name, read_func, offset}]

  defp protocol_preamble(:ipv4) do
    {34, # ETH(14) + IP(20)
     [{:!=, "ethertype", 0x0800}],
     [
       {"ethertype",    :read_u16_be, 12},
       {"src_ip",       :read_u32_be, 26},
       {"dst_ip",       :read_u32_be, 30},
       {"protocol",     :read_u8,     23},
       {"ttl",          :read_u8,     22},
       {"total_length", :read_u16_be, 16}
     ]}
  end

  defp protocol_preamble(:tcp) do
    {54, # ETH(14) + IP(20) + TCP(20)
     [{:!=, "ethertype", 0x0800}, {:!=, "protocol", 6}],
     [
       {"ethertype",    :read_u16_be, 12},
       {"protocol",     :read_u8,     23},
       {"src_ip",       :read_u32_be, 26},
       {"dst_ip",       :read_u32_be, 30},
       {"ttl",          :read_u8,     22},
       {"total_length", :read_u16_be, 16},
       {"src_port",     :read_u16_be, 34},
       {"dst_port",     :read_u16_be, 36},
       {"flags",        :read_u8,     47},
       # syn? = (flags & 0x02) != 0  — encoded as helper vars
       {"is_syn",       {:flag, 0x02}},
       {"is_ack",       {:flag, 0x10}},
       {"is_fin",       {:flag, 0x01}},
       {"is_rst",       {:flag, 0x04}}
     ]}
  end

  defp protocol_preamble(:udp) do
    {42, # ETH(14) + IP(20) + UDP(8)
     [{:!=, "ethertype", 0x0800}, {:!=, "protocol", 17}],
     [
       {"ethertype",    :read_u16_be, 12},
       {"protocol",     :read_u8,     23},
       {"src_ip",       :read_u32_be, 26},
       {"dst_ip",       :read_u32_be, 30},
       {"ttl",          :read_u8,     22},
       {"total_length", :read_u16_be, 16},
       {"src_port",     :read_u16_be, 34},
       {"dst_port",     :read_u16_be, 36},
       {"udp_length",   :read_u16_be, 38}
     ]}
  end

  defp protocol_preamble(:icmp) do
    {42, # ETH(14) + IP(20) + ICMP(8)
     [{:!=, "ethertype", 0x0800}, {:!=, "protocol", 1}],
     [
       {"ethertype",    :read_u16_be, 12},
       {"protocol",     :read_u8,     23},
       {"src_ip",       :read_u32_be, 26},
       {"dst_ip",       :read_u32_be, 30},
       {"ttl",          :read_u8,     22},
       {"total_length", :read_u16_be, 16},
       {"icmp_type",    :read_u8,     34},
       {"icmp_code",    :read_u8,     35}
     ]}
  end

  defp protocol_preamble(:ipv6) do
    {54, # ETH(14) + IPv6(40)
     [{:!=, "ethertype", 0x86DD}],
     [
       {"ethertype",      :read_u16_be, 12},
       {"next_header",    :read_u8,     20},
       {"hop_limit",      :read_u8,     21},
       {"payload_length", :read_u16_be, 18},
       {"src_ip6_hi",     :read_u32_be, 22},
       {"src_ip6_lo",     :read_u32_be, 34},
       {"dst_ip6_hi",     :read_u32_be, 38},
       {"dst_ip6_lo",     :read_u32_be, 50}
     ]}
  end

  defp protocol_preamble(:tcp6) do
    {74, # ETH(14) + IPv6(40) + TCP(20)
     [{:!=, "ethertype", 0x86DD}, {:!=, "next_header", 6}],
     [
       {"ethertype",      :read_u16_be, 12},
       {"next_header",    :read_u8,     20},
       {"hop_limit",      :read_u8,     21},
       {"payload_length", :read_u16_be, 18},
       {"src_ip6_hi",     :read_u32_be, 22},
       {"src_ip6_lo",     :read_u32_be, 34},
       {"dst_ip6_hi",     :read_u32_be, 38},
       {"dst_ip6_lo",     :read_u32_be, 50},
       {"src_port",       :read_u16_be, 54},
       {"dst_port",       :read_u16_be, 56},
       {"flags",          :read_u8,     67},
       {"is_syn",         {:flag, 0x02}},
       {"is_ack",         {:flag, 0x10}},
       {"is_fin",         {:flag, 0x01}},
       {"is_rst",         {:flag, 0x04}}
     ]}
  end

  defp protocol_preamble(:udp6) do
    {62, # ETH(14) + IPv6(40) + UDP(8)
     [{:!=, "ethertype", 0x86DD}, {:!=, "next_header", 17}],
     [
       {"ethertype",      :read_u16_be, 12},
       {"next_header",    :read_u8,     20},
       {"hop_limit",      :read_u8,     21},
       {"payload_length", :read_u16_be, 18},
       {"src_ip6_hi",     :read_u32_be, 22},
       {"src_ip6_lo",     :read_u32_be, 34},
       {"dst_ip6_hi",     :read_u32_be, 38},
       {"dst_ip6_lo",     :read_u32_be, 50},
       {"src_port",       :read_u16_be, 54},
       {"dst_port",       :read_u16_be, 56},
       {"udp_length",     :read_u16_be, 58}
     ]}
  end

  defp protocol_preamble(:arp) do
    {42, # ETH(14) + ARP(28)
     [{:!=, "ethertype", 0x0806}],
     [
       {"ethertype",      :read_u16_be, 12},
       {"arp_op",         :read_u16_be, 20},
       {"sender_ip",      :read_u32_be, 28},
       {"target_ip",      :read_u32_be, 38},
       {"sender_mac_hi",  :read_u32_be, 22},
       {"sender_mac_lo",  :read_u16_be, 26},
       {"target_mac_hi",  :read_u32_be, 32},
       {"target_mac_lo",  :read_u16_be, 36}
     ]}
  end

  defp protocol_preamble(:vlan_ipv4) do
    {38, # ETH(14) + VLAN(4) + IPv4(20)
     [{:!=, "outer_ethertype", 0x8100}, {:!=, "ethertype", 0x0800}],
     [
       {"outer_ethertype", :read_u16_be, 12},
       {"vlan_tci",        :read_u16_be, 14},
       {"ethertype",       :read_u16_be, 16},
       {"protocol",        :read_u8,     27},
       {"ttl",             :read_u8,     26},
       {"total_length",    :read_u16_be, 20},
       {"src_ip",          :read_u32_be, 30},
       {"dst_ip",          :read_u32_be, 34}
     ]}
  end

  defp protocol_preamble(:vlan_tcp) do
    {58, # ETH(14) + VLAN(4) + IPv4(20) + TCP(20)
     [{:!=, "outer_ethertype", 0x8100}, {:!=, "ethertype", 0x0800}, {:!=, "protocol", 6}],
     [
       {"outer_ethertype", :read_u16_be, 12},
       {"vlan_tci",        :read_u16_be, 14},
       {"ethertype",       :read_u16_be, 16},
       {"protocol",        :read_u8,     27},
       {"ttl",             :read_u8,     26},
       {"total_length",    :read_u16_be, 20},
       {"src_ip",          :read_u32_be, 30},
       {"dst_ip",          :read_u32_be, 34},
       {"src_port",        :read_u16_be, 38},
       {"dst_port",        :read_u16_be, 40},
       {"flags",           :read_u8,     51},
       {"is_syn",          {:flag, 0x02}},
       {"is_ack",          {:flag, 0x10}},
       {"is_fin",          {:flag, 0x01}},
       {"is_rst",          {:flag, 0x04}}
     ]}
  end

  defp protocol_preamble(:dns) do
    {54, # ETH(14) + IPv4(20) + UDP(8) + DNS(12)
     [{:!=, "ethertype", 0x0800}, {:!=, "protocol", 17},
      {:both_ne, "src_port", "dst_port", 53}],
     [
       {"ethertype",    :read_u16_be, 12},
       {"protocol",     :read_u8,     23},
       {"src_ip",       :read_u32_be, 26},
       {"dst_ip",       :read_u32_be, 30},
       {"ttl",          :read_u8,     22},
       {"total_length", :read_u16_be, 16},
       {"src_port",     :read_u16_be, 34},
       {"dst_port",     :read_u16_be, 36},
       {"dns_id",       :read_u16_be, 42},
       {"dns_flags",    :read_u16_be, 44},
       {"dns_qcount",   :read_u16_be, 46},
       {"dns_acount",   :read_u16_be, 48}
     ]}
  end

  # Build the full statement list: data bindings + bounds check + guards + field reads + user code
  defp wrap_with_preamble({min_bytes, guards, fields}, user_stmts) do
    pass = {:return_stmt, {:atom_lit, "pass", @loc}, @loc}

    # 1. data = ctx.data, data_end = ctx.data_end
    data_bindings = [
      {:let_stmt, {:var_pat, "data"},
       {:field_access, {:var, "ctx", @loc}, "data", @loc}, @loc},
      {:let_stmt, {:var_pat, "data_end"},
       {:field_access, {:var, "ctx", @loc}, "data_end", @loc}, @loc}
    ]

    # 2. if data + min_bytes > data_end do return :pass end
    bounds_check = [
      {:if_stmt,
       {:binop, :>, {:binop, :+, {:var, "data", @loc}, {:integer_lit, min_bytes, @loc}, @loc},
        {:var, "data_end", @loc}, @loc},
       [pass], [], [], @loc}
    ]

    # 3. Field reads (only real reads, not flag helpers)
    {read_stmts, flag_stmts} =
      Enum.reduce(fields, {[], []}, fn
        {name, {:flag, mask}}, {reads, flags} ->
          # syn? = (flags & 0x02) != 0
          flag_expr = {:binop, :!=,
            {:binop, :&, {:var, "flags", @loc}, {:integer_lit, mask, @loc}, @loc},
            {:integer_lit, 0, @loc}, @loc}
          {reads, flags ++ [{:let_stmt, {:var_pat, name}, flag_expr, @loc}]}
        {name, func, offset}, {reads, flags} ->
          read_expr = {:call, Atom.to_string(func),
            [{:var, "data", @loc}, {:integer_lit, offset, @loc}], @loc}
          {reads ++ [{:let_stmt, {:var_pat, name}, read_expr, @loc}], flags}
      end)

    # 4. Guard checks: if ethertype != 0x0800 do return :pass end
    guard_stmts = Enum.flat_map(guards, fn
      {:!=, var_name, value} ->
        [{:if_stmt,
         {:binop, :!=, {:var, var_name, @loc}, {:integer_lit, value, @loc}, @loc},
         [pass], [], [], @loc}]
      {:both_ne, var1, var2, value} ->
        # if var1 != value AND var2 != value → not a match → :pass
        [{:if_stmt,
         {:binop, :"&&",
           {:binop, :!=, {:var, var1, @loc}, {:integer_lit, value, @loc}, @loc},
           {:binop, :!=, {:var, var2, @loc}, {:integer_lit, value, @loc}, @loc},
           @loc},
         [pass], [], [], @loc}]
    end)

    # Order: reads that guards depend on first, then guards, then remaining reads
    guard_var_set = guards
      |> Enum.flat_map(fn
        {:!=, name, _} -> [name]
        {:both_ne, v1, v2, _} -> [v1, v2]
      end)
      |> MapSet.new()

    {pre_guard_reads, post_guard_reads} =
      Enum.split_with(read_stmts, fn {:let_stmt, {:var_pat, name}, _, _} ->
        MapSet.member?(guard_var_set, name)
      end)

    data_bindings ++ bounds_check ++ pre_guard_reads ++ guard_stmts ++
      post_guard_reads ++ flag_stmts ++ user_stmts
  end

  # ── Helpers ──

  defp classify_call(:+), do: {:binop, :+}
  defp classify_call(:-), do: {:binop, :-}
  defp classify_call(:*), do: {:binop, :*}
  defp classify_call(:div), do: {:binop, :/}
  defp classify_call(:rem), do: {:binop, :"%"}
  defp classify_call(:==), do: {:binop, :==}
  defp classify_call(:!=), do: {:binop, :!=}
  defp classify_call(:<), do: {:binop, :<}
  defp classify_call(:>), do: {:binop, :>}
  defp classify_call(:<=), do: {:binop, :<=}
  defp classify_call(:>=), do: {:binop, :>=}
  defp classify_call(:&&), do: {:binop, :"&&"}
  defp classify_call(:||), do: {:binop, :"||"}
  defp classify_call(:&&&), do: {:binop, :&}
  defp classify_call(:|||), do: {:binop, :|}
  defp classify_call(:^^^), do: {:binop, :^}
  defp classify_call(:<<<), do: {:binop, :"<<"}
  defp classify_call(:>>>), do: {:binop, :">>"}
  defp classify_call(:!), do: {:unop, :!}
  defp classify_call(:~~~), do: {:unop, :"~"}
  defp classify_call(_), do: :call

  defp to_bin(a) when is_atom(a), do: Atom.to_string(a)
  defp to_bin(b) when is_binary(b), do: b
  defp to_bin(n) when is_integer(n), do: Integer.to_string(n)
end
