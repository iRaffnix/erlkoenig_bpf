defmodule ErlkoenigEbpfDsl.XDP do
  @moduledoc """
  XDP program definition macros.

  ## Basic usage

      defmodule MyFirewall do
        use ErlkoenigEbpfDsl.XDP

        xdp "my_firewall" do
          map :counters, :hash, key: :u32, value: :u64, max_entries: 1024

          main do
            :pass
          end
        end
      end

  ## Protocol helpers

  Use `on_ipv4`, `on_tcp`, `on_udp`, `on_icmp` instead of `main` for
  automatic packet parsing. These set up bounds checks, protocol guards,
  and bind named fields. Non-matching packets return `:pass`.

      xdp "syn_flood" do
        map :count, :hash, key: :u32, value: :u64, max_entries: 65536

        on_tcp do
          if is_syn && !is_ack do
            c = map_lookup(count, src_ip)
            map_update(count, src_ip, c + 1)
            if c > 100, do: :drop, else: :pass
          else
            :pass
          end
        end
      end

  ### Available fields

  - `on_ipv4`: `src_ip`, `dst_ip`, `protocol`, `ttl`, `total_length`
  - `on_tcp` (extends ipv4): `src_port`, `dst_port`, `flags`, `is_syn`, `is_ack`, `is_fin`, `is_rst`
  - `on_udp` (extends ipv4): `src_port`, `dst_port`, `udp_length`
  - `on_icmp` (extends ipv4): `icmp_type`, `icmp_code`
  - `on_ipv6`: `next_header`, `hop_limit`, `payload_length`, `src_ip6_hi`, `src_ip6_lo`, `dst_ip6_hi`, `dst_ip6_lo`
  - `on_tcp6` (extends ipv6): `src_port`, `dst_port`, `flags`, `is_syn`, `is_ack`, `is_fin`, `is_rst`
  - `on_udp6` (extends ipv6): `src_port`, `dst_port`, `udp_length`
  - `on_arp`: `arp_op`, `sender_ip`, `target_ip`, `sender_mac_hi`, `sender_mac_lo`, `target_mac_hi`, `target_mac_lo`
  - `on_vlan_ipv4` (802.1Q): `vlan_tci`, `src_ip`, `dst_ip`, `protocol`, `ttl`, `total_length`
  - `on_vlan_tcp` (802.1Q+TCP): `vlan_tci`, `src_port`, `dst_port`, `flags`, `is_syn`, `is_ack`, `is_fin`, `is_rst`
  - `on_dns` (UDP port 53): all ipv4+udp fields + `dns_id`, `dns_flags`, `dns_qcount`, `dns_acount`

  ## Module attributes as constants

  All constants from `ErlkoenigEbpfDsl.Constants` (e.g. `@icmp_echo_request`,
  `@port_dns`, `@vlan_id_mask`) are available inside `on_*` blocks and are
  resolved at compile time.
  """

  defmacro __using__(_opts) do
    quote do
      import ErlkoenigEbpfDsl.XDP
      use ErlkoenigEbpfDsl.Constants
      Module.register_attribute(__MODULE__, :ebpf_builder, accumulate: false)
      @before_compile ErlkoenigEbpfDsl.XDP
    end
  end

  defmacro xdp(name, do: block) do
    quote do
      @ebpf_builder ErlkoenigEbpfDsl.Builder.new(unquote(name))
      unquote(block)
    end
  end

  defmacro map(name, kind, opts) do
    quote do
      @ebpf_builder ErlkoenigEbpfDsl.Builder.add_map(
        @ebpf_builder, unquote(name), unquote(kind), unquote(opts))
    end
  end

  defmacro main(do: block) do
    ast = Macro.escape(block)
    quote do
      @ebpf_builder ErlkoenigEbpfDsl.Builder.set_main(
        @ebpf_builder,
        ErlkoenigEbpfDsl.XDP.resolve_module_attrs(unquote(ast), __MODULE__))
    end
  end

  # Generate on_* macros — all follow the same pattern:
  # escape the block, then resolve @attrs in the user's module context (inside quote).
  for proto <- [:ipv4, :tcp, :udp, :icmp, :ipv6, :tcp6, :udp6, :arp, :vlan_ipv4, :vlan_tcp, :dns] do
    macro_name = :"on_#{proto}"

    defmacro unquote(macro_name)(do: block) do
      proto = unquote(proto)
      ast = Macro.escape(block)
      quote do
        @ebpf_builder ErlkoenigEbpfDsl.Builder.set_main_protocol(
          @ebpf_builder, unquote(proto),
          ErlkoenigEbpfDsl.XDP.resolve_module_attrs(unquote(ast), __MODULE__))
      end
    end
  end

  @doc false
  # Called at compile time in the user's module context (inside quote, not macro body).
  # Module.get_attribute works here because it runs during module body evaluation.
  def resolve_module_attrs(ast, module) do
    Macro.postwalk(ast, fn
      {:@, _, [{name, _, ctx}]} = node when is_atom(name) and is_atom(ctx) ->
        case Module.get_attribute(module, name) do
          nil -> node
          val -> val
        end
      other -> other
    end)
  end

  defmacro __before_compile__(_env) do
    quote do
      def __ebpf_ast__ do
        ErlkoenigEbpfDsl.Builder.to_ast(@ebpf_builder)
      end

      def compile do
        ErlkoenigEbpfDsl.compile(__ebpf_ast__())
      end

      def bytecode do
        {:ok, bin} = compile()
        bin
      end
    end
  end
end
