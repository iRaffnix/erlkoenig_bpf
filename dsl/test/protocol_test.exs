defmodule ErlkoenigEbpfDsl.ProtocolTest do
  use ExUnit.Case, async: true

  alias ErlkoenigEbpfDsl.Builder

  describe "on_ipv4" do
    test "generates data bindings, bounds check, ethertype guard, and field bindings" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :ipv4, quote(do: :pass))
      ast = Builder.to_ast(state)

      {:program, :xdp, _, _, _, _, _, [fn_decl]} = ast
      {:fn_decl, "main", _, _, stmts, _} = fn_decl

      # data = ctx.data
      assert {:let_stmt, {:var_pat, "data"}, {:field_access, {:var, "ctx", _}, "data", _}, _} =
        Enum.at(stmts, 0)
      # data_end = ctx.data_end
      assert {:let_stmt, {:var_pat, "data_end"}, {:field_access, {:var, "ctx", _}, "data_end", _}, _} =
        Enum.at(stmts, 1)
      # if data + 34 > data_end do return :pass end
      assert {:if_stmt, {:binop, :>, {:binop, :+, _, {:integer_lit, 34, _}, _}, _, _}, _, _, _, _} =
        Enum.at(stmts, 2)
      # ethertype = read_u16_be(data, 12)
      assert {:let_stmt, {:var_pat, "ethertype"}, {:call, "read_u16_be", _, _}, _} =
        Enum.at(stmts, 3)
      # if ethertype != 0x0800 do return :pass end
      assert {:if_stmt, {:binop, :!=, {:var, "ethertype", _}, {:integer_lit, 2048, _}, _}, _, _, _, _} =
        Enum.at(stmts, 4)
      # Field bindings: src_ip, dst_ip, protocol, ttl, total_length
      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "src_ip" in var_names
      assert "dst_ip" in var_names
      assert "protocol" in var_names
      assert "ttl" in var_names
      assert "total_length" in var_names
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :ipv4, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_tcp" do
    test "includes TCP fields and flag helpers" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :tcp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "src_port" in var_names
      assert "dst_port" in var_names
      assert "flags" in var_names
      assert "is_syn" in var_names
      assert "is_ack" in var_names
      assert "is_fin" in var_names
      assert "is_rst" in var_names
    end

    test "has both ethertype and protocol guards" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :tcp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"ethertype", 0x0800} in guards
      assert {"protocol", 6} in guards
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :tcp, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_udp" do
    test "includes UDP fields" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :udp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "src_port" in var_names
      assert "dst_port" in var_names
      assert "udp_length" in var_names
    end

    test "guards on protocol 17" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :udp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"protocol", 17} in guards
    end
  end

  describe "on_icmp" do
    test "includes ICMP fields" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :icmp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "icmp_type" in var_names
      assert "icmp_code" in var_names
    end

    test "guards on protocol 1" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :icmp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"protocol", 1} in guards
    end
  end

  describe "on_ipv6" do
    test "includes IPv6 fields and bounds check at 54 bytes" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :ipv6, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "next_header" in var_names
      assert "hop_limit" in var_names
      assert "payload_length" in var_names
      assert "src_ip6_hi" in var_names
      assert "src_ip6_lo" in var_names
      assert "dst_ip6_hi" in var_names
      assert "dst_ip6_lo" in var_names

      assert {:if_stmt, {:binop, :>, {:binop, :+, _, {:integer_lit, 54, _}, _}, _, _}, _, _, _, _} =
        Enum.at(stmts, 2)
    end

    test "guards on ethertype 0x86DD" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :ipv6, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"ethertype", 0x86DD} in guards
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :ipv6, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_tcp6" do
    test "includes TCP6 fields and flag helpers" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :tcp6, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "src_port" in var_names
      assert "dst_port" in var_names
      assert "flags" in var_names
      assert "is_syn" in var_names
      assert "is_ack" in var_names
      assert "next_header" in var_names
      assert "src_ip6_hi" in var_names
    end

    test "guards on ethertype 0x86DD and next_header 6" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :tcp6, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"ethertype", 0x86DD} in guards
      assert {"next_header", 6} in guards
    end

    test "bounds check at 74 bytes" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :tcp6, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      assert {:if_stmt, {:binop, :>, {:binop, :+, _, {:integer_lit, 74, _}, _}, _, _}, _, _, _, _} =
        Enum.at(stmts, 2)
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :tcp6, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_udp6" do
    test "includes UDP6 fields" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :udp6, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "src_port" in var_names
      assert "dst_port" in var_names
      assert "udp_length" in var_names
      assert "next_header" in var_names
    end

    test "guards on next_header 17" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :udp6, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"next_header", 17} in guards
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :udp6, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_arp" do
    test "includes ARP fields" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :arp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "arp_op" in var_names
      assert "sender_ip" in var_names
      assert "target_ip" in var_names
      assert "sender_mac_hi" in var_names
      assert "sender_mac_lo" in var_names
      assert "target_mac_hi" in var_names
      assert "target_mac_lo" in var_names
    end

    test "guards on ethertype 0x0806" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :arp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"ethertype", 0x0806} in guards
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :arp, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_vlan_ipv4" do
    test "includes VLAN + IPv4 fields" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :vlan_ipv4, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "outer_ethertype" in var_names
      assert "vlan_tci" in var_names
      assert "ethertype" in var_names
      assert "src_ip" in var_names
      assert "dst_ip" in var_names
      assert "protocol" in var_names
    end

    test "guards on outer_ethertype 0x8100 and ethertype 0x0800" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :vlan_ipv4, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"outer_ethertype", 0x8100} in guards
      assert {"ethertype", 0x0800} in guards
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :vlan_ipv4, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_vlan_tcp" do
    test "includes VLAN + TCP fields and flag helpers" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :vlan_tcp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "vlan_tci" in var_names
      assert "src_port" in var_names
      assert "dst_port" in var_names
      assert "flags" in var_names
      assert "is_syn" in var_names
      assert "is_ack" in var_names
    end

    test "guards on outer_ethertype, ethertype, and protocol" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :vlan_tcp, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      guards = for {:if_stmt, {:binop, :!=, {:var, name, _}, {:integer_lit, val, _}, _}, _, _, _, _} <- stmts,
                   do: {name, val}
      assert {"outer_ethertype", 0x8100} in guards
      assert {"ethertype", 0x0800} in guards
      assert {"protocol", 6} in guards
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :vlan_tcp, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end

  describe "on_dns" do
    test "includes DNS fields" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :dns, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      var_names = for {:let_stmt, {:var_pat, name}, _, _} <- stmts, do: name
      assert "dns_id" in var_names
      assert "dns_flags" in var_names
      assert "dns_qcount" in var_names
      assert "dns_acount" in var_names
      assert "src_port" in var_names
      assert "dst_port" in var_names
    end

    test "has both_!= guard for port 53" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :dns, quote(do: :pass))
      {:fn_decl, "main", _, _, stmts, _} =
        Builder.to_ast(state) |> elem(7) |> hd()

      # Find the AND guard: if src_port != 53 && dst_port != 53 do return :pass end
      and_guards = for {:if_stmt, {:binop, :"&&", _, _, _}, _, _, _, _} <- stmts, do: true
      assert length(and_guards) == 1
    end

    test "compiles to valid BPF bytecode" do
      state = Builder.new("test")
      state = Builder.set_main_protocol(state, :dns, quote(do: :pass))
      {:ok, bin} = ErlkoenigEbpfDsl.compile(Builder.to_ast(state))
      assert is_binary(bin) and rem(byte_size(bin), 8) == 0
    end
  end
end
