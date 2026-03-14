defmodule ErlkoenigEbpfDsl.UbpfTest do
  @moduledoc """
  Run all DSL examples through the uBPF VM to verify they produce
  correct XDP actions on real (constructed) packets.
  """
  use ExUnit.Case

  @xdp_drop 1
  @xdp_pass 2

  @examples_dir Path.expand("../examples", __DIR__)

  # ── Packet construction helpers ──

  defp eth_header(ethertype) do
    # dst_mac(6) + src_mac(6) + ethertype(2)
    <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      ethertype::16-big>>
  end

  defp ipv4_header(opts \\ []) do
    protocol = Keyword.get(opts, :protocol, 6)
    ttl = Keyword.get(opts, :ttl, 64)
    total_length = Keyword.get(opts, :total_length, 40)
    src_ip = Keyword.get(opts, :src_ip, {10, 0, 0, 1})
    dst_ip = Keyword.get(opts, :dst_ip, {10, 0, 0, 2})

    {s1, s2, s3, s4} = src_ip
    {d1, d2, d3, d4} = dst_ip

    # Simplified IPv4 header (20 bytes, no options)
    <<0x45, 0x00,                          # version/ihl, dscp/ecn
      total_length::16-big,                # total length
      0x00, 0x01, 0x00, 0x00,             # identification, flags/fragment
      ttl::8, protocol::8,                 # ttl, protocol
      0x00, 0x00,                          # header checksum (ignored by BPF)
      s1, s2, s3, s4,                      # src ip
      d1, d2, d3, d4>>                     # dst ip
  end

  defp ipv6_header(opts \\ []) do
    next_header = Keyword.get(opts, :next_header, 6)
    hop_limit = Keyword.get(opts, :hop_limit, 64)
    payload_length = Keyword.get(opts, :payload_length, 20)

    # IPv6 header (40 bytes)
    <<0x60, 0x00, 0x00, 0x00,             # version, traffic class, flow label
      payload_length::16-big,              # payload length
      next_header::8, hop_limit::8,        # next header, hop limit
      # src addr (16 bytes)
      0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      # dst addr (16 bytes)
      0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02>>
  end

  defp tcp_header(opts \\ []) do
    src_port = Keyword.get(opts, :src_port, 12345)
    dst_port = Keyword.get(opts, :dst_port, 80)
    flags = Keyword.get(opts, :flags, 0x10)  # ACK by default

    <<src_port::16-big, dst_port::16-big,  # ports
      0x00, 0x00, 0x00, 0x01,             # seq number
      0x00, 0x00, 0x00, 0x00,             # ack number
      0x50, flags::8,                      # data offset (5), flags
      0xFF, 0xFF,                          # window size
      0x00, 0x00, 0x00, 0x00>>            # checksum, urgent pointer
  end

  defp udp_header(opts \\ []) do
    src_port = Keyword.get(opts, :src_port, 12345)
    dst_port = Keyword.get(opts, :dst_port, 53)
    length = Keyword.get(opts, :length, 20)

    <<src_port::16-big, dst_port::16-big,
      length::16-big, 0x00, 0x00>>         # length, checksum
  end

  defp icmp_header(opts \\ []) do
    type = Keyword.get(opts, :type, 8)     # echo request
    code = Keyword.get(opts, :code, 0)

    <<type::8, code::8,
      0x00, 0x00,                          # checksum
      0x00, 0x01, 0x00, 0x01>>            # id, sequence
  end

  defp arp_packet(opts \\ []) do
    sender_ip = Keyword.get(opts, :sender_ip, {10, 0, 0, 1})
    target_ip = Keyword.get(opts, :target_ip, {10, 0, 0, 2})
    op = Keyword.get(opts, :op, 1)  # request

    {s1, s2, s3, s4} = sender_ip
    {t1, t2, t3, t4} = target_ip

    <<0x00, 0x01,                          # hardware type (ethernet)
      0x08, 0x00,                          # protocol type (ipv4)
      0x06, 0x04,                          # hw addr len, proto addr len
      op::16-big,                          # operation
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, # sender mac
      s1, s2, s3, s4,                      # sender ip
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # target mac
      t1, t2, t3, t4>>                     # target ip
  end

  defp vlan_tag(vlan_id \\ 100) do
    # PCP=0, DEI=0, VLAN ID
    <<0x81, 0x00,                          # TPID (0x8100) — this is the outer ethertype
      vlan_id::16-big>>                    # TCI: PCP(3) + DEI(1) + VID(12)
  end

  defp dns_header() do
    <<0x12, 0x34,                          # transaction ID
      0x01, 0x00,                          # flags: standard query
      0x00, 0x01,                          # question count: 1
      0x00, 0x00,                          # answer count: 0
      0x00, 0x00,                          # authority count
      0x00, 0x00>>                         # additional count
  end

  # ── Packet builders for each protocol ──

  defp ipv4_packet(opts \\ []) do
    eth_header(0x0800) <> ipv4_header(opts)
  end

  defp tcp_packet(opts \\ []) do
    ipv4_packet(protocol: 6, total_length: 60) <> tcp_header(opts)
  end

  defp udp_packet(opts \\ []) do
    ipv4_packet(protocol: 17, total_length: 48) <> udp_header(opts)
  end

  defp icmp_packet(opts \\ []) do
    ipv4_packet(protocol: 1, total_length: 48) <> icmp_header(opts)
  end

  defp ipv6_packet(opts \\ []) do
    eth_header(0x86DD) <> ipv6_header(opts)
  end

  defp tcp6_packet(opts \\ []) do
    eth_header(0x86DD) <> ipv6_header(next_header: 6) <> tcp_header(opts)
  end

  defp udp6_packet(opts \\ []) do
    eth_header(0x86DD) <> ipv6_header(next_header: 17) <> udp_header(opts)
  end

  defp arp_full_packet(opts \\ []) do
    eth_header(0x0806) <> arp_packet(opts)
  end

  defp vlan_ipv4_packet(opts \\ []) do
    # ETH dst+src (12 bytes) + VLAN tag (4 bytes, includes 0x8100) + inner ethertype + IPv4
    <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55>> <>
      vlan_tag(Keyword.get(opts, :vlan_id, 100)) <>
      <<0x08, 0x00>> <>
      ipv4_header(opts)
  end

  defp vlan_tcp_packet(opts \\ []) do
    <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55>> <>
      vlan_tag(Keyword.get(opts, :vlan_id, 100)) <>
      <<0x08, 0x00>> <>
      ipv4_header(protocol: 6, total_length: 60) <>
      tcp_header(opts)
  end

  defp dns_packet(opts \\ []) do
    src_port = Keyword.get(opts, :src_port, 12345)
    dst_port = Keyword.get(opts, :dst_port, 53)
    udp_packet(src_port: src_port, dst_port: dst_port, length: 32) <> dns_header()
  end

  # ── uBPF port helpers ──

  defp port_available? do
    try do
      port_path = Path.join(:code.priv_dir(:erlkoenig_ebpf), "ubpf_port")
      File.exists?(port_path)
    rescue
      _ -> false
    end
  end

  defp with_port(fun) do
    {:ok, port} = :ebpf_ubpf.start()
    try do
      fun.(port)
    after
      :ebpf_ubpf.stop(port)
    end
  end

  # Create maps matching a module's declarations, returns list of fds.
  defp setup_maps(port, module) do
    {:program, :xdp, _, _, _, maps, _, _} = module.__ebpf_ast__()
    :ebpf_ubpf.reset_maps(port)

    Enum.map(maps, fn {:map_decl, _name, _kind, key_type, val_type, max_entries, _loc} ->
      key_size = type_size(key_type)
      val_size = type_size(val_type)
      {:ok, fd} = :ebpf_ubpf.create_map(port, key_size, val_size, max_entries)
      fd
    end)
  end

  defp type_size({:prim, :u8}), do: 1
  defp type_size({:prim, :u16}), do: 2
  defp type_size({:prim, :u32}), do: 4
  defp type_size({:prim, :u64}), do: 8

  defp load_and_run_xdp(port, module, packet) do
    {:ok, bytecode} = module.compile()
    setup_maps(port, module)
    :ok = :ebpf_ubpf.load(port, bytecode)
    :ebpf_ubpf.run_xdp(port, packet)
  end

  # ── Test definitions ──
  # Each test: compile example → create maps → load → run_xdp → assert action

  @tag :ubpf
  describe "uBPF execution of DSL examples" do
    @describetag :ubpf

    setup do
      if port_available?() do
        :ok
      else
        {:skip, "ubpf_port not available"}
      end
    end

    test "01_hello_pass returns XDP_PASS" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "01_hello_pass.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet())
      end)
    end

    test "02_drop_all returns XDP_DROP" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "02_drop_all.ex"))
        assert {:ok, @xdp_drop} = load_and_run_xdp(port, mod, ipv4_packet())
      end)
    end

    test "03_ip_blacklist passes unknown IP" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "03_ip_blacklist.ex"))
        # Empty blacklist → all IPs pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet())
      end)
    end

    test "04_protocol_counter passes and counts" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "04_protocol_counter.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet())
      end)
    end

    test "05_port_firewall drops unknown port" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "05_port_firewall.ex"))
        # Empty allowed_ports map → all ports dropped
        assert {:ok, @xdp_drop} = load_and_run_xdp(port, mod, tcp_packet(dst_port: 8080))
      end)
    end

    test "06_syn_flood_protect passes first SYN" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "06_syn_flood_protect.ex"))
        # SYN without ACK, first packet → count=1, under threshold → pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, tcp_packet(flags: 0x02))
      end)
    end

    test "07_ttl_filter passes normal TTL" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "07_ttl_filter.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet(ttl: 64))
      end)
    end

    test "07_ttl_filter drops low TTL" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "07_ttl_filter.ex"))
        assert {:ok, @xdp_drop} = load_and_run_xdp(port, mod, ipv4_packet(ttl: 1))
      end)
    end

    test "08_bandwidth_monitor passes and tracks bytes" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "08_bandwidth_monitor.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet(total_length: 1500))
      end)
    end

    test "09_ipv6_filter passes IPv6" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "09_ipv6_filter.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv6_packet())
      end)
    end

    test "09_ipv6_filter passes non-IPv6 (guard bailout)" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "09_ipv6_filter.ex"))
        # IPv4 packet → ethertype != 0x86DD → guard returns :pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet())
      end)
    end

    test "10_arp_monitor passes first ARP" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "10_arp_monitor.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, arp_full_packet())
      end)
    end

    test "11_vlan_firewall drops unknown port on VLAN" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "11_vlan_firewall.ex"))
        # Empty allowed_ports → drop
        assert {:ok, @xdp_drop} = load_and_run_xdp(port, mod, vlan_tcp_packet(dst_port: 8080))
      end)
    end

    test "12_dns_monitor passes DNS query" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "12_dns_monitor.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, dns_packet())
      end)
    end

    test "13_icmp_rate_limit passes first ping" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "13_icmp_rate_limit.ex"))
        # Echo request, first packet → under threshold → pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, icmp_packet(type: 8))
      end)
    end

    test "13_icmp_rate_limit passes non-echo ICMP" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "13_icmp_rate_limit.ex"))
        # Echo reply (type 0) → not echo request → pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, icmp_packet(type: 0))
      end)
    end

    test "14_udp_amplification_guard passes small UDP" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "14_udp_amplification_guard.ex"))
        # Small UDP packet (length < 512) → pass regardless of port
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, udp_packet(src_port: 53, length: 100))
      end)
    end

    test "14_udp_amplification_guard passes first large DNS response" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "14_udp_amplification_guard.ex"))
        # Large UDP from DNS port → first packet, count=1 → pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, udp_packet(src_port: 53, length: 600))
      end)
    end

    test "15_tcp6_syn_flood passes first SYN over IPv6" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "15_tcp6_syn_flood.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, tcp6_packet(flags: 0x02))
      end)
    end

    test "15_tcp6_syn_flood passes ACK over IPv6" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "15_tcp6_syn_flood.ex"))
        # ACK packet → not (syn && !ack) → pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, tcp6_packet(flags: 0x10))
      end)
    end

    test "16_udp6_port_scan_detect passes first UDP6" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "16_udp6_port_scan_detect.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, udp6_packet())
      end)
    end

    test "17_vlan_traffic_accounting passes VLAN IPv4" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "17_vlan_traffic_accounting.ex"))
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, vlan_ipv4_packet())
      end)
    end

    test "19_protocol_profiler passes and counts" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "19_protocol_profiler.ex"))
        # Profiler always passes, just counts
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet())
      end)
    end

    test "protocol guard: on_tcp passes non-TCP packet" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "05_port_firewall.ex"))
        # UDP packet → protocol guard (protocol != 6) → return :pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, udp_packet())
      end)
    end

    test "18_ddos_blocklist passes unknown IP" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "18_ddos_blocklist.ex"))
        # Unknown IP not in blocklist → map_lookup returns 0 → pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, ipv4_packet(src_ip: {1, 2, 3, 4}))
      end)
    end

    test "bounds check: short packet returns pass" do
      with_port(fn port ->
        [{mod, _}] = Code.compile_file(Path.join(@examples_dir, "03_ip_blacklist.ex"))
        # Packet too short for IPv4 (< 34 bytes) → bounds check → pass
        assert {:ok, @xdp_pass} = load_and_run_xdp(port, mod, <<0x00::size(80)>>)
      end)
    end
  end
end
