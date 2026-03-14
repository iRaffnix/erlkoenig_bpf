defmodule ErlkoenigEbpfDsl.Constants do
  @moduledoc """
  Network protocol constants for XDP programs.
  """

  defmacro __using__(_opts) do
    quote do
      # EtherType
      @eth_p_ip      0x0800
      @eth_p_ipv6    0x86DD
      @eth_p_arp     0x0806

      # IP Protocol
      @ipproto_tcp   6
      @ipproto_udp   17
      @ipproto_icmp  1

      # TCP Flags
      @tcp_fin       0x01
      @tcp_syn       0x02
      @tcp_rst       0x04
      @tcp_psh       0x08
      @tcp_ack       0x10
      @tcp_urg       0x20

      # XDP Actions
      @xdp_aborted   0
      @xdp_drop      1
      @xdp_pass      2
      @xdp_tx        3
      @xdp_redirect  4

      # VLAN / 802.1Q
      @eth_p_8021q   0x8100

      # ARP opcodes
      @arp_request   1
      @arp_reply     2

      # ICMP types
      @icmp_echo_reply    0
      @icmp_dest_unreach  3
      @icmp_echo_request  8
      @icmp_time_exceeded 11

      # ICMP codes (for dest_unreach)
      @icmp_net_unreach   0
      @icmp_host_unreach  1
      @icmp_port_unreach  3

      # Well-known ports
      @port_dns      53
      @port_ntp      123
      @port_http     80
      @port_https    443
      @port_ssh      22
      @port_ssdp     1900

      # VLAN ID mask (lower 12 bits of TCI)
      @vlan_id_mask  0x0FFF

      # DNS flags
      @dns_qr_response  0x8000

      # Ethernet header size
      @eth_hlen      14
      # IPv4 header size (without options)
      @ipv4_hlen     20
      # IPv6 header size (without extension headers)
      @ipv6_hlen     40
      # TCP header size (without options)
      @tcp_hlen      20
      # UDP header size
      @udp_hlen      8
      # VLAN tag size (802.1Q)
      @vlan_hlen     4
    end
  end
end
