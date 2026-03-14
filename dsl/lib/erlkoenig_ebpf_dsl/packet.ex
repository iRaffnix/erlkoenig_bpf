defmodule ErlkoenigEbpfDsl.Packet do
  @moduledoc """
  Packet parsing helper macros for XDP programs.

  These macros generate the correct bounds-check + field-read sequences
  that the BPF verifier requires. Each macro ensures data access is safe
  by checking `data + offset > data_end` before reading.

  Usage inside an `xdp do ... main do ... end end` block:

      with_ipv4 ctx do
        # ipv4.src_addr, ipv4.dst_addr, ipv4.protocol, etc. available
        if ipv4.protocol == 6 do
          with_tcp ctx do
            # tcp.src_port, tcp.dst_port, tcp.flags, etc. available
            :drop
          else
            :pass
          end
        end
      else
        :pass
      end
  """

  @eth_hlen 14
  @ipv4_hlen 20
  @tcp_hlen 20
  @udp_hlen 8

  @doc """
  Parse an IPv4 packet from the XDP context.

  Binds `data`, `data_end`, `ethertype`, and an `ipv4` map with fields:
  `src_addr`, `dst_addr`, `protocol`, `ttl`, `total_length`.

  The `else` block is executed if the packet is too short or not IPv4.
  """
  defmacro with_ipv4(ctx_var, do: block, else: else_block) do
    min_len = @eth_hlen + @ipv4_hlen

    quote do
      data = unquote(ctx_var).data
      data_end = unquote(ctx_var).data_end

      if data + unquote(min_len) > data_end do
        unquote(else_block)
      else
        ethertype = read_u16_be(data, 12)

        if ethertype != 0x0800 do
          unquote(else_block)
        else
          # IPv4 fields
          ipv4_protocol = read_u8(data, 23)
          ipv4_ttl = read_u8(data, 22)
          ipv4_total_length = read_u16_be(data, 16)
          ipv4_src_addr = read_u32_be(data, 26)
          ipv4_dst_addr = read_u32_be(data, 30)

          unquote(block)
        end
      end
    end
  end

  @doc """
  Parse a TCP packet. Must be nested inside `with_ipv4`.

  Requires at least 54 bytes (ETH + IP + TCP headers).
  Binds `tcp_src_port`, `tcp_dst_port`, `tcp_flags`.
  """
  defmacro with_tcp(ctx_var, do: block, else: else_block) do
    min_len = @eth_hlen + @ipv4_hlen + @tcp_hlen

    quote do
      with_ipv4 unquote(ctx_var) do
        if ipv4_protocol != 6 do
          unquote(else_block)
        else
          if data + unquote(min_len) > data_end do
            unquote(else_block)
          else
            tcp_src_port = read_u16_be(data, 34)
            tcp_dst_port = read_u16_be(data, 36)
            tcp_flags = read_u8(data, 47)

            unquote(block)
          end
        end
      else
        unquote(else_block)
      end
    end
  end

  @doc """
  Parse a UDP packet. Must be nested inside `with_ipv4`.

  Requires at least 42 bytes (ETH + IP + UDP headers).
  Binds `udp_src_port`, `udp_dst_port`, `udp_length`.
  """
  defmacro with_udp(ctx_var, do: block, else: else_block) do
    min_len = @eth_hlen + @ipv4_hlen + @udp_hlen

    quote do
      with_ipv4 unquote(ctx_var) do
        if ipv4_protocol != 17 do
          unquote(else_block)
        else
          if data + unquote(min_len) > data_end do
            unquote(else_block)
          else
            udp_src_port = read_u16_be(data, 34)
            udp_dst_port = read_u16_be(data, 36)
            udp_length = read_u16_be(data, 38)

            unquote(block)
          end
        end
      else
        unquote(else_block)
      end
    end
  end

  @doc """
  Parse an ICMP packet. Must be nested inside `with_ipv4`.

  Requires at least 42 bytes (ETH + IP + ICMP header).
  Binds `icmp_type`, `icmp_code`.
  """
  defmacro with_icmp(ctx_var, do: block, else: else_block) do
    min_len = @eth_hlen + @ipv4_hlen + 8  # ICMP header = 8 bytes

    quote do
      with_ipv4 unquote(ctx_var) do
        if ipv4_protocol != 1 do
          unquote(else_block)
        else
          if data + unquote(min_len) > data_end do
            unquote(else_block)
          else
            icmp_type = read_u8(data, 34)
            icmp_code = read_u8(data, 35)

            unquote(block)
          end
        end
      else
        unquote(else_block)
      end
    end
  end
end
