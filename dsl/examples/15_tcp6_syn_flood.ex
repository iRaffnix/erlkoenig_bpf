# TCP6 SYN Flood Protection: SYN-Flood Erkennung auf IPv6.
# Zaehlt SYN-Pakete ohne ACK pro Source-IPv6 (untere 32 Bit),
# ab 100 Requests wird gedroppt.

defmodule Tcp6SynFlood do
  use ErlkoenigEbpfDsl.XDP

  xdp "tcp6_syn_flood" do
    map :syn6_count, :hash, key: :u32, value: :u64, max_entries: 65536

    on_tcp6 do
      if is_syn && !is_ack do
        count = map_lookup(syn6_count, src_ip6_lo)
        new_count = count + 1
        map_update(syn6_count, src_ip6_lo, new_count)
        if new_count > 100 do
          :drop
        else
          :pass
        end
      else
        :pass
      end
    end
  end
end
