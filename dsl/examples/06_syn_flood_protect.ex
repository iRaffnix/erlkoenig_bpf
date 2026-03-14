# SYN Flood Protection: Rate-Limiting pro Source-IP.

defmodule SynFloodProtect do
  use ErlkoenigEbpfDsl.XDP

  xdp "syn_flood_protect" do
    map :syn_count, :hash, key: :u32, value: :u64, max_entries: 65536

    on_tcp do
      if is_syn && !is_ack do
        count = map_lookup(syn_count, src_ip)
        new_count = count + 1
        map_update(syn_count, src_ip, new_count)

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
