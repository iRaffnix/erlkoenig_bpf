# DDoS Blocklist Filter: Pakete von bekannten Angreifer-IPs droppen.
# Portiert von C/XDP xdp_ddos_filter.
#
# Wenn src_ip in der Blocklist steht, wird der Drop-Zaehler
# inkrementiert und das Paket verworfen. Alle anderen passieren.

defmodule DdosBlocklist do
  use ErlkoenigEbpfDsl.XDP

  xdp "ddos_blocklist" do
    map :blocklist, :hash, key: :u32, value: :u64, max_entries: 10240

    on_ipv4 do
      drop_cnt = map_lookup(blocklist, src_ip)

      if drop_cnt > 0 do
        map_update(blocklist, src_ip, drop_cnt + 1)
        :drop
      else
        :pass
      end
    end
  end
end
