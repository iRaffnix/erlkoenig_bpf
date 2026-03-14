# IP Blacklist: Source-IP gegen Map pruefen, bei Treffer droppen.

defmodule IpBlacklist do
  use ErlkoenigEbpfDsl.XDP

  xdp "ip_blacklist" do
    map :blacklist, :hash, key: :u32, value: :u64, max_entries: 10000

    on_ipv4 do
      found = map_lookup(blacklist, src_ip)
      if found != 0 do
        :drop
      else
        :pass
      end
    end
  end
end
