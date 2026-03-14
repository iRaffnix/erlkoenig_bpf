# DNS Monitor: DNS-Queries pro Source-IP zaehlen.

defmodule DnsMonitor do
  use ErlkoenigEbpfDsl.XDP

  xdp "dns_monitor" do
    map :dns_queries, :hash, key: :u32, value: :u64, max_entries: 65536

    on_dns do
      count = map_lookup(dns_queries, src_ip)
      map_update(dns_queries, src_ip, count + 1)
      :pass
    end
  end
end
