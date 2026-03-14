# ARP Monitor: ARP-Requests pro Sender-IP zaehlen, Flood-Protection.

defmodule ArpMonitor do
  use ErlkoenigEbpfDsl.XDP

  xdp "arp_monitor" do
    map :arp_count, :hash, key: :u32, value: :u64, max_entries: 4096

    on_arp do
      count = map_lookup(arp_count, sender_ip)
      map_update(arp_count, sender_ip, count + 1)
      if count > 50 do
        :drop
      else
        :pass
      end
    end
  end
end
