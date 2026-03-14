# VLAN Firewall: Nur erlaubte Ports auf VLAN-tagged Traffic durchlassen.

defmodule VlanFirewall do
  use ErlkoenigEbpfDsl.XDP

  xdp "vlan_firewall" do
    map :allowed_ports, :hash, key: :u32, value: :u64, max_entries: 1024

    on_vlan_tcp do
      allowed = map_lookup(allowed_ports, dst_port)
      if allowed != 0 do
        :pass
      else
        :drop
      end
    end
  end
end
