# VLAN Traffic Accounting: Bytes pro VLAN-ID zaehlen.
# vlan_tci enthaelt PCP(3) + DEI(1) + VLAN-ID(12),
# wir maskieren auf die unteren 12 Bit fuer die VLAN-ID.

defmodule VlanTrafficAccounting do
  use ErlkoenigEbpfDsl.XDP

  xdp "vlan_accounting" do
    map :vlan_bytes, :hash, key: :u32, value: :u64, max_entries: 4096

    on_vlan_ipv4 do
      vlan_id = vlan_tci &&& @vlan_id_mask
      current = map_lookup(vlan_bytes, vlan_id)
      map_update(vlan_bytes, vlan_id, current + total_length)
      :pass
    end
  end
end
