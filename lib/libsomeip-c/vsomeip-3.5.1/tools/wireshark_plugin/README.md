# vsomeip-dissector
Wireshark dissector for vSomeip internal communication via TCP

## How To Use

1. Place `vsomeip-dissector.lua` file in `~/.config/wireshark/plugins/vsomeip/vsomeip-dissector.lua`
   (create `plugins` directory if it doesn't exist)
2. In wireshark go to `Analyze` > `Reload Lua Plugins`
3. In wireshark go to `Analyze` > `Enable Protocols` and search for `vsomeip` and enable it

## Referances

vSomeip Protocol definitions: documentation/vsomeipProtocol.md