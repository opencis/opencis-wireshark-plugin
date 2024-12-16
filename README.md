# OpenCIS Wireshark Plugin

Welcome to the OpenCIS Wireshark Plugin repository! This plugin provides a Wireshark dissector for the OpenCIS-over-TCP packets. Please check the following instructions thoroughly before installing the dissector to your Wireshark.

## Minimum Environment Requirements

 - Latest `opencis-core` (https://github.com/opencis/opencis-core)
 - Lua: 5.3.0+.
 - Wireshark: 4.3.0+. Check https://www.wireshark.org/download.html for the latest version. 

The reason of this relatively "strict" requirement is because of the 64-bit support limitations for Lua versions before 5.3.0 (Wireshark started using Lua 5.3.0+ since Wireshark 4.3.0+). Many CXL packets pass longer-than-32-bit addresses (e.g., 46-bit addresses are used for CXL.cache and CXL.mem Back-invalidation), but Lua versions before 5.3.0 cannot handle 64-bit integers properly, and Wireshark only supports Lua 5.3.0+ since Wireshark 4.3.0+.

## Installation

To install the dissector, you need to first identify the location to put your Wireshark Lua plugins. 
Open "About Wireshark" dialog, then choose Folders. Find the folder for "Personal Lua Plugins".

Download the `opencis_dissector.lua` to the "Personal Lua Plugins" folder. Then go to Wireshark Preferences, select "Protocols" on the left, then select "OPENCIS". Choose the port number you used when running OpenCIS workloads. Type 1 and Type 2 image classification demos provided by the `opencis-core` repository uses port 22500 by default, but feel free to change the port number based on your choice when running your custom workload.

## Usage

Before running OpenCIS, you should run Wireshark first. Choose the correct network interface to listen to. If you are running everything locally (which is very likely), choose `lo` or similarly-named loopback interface (usually starts with `lo`) since that is the interface for local network traffic. 
You can then start listening the OpenCIS traffic. If Wireshark is not listening, click the blue shark fin logo on the top left corner of the window. Eventually you should see OpenCIS packets if OpenCIS is running. You can also save the packet captures to `pcap` files for further inspections in the future.

### Filter

All filters are defined under `opencis`. Depending on your need, you can utilize the filter in very flexible ways. Some examples:
 - `opencis.mem.m2s.birsp || opencis.mem.s2m.bisnp` shows all CXL.mem back invalidation packets.
 - `opencis.mem.s2m.bisnp.mem_opcode == BISnpData` selects all BISnpData packets.
The complete filter definitions can be found in the dissector source code.

## Known limitations

 - Heuristic dissection is not implemented yet.
