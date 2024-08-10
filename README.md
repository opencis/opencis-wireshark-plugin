# OpenCXL Wireshark Plugin

Welcome to the OpenCXL Wireshark Plugin repository! This plugin provides a Wireshark dissector for the OpenCXL-over-TCP packets. Please check the following instructions thoroughly before installing the dissector to your Wireshark.

## Minimum Environment Requirements

 - Latest `opencxl-core` (https://github.com/opencxl/opencxl-core)
 - Lua: 5.3.0+.
 - Wireshark: 4.3.0+ (Development Release as of Aug 9, 2024). Check https://www.wireshark.org/download.html for the latest version. 

The reason of this relatively "strict" requirement is because of the limitation of 64-bit support for Lua versions older than 5.3.0. Many CXL packets pass longer-than-32-bit addresses (e.g., 46-bit addresses are used for CXL.cache and CXL.mem Back-invalidation), but Lua versions older than 5.3.0 cannot handle 64-bit integers properly, and Wireshark only supports Lua 5.3.0+ since Wireshark 4.3.0+.

## Installation

To install the dissector, you need to first identify the location to put your Wireshark Lua plugins. 
Open "About Wireshark" dialog, then choose Folders. Find the folder for "Global Lua Plugins" or "Personal Lua Plugins" depending on if you would like to install the plugin just for yourself or all Wireshark users on this computer.

Download the `opencxl_dissector.lua` to the "Global Lua Plugins" or the "Personal Lua Plugins" folder depending on your choice. Then go to Wireshark Preferences, select "Protocols" on the left, then select "OPENCXL". Choose the port number you used when running OpenCXL workloads. Type 1 and Type 2 image classification demos provided by the `opencxl-core` repository uses port 22500 by default, but feel free to change the port number based on your choice when running your custom workload.

## Usage

Before running OpenCXL, you should run Wireshark first. Choose the correct network interface to listen to. If you are running everything locally (which is very likely), choose `lo0` or similarly-named loopback interface (usually starts with `lo`) since that is the interface for local network traffic. 
You can then start listening the OpenCXL traffic. If Wireshark is not listening, click the blue shark fin logo on the top left corner of the window. Eventually you should see OpenCXL packets if OpenCXL is running.

### Filter

We also defined many filters. All filters are under the root named `opencxl`. Depending on your need, you can utilize the filter in very flexible ways. Some examples:
 - `opencxl.mem.m2s.birsp || opencxl.mem.s2m.bisnp` shows all CXL.mem back invalidation packets.
 - `opencxl.mem.s2m.bisnp.mem_opcode == BISnpData` selects all BISnpData packets.

## Known limitations

 - Heuristic dissection is not implemented yet.
 - CXL.cache packet details are not implemented yet.