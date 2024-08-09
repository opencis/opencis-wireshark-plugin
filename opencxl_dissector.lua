----------------------------------------
-- script-name: opencxl_dissector.lua
--
-- Original author: Xiangqun Zhang <xzhang84 at syracuse dot edu>
-- Copyright (c) 2024, Eeum, Inc.
-- This code is published under GNU GPL v2 to be compatible with Wireshark.
-- Based on Hadriel Kaplan's dns_dissector.lua
--
----------------------------------------
-- do not modify this table

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    port         = 22500,
    heur_enabled = false,
}

-- for testing purposes, we want to be able to pass in changes to the defaults
-- from the command line; because you can't set lua preferences from the command
-- line using the '-o' switch (the preferences don't exist until this script is
-- loaded, so the command line thinks they're invalid preferences being set)
-- so we pass them in as command arguments insetad, and handle it here:
local args={...} -- get passed-in args
if args and #args > 0 then
    for _, arg in ipairs(args) do
        local name, value = arg:match("(.+)=(.+)")
        if name and value then
            if tonumber(value) then
                value = tonumber(value)
            elseif value == "true" or value == "TRUE" then
                value = true
            elseif value == "false" or value == "FALSE" then
                value = false
            elseif value == "DISABLED" then
                value = debug_level.DISABLED
            elseif value == "LEVEL_1" then
                value = debug_level.LEVEL_1
            elseif value == "LEVEL_2" then
                value = debug_level.LEVEL_2
            else
                error("invalid commandline argument value")
            end
        else
            error("invalid commandline argument syntax")
        end

        default_settings[name] = value
    end
end

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) < 4 and tonumber(minor) < 3 then
    error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
            "This script needs Wireshark/Tshark version 4.3.0 or higher.\n" )
end

local lua_major, lua_minor = _VERSION:match("(%d+)%.(%d+)")
if major and tonumber(lua_major) < 5 and tonumber(lua_minor) < 3 then
    error(  "Sorry, but your Lua version (".._VERSION..") is too old for this script!\n"..
            "This script needs Lua version 5.3.0 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

----------------------------------------


----------------------------------------
-- creates a Proto object, but doesn't register it yet
local opencxl = Proto("opencxl","OpenCXL Protocol")
local opencxl_header = Proto("opencxl.sys","OpenCXL System Header")
local opencxl_io_header = Proto("opencxl.io","CXL.io Header")
local opencxl_mreq_header = Proto("opencxl.io.mreq","CXL.io Memory Request Header")
local opencxl_cpl_packet = Proto("opencxl.io.cpl","CXL.io Completion Packet")
local opencxl_cfg_packet = Proto("opencxl.io.cfg","CXL.io Config Packet")
local opencxl_mem_header = Proto("opencxl.mem","CXL.mem Header")
local opencxl_m2s_req_header = Proto("opencxl.mem.m2s.req","CXL.mem M2S_REQ Header")
local opencxl_m2s_rwd_header = Proto("opencxl.mem.m2s.rwd","CXL.mem M2S_RWD Header")
local opencxl_m2s_birsp_header = Proto("opencxl.mem.m2s.birsp","CXL.mem M2S_BIRSP Header")
local opencxl_s2m_bisnp_header = Proto("opencxl.mem.s2m.bisnp","CXL.mem S2M_BISNP Header")
local opencxl_s2m_ndr_header = Proto("opencxl.mem.s2m.ndr","CXL.mem S2M_NDR Header")
local opencxl_s2m_drs_header = Proto("opencxl.mem.s2m.drs","CXL.mem S2M_DRS Header")
----------------------------------------
-- Define system header

local sys_header_payload_type_readable = {
    [0] = "CXL",
    [1] = "CXL.io",
    [2] = "CXL.mem",
    [3] = "CXL.cache",
    [15] = "Sideband"
}


local sys_header_payload_type = ProtoField.uint16("opencxl.system.payload_type", "Payload Type", base.HEX, sys_header_payload_type_readable, 0x000F, "What's the payload type?")
local sys_header_payload_len = ProtoField.new("Length", "opencxl.system.payload_len", ftypes.UINT16, nil, base.HEX, 0xFFF0, "Length of the payload?")

local io_header_payload_type_readable = {
    [tonumber("00000000", 2)] = "MRD_32B",
    [tonumber("00100000", 2)] = "MRD_64B",
    [tonumber("00000001", 2)] = "MRD_LK_32B",
    [tonumber("00100001", 2)] = "MRD_LK_64B",
    [tonumber("01000000", 2)] = "MWR_32B",
    [tonumber("01100000", 2)] = "MWR_64B",
    [tonumber("00000010", 2)] = "IO_RD",
    [tonumber("01000010", 2)] = "IO_WR",
    [tonumber("00000100", 2)] = "CFG_RD0",
    [tonumber("01000100", 2)] = "CFG_WR0",
    [tonumber("00000101", 2)] = "CFG_RD1",
    [tonumber("01000101", 2)] = "CFG_WR1",
    [tonumber("00011011", 2)] = "TCFG_RD",
    [tonumber("01011011", 2)] = "D_MRW_32B",
    [tonumber("01111011", 2)] = "D_MRW_64B",
    [tonumber("00001010", 2)] = "CPL",
    [tonumber("01001010", 2)] = "CPL_D",
    [tonumber("00001011", 2)] = "CPL_LK",
    [tonumber("01001011", 2)] = "CPL_D_LK",
    [tonumber("01001100", 2)] = "FETCH_ADD_32B",
    [tonumber("01101100", 2)] = "FETCH_ADD_64B",
    [tonumber("01001101", 2)] = "SWAP_32B",
    [tonumber("01101101", 2)] = "SWAP_64B",
    [tonumber("01001110", 2)] = "CAS_32B",
    [tonumber("01101110", 2)] = "CAS_64B"
}


-- io_header
local io_header_fmt_type = ProtoField.new   ("Format Type", "opencxl.io.fmt_type", ftypes.UINT32, io_header_payload_type_readable, base.HEX, 0xFF, "Format Type?")
local io_header_th = ProtoField.new   ("th", "opencxl.io.th", ftypes.UINT32, nil, base.HEX, 0x100, "Format Type?")
local io_header_rsvd = ProtoField.new   ("rsvd", "opencxl.io.rsvd", ftypes.UINT32, nil, base.HEX, 0x200, "Reserved")
local io_header_attr_b2 = ProtoField.new   ("attr_b2", "opencxl.io.attr_b2", ftypes.UINT32, nil, base.HEX, 0x400, "Attr b2")
local io_header_t8 = ProtoField.new   ("t8", "opencxl.io.t8", ftypes.UINT32, nil, base.HEX, 0x800, "t8")
local io_header_tc = ProtoField.new   ("tc", "opencxl.io.t8", ftypes.UINT32, nil, base.HEX, 0x7000, "tc")
local io_header_t9 = ProtoField.new   ("t9", "opencxl.io.t9", ftypes.UINT32, nil, base.HEX, 0x8000, "t9")
local io_header_length_upper = ProtoField.new   ("Length Upper", "opencxl.io.length_upper", ftypes.UINT32, nil, base.HEX, 0x30000, "Length, Upper Bits")
local io_header_at = ProtoField.new   ("at", "opencxl.io.at", ftypes.UINT32, nil, base.HEX, 0xC0000, "at")
local io_header_attr = ProtoField.new   ("attr", "opencxl.io.attr", ftypes.UINT32, nil, base.HEX, 0x300000, "attr")
local io_header_ep = ProtoField.new   ("ep", "opencxl.io.ep", ftypes.UINT32, nil, base.HEX, 0x400000, "ep")
local io_header_td = ProtoField.new   ("td", "opencxl.io.td", ftypes.UINT32, nil, base.HEX, 0x800000, "td")
local io_header_length_lower = ProtoField.new   ("Length Lower", "opencxl.io.length_lower", ftypes.UINT32, nil, base.HEX, 0xFF000000, "Length, Lower Bits")

-- io_mreq_header
local io_mreq_header_req_id = ProtoField.new   ("Request ID", "opencxl.io.mreq.req_id", ftypes.UINT16, nil, base.HEX, nil, "Packet Request ID")
local io_mreq_header_tag = ProtoField.new   ("Tag", "opencxl.io.mreq.tag", ftypes.UINT8, nil, base.HEX, nil, "Packet Tag")
local io_mreq_header_first_dw_be = ProtoField.new   ("first_dw_be", "opencxl.io.mreq.first_dw_be", ftypes.UINT8, nil, base.HEX, 0x0F, "first_dw_be")
local io_mreq_header_last_dw_be = ProtoField.new   ("last_dw_be", "opencxl.io.mreq.last_dw_be", ftypes.UINT8, nil, base.HEX, 0xF0, "last_dw_be")
local io_mreq_header_addr_upper = ProtoField.new   ("Upper 56-bit Address", "opencxl.io.mreq.addr_upper", ftypes.UINT64, nil, base.HEX, UInt64(0xFFFFFF00, 0xFFFFFFFF), "Upper 56-bit Address")
local io_mreq_header_addr_lower = ProtoField.new   ("Lower 8-bit Address >> 2", "opencxl.io.mreq.addr_lower", ftypes.UINT64, nil, base.HEX, UInt64(0x000000FC, 0x00000000), "Lower 8-bit Address, right shifted with 2 to be DWORD-aligned")
local io_mreq_header_rsvd = ProtoField.new   ("Reserved", "opencxl.io.mreq.rsvd", ftypes.UINT64, nil, base.HEX, UInt64(0x00000003, 0x00000000), "Reserved")

-- cpl(d) header
local io_cpl_header_cpl_id = ProtoField.new   ("Completion ID", "opencxl.io.cpl.cpl_id", ftypes.UINT16, nil, base.HEX, nil, "Packet Completion ID")
local io_cpl_header_byte_upper = ProtoField.new   ("Byte Count Upper", "opencxl.io.cpl.byte_upper", ftypes.UINT8, nil, base.HEX, 0x0F, "Byte Count, Upper Bits")
local io_cpl_header_bcm = ProtoField.new   ("BCM", "opencxl.io.cpl.bcm", ftypes.UINT8, nil, base.HEX, 0x10, "BCM")
local io_cpl_header_status = ProtoField.new   ("Status", "opencxl.io.cpl.status", ftypes.UINT8, nil, base.HEX, 0xE0, "Status")
local io_cpl_header_byte_lower = ProtoField.new   ("Byte Count Lower", "opencxl.io.cpl.byte_lower", ftypes.UINT8, nil, base.HEX, nil, "Byte Count, Lower Bits")
local io_cpl_header_req_id = ProtoField.new   ("Request ID", "opencxl.io.cpl.req_id", ftypes.UINT16, nil, base.HEX, nil, "Packet Request ID")
local io_cpl_header_tag = ProtoField.new   ("Tag", "opencxl.io.cpl.tag", ftypes.UINT8, nil, base.HEX, nil, "Packet Tag")
local io_cpl_lower_addr = ProtoField.new   ("Lower Address", "opencxl.io.cpl.lower_addr", ftypes.UINT8, nil, base.HEX, 0x7F, "Packet Tag")
local io_cpl_rsvd = ProtoField.new   ("Reserved", "opencxl.io.cpl.rsvd", ftypes.UINT8, nil, base.HEX, 0x80, "Reserved")
local io_cpl_data_32b = ProtoField.new   ("CPL Data (32-bit)", "opencxl.io.cpl.data_32b", ftypes.UINT32, nil, base.HEX, nil, "CPL Data (32-bit)")
local io_cpl_data_64b = ProtoField.new   ("CPL Data (64-bit)", "opencxl.io.cpl.data_64b", ftypes.UINT64, nil, base.HEX, nil, "CPL Data (64-bit)")

-- io_cfg header
local io_cfg_header_req_id = ProtoField.new   ("Request ID", "opencxl.io.cfg.req_id", ftypes.UINT16, nil, base.HEX, nil, "Packet Request ID")
local io_cfg_header_tag = ProtoField.new   ("Tag", "opencxl.io.cfg.tag", ftypes.UINT8, nil, base.HEX, nil, "Tag")
local io_cfg_header_first_dw_be = ProtoField.new   ("first_dw_be", "opencxl.io.cfg.first_dw_be", ftypes.UINT8, nil, base.HEX, 0x0F, "first_dw_be")
local io_cfg_header_last_dw_be = ProtoField.new   ("last_dw_be", "opencxl.io.cfg.last_dw_be", ftypes.UINT8, nil, base.HEX, 0xF0, "last_dw_be")
local io_cfg_header_dest_id = ProtoField.new   ("Destination ID", "opencxl.io.cfg.dest_id", ftypes.UINT16, nil, base.HEX, nil, "Packet Destination ID")
local io_cfg_header_ext_reg_num = ProtoField.new   ("first_dw_be", "opencxl.io.cfg.ext_reg_num", ftypes.UINT8, nil, base.HEX, 0x0F, "Extended Reg Num")
local io_cfg_header_rsvd = ProtoField.new   ("Reserved", "opencxl.io.cfg.rsvd", ftypes.UINT8, nil, base.HEX, 0xF0, "Reserved")
local io_cfg_header_r = ProtoField.new   ("r", "opencxl.io.cfg.r", ftypes.UINT8, nil, base.HEX, 0x03, "r")
local io_cfg_header_reg_num = ProtoField.new   ("Reg Num", "opencxl.io.cfg.reg_num", ftypes.UINT8, nil, base.HEX, 0xFC, "Reg Num")
local io_cfg_header_data = ProtoField.new   ("Data", "opencxl.io.cfg.data", ftypes.UINT32, nil, base.HEX, nil, "Value")

-- mem header
local mem_header_channel_type_readable = {
    [1] = "M2S_REQ",
    [2] = "M2S_RWD",
    [3] = "M2S_BIRSP",
    [4] = "S2M_BISNP",
    [5] = "S2M_NDR",
    [6] = "S2M_DRS",
}

local mem_header_req_id = ProtoField.new   ("Port Index", "opencxl.mem.port_index", ftypes.UINT8, nil, base.HEX, nil, "Port Index")
local mem_header_channel_t = ProtoField.new   ("Channel Type", "opencxl.mem.channel_t", ftypes.UINT8, mem_header_channel_type_readable, base.HEX, nil, "Channel Type")

-- mem_m2s_req header
local mem_header_m2s_req_opcode_readable = {
    [tonumber("0000", 2)] = "MemInv",
    [tonumber("0001", 2)] = "MemRd",
    [tonumber("0010", 2)] = "MemRdData",
    [tonumber("0011", 2)] = "MemRdFwd",
    [tonumber("0100", 2)] = "MemWrFrd",
    [tonumber("0101", 2)] = "MemRdTEE",
    [tonumber("0110", 2)] = "MemRdDataTEE",
    [tonumber("1000", 2)] = "MemSpecRd",
    [tonumber("1001", 2)] = "MemInvNT",
    [tonumber("1010", 2)] = "MemClnEvct",
    [tonumber("1100", 2)] = "MemSpecRdTEE",
    [tonumber("1101", 2)] = "TEUpdate",
}
local mem_m2s_req_header_valid = ProtoField.new   ("Valid", "opencxl.mem.m2s.req.valid", ftypes.UINT8, nil, base.HEX, 0x1, "Packet Valid?")
local mem_m2s_req_header_mem_opcode = ProtoField.new   ("Mem Opcode", "opencxl.mem.m2s.req.mem_opcode", ftypes.UINT8, mem_header_m2s_req_opcode_readable, base.HEX, 0x1E, "Opcode")
local mem_m2s_req_header_snp_type = ProtoField.new   ("Snoop Type", "opencxl.mem.m2s.req.snp_type", ftypes.UINT8, nil, base.HEX, 0xE0, "Snoop Type")
local mem_m2s_req_header_meta_field = ProtoField.new   ("Meta Field", "opencxl.mem.m2s.req.meta_field", ftypes.UINT8, nil, base.HEX, 0x3, "Meta Field")
local mem_m2s_req_header_meta_value = ProtoField.new   ("Meta Value", "opencxl.mem.m2s.req.meta_value", ftypes.UINT8, nil, base.HEX, 0xC, "Meta Value")
local mem_m2s_req_header_tag = ProtoField.new   ("Tag", "opencxl.mem.m2s.req.tag", ftypes.UINT32, nil, base.HEX, 0xFFFF0, "Tag")
local mem_m2s_req_header_addr = ProtoField.new   ("Host Address << 6", "opencxl.mem.m2s.req.addr", ftypes.UINT64, nil, base.HEX, UInt64(0xFFFFFFF0, 0x0003FFFF), "Address")
local mem_m2s_req_header_ld_id = ProtoField.new   ("Logical Device Identifier", "opencxl.mem.m2s.req.ld_id", ftypes.UINT8, nil, base.HEX, 0x3C, "Logical Device Identifier within a Multiple-Logical Device")
local mem_m2s_req_header_rsvd = ProtoField.new   ("Reserved", "opencxl.mem.m2s.req.rsvd", ftypes.UINT32, nil, base.HEX, 0x3FFFFC, "Reserved")
local mem_m2s_req_header_tc = ProtoField.new   ("Traffic Class", "opencxl.mem.m2s.req.tc", ftypes.UINT8, nil, base.HEX, 0xC, "Traffic Class")
local mem_m2s_req_header_padding = ProtoField.new   ("Padding", "opencxl.mem.m2s.req.padding", ftypes.UINT8, nil, base.HEX, 0xF0, "Reserved")

-- mem_m2s_rwd_header 
local mem_header_m2s_rwd_opcode_readable = {
    [tonumber("0001", 2)] = "MemWr",
    [tonumber("0010", 2)] = "MemWrPtl",
    [tonumber("0100", 2)] = "BIConflict",
    [tonumber("0101", 2)] = "MemRdFill",
    [tonumber("1001", 2)] = "MemWrTEE",
    [tonumber("1010", 2)] = "MemWrPtlTEE",
    [tonumber("1101", 2)] = "MemRdFillTEE",
}
local mem_m2s_rwd_header_valid = ProtoField.new   ("Valid", "opencxl.mem.m2s.rwd.valid", ftypes.UINT8, nil, base.HEX, 0x1, "Packet Valid?")
local mem_m2s_rwd_header_mem_opcode = ProtoField.new   ("Mem Opcode", "opencxl.mem.m2s.rwd.mem_opcode", ftypes.UINT8, mem_header_m2s_rwd_opcode_readable, base.HEX, 0x1E, "Opcode")
local mem_m2s_rwd_header_snp_type = ProtoField.new   ("Snoop Type", "opencxl.mem.m2s.rwd.snp_type", ftypes.UINT8, nil, base.HEX, 0xE0, "Snoop Type")
local mem_m2s_rwd_header_meta_field = ProtoField.new   ("Meta Field", "opencxl.mem.m2s.rwd.meta_field", ftypes.UINT8, nil, base.HEX, 0x3, "Meta Field")
local mem_m2s_rwd_header_meta_value = ProtoField.new   ("Meta Value", "opencxl.mem.m2s.rwd.meta_value", ftypes.UINT8, nil, base.HEX, 0xC, "Meta Value")
local mem_m2s_rwd_header_tag = ProtoField.new   ("Tag", "opencxl.mem.m2s.rwd.tag", ftypes.UINT32, nil, base.HEX, 0xFFFF0, "Tag")
local mem_m2s_rwd_header_addr = ProtoField.new   ("Host Address << 6", "opencxl.mem.m2s.rwd.addr", ftypes.UINT64, nil, base.HEX, UInt64(0xFFFFFFF0, 0x0003FFFF), "Address")
local mem_m2s_rwd_header_poison = ProtoField.new   ("Poison", "opencxl.mem.m2s.rwd.poison", ftypes.UINT8, nil, base.HEX, 0x04, "Poison")
local mem_m2s_rwd_header_bep = ProtoField.new   ("Trailer Present", "opencxl.mem.m2s.rwd.bep", ftypes.UINT8, nil, base.HEX, 0x08, "Trailer Present (formerly BEP)")
local mem_m2s_rwd_header_ld_id = ProtoField.new   ("Logical Device Identifier", "opencxl.mem.m2s.rwd.ld_id", ftypes.UINT8, nil, base.HEX, 0xF0, "Logical Device Identifier within a Multiple-Logical Device")
local mem_m2s_rwd_header_ck_id = ProtoField.new   ("Context Key ID", "opencxl.mem.m2s.rwd.ck_id", ftypes.UINT16, nil, base.HEX, 0x1FFF, "Optional key ID")
local mem_m2s_rwd_header_rsvd = ProtoField.new   ("Reserved", "opencxl.mem.m2s.rwd.rsvd", ftypes.UINT16, nil, base.HEX, 0x3FE, "Reserved")
local mem_m2s_rwd_header_tc = ProtoField.new   ("Traffic Class", "opencxl.mem.m2s.rwd.tc", ftypes.UINT8, nil, base.HEX, 0xC, "Traffic Class")
local mem_m2s_rwd_data = ProtoField.new   ("Data (Hex)", "opencxl.mem.m2s.rwd.data", ftypes.BYTES, nil, base.SPACE, nil, "Data")

-- mem_m2s_birsp_header
local mem_header_m2s_birsp_opcode_readable = {
    [tonumber("0000", 2)] = "BIRspI",
    [tonumber("0001", 2)] = "BIRspS",
    [tonumber("0010", 2)] = "BIRspE",
    [tonumber("0100", 2)] = "BIRspIBlk",
    [tonumber("0101", 2)] = "BIRspSBlk",
    [tonumber("0110", 2)] = "BIRspEBlk",
}
local mem_m2s_birsp_header_valid = ProtoField.new   ("Valid", "opencxl.mem.m2s.birsp.valid", ftypes.UINT32, nil, base.HEX, 0x1, "Packet Valid?")
local mem_m2s_birsp_header_mem_opcode = ProtoField.new   ("Valid", "opencxl.mem.m2s.birsp.mem_opcode", ftypes.UINT32, mem_header_m2s_birsp_opcode_readable, base.HEX, 0x1E, "Opcode")
local mem_m2s_birsp_header_bi_id = ProtoField.new   ("BI ID", "opencxl.mem.m2s.birsp.bi_id", ftypes.UINT32, nil, base.HEX, 0x1FFE0, "BI ID")
local mem_m2s_birsp_header_bi_tag = ProtoField.new   ("BI Tag", "opencxl.mem.m2s.birsp.bi_tag", ftypes.UINT32, nil, base.HEX, 0x1FFE0000, "BI Tag")
local mem_m2s_birsp_header_low_addr = ProtoField.new   ("Cacheline addr low 2 bits", "opencxl.mem.m2s.birsp.low_addr", ftypes.UINT32, nil, base.HEX, 0x60000000, "The lower 2 bits of cacheline address")
local mem_m2s_birsp_header_rsvd = ProtoField.new   ("Reserved", "opencxl.mem.m2s.birsp.low_addr", ftypes.UINT16, nil, base.HEX, 0xFF8, "Reserved")

-- mem_s2m_bisnp_header
local mem_header_s2m_bisnp_opcode_readable = {
    [tonumber("0000", 2)] = "BISnpCur",
    [tonumber("0001", 2)] = "BISnpData",
    [tonumber("0010", 2)] = "BISnpInv",
    [tonumber("0100", 2)] = "BISnpCurBlk",
    [tonumber("0101", 2)] = "BISnpDataBlk",
    [tonumber("0110", 2)] = "BISnpInvBlk",
}
local mem_s2m_bisnp_header_valid = ProtoField.new   ("Valid", "opencxl.mem.s2m.bisnp.valid", ftypes.UINT32, nil, base.HEX, 0x1, "Packet Valid?")
local mem_s2m_bisnp_header_mem_opcode = ProtoField.new   ("Valid", "opencxl.mem.s2m.bisnp.mem_opcode", ftypes.UINT32, mem_header_s2m_bisnp_opcode_readable, base.HEX, 0x1E, "Opcode")
local mem_s2m_bisnp_header_bi_id = ProtoField.new   ("BI ID", "opencxl.mem.s2m.bisnp.bi_id", ftypes.UINT32, nil, base.HEX, 0x1FFE0, "BI ID")
local mem_s2m_bisnp_header_bi_tag = ProtoField.new   ("BI Tag", "opencxl.mem.s2m.bisnp.bi_tag", ftypes.UINT32, nil, base.HEX, 0x1FFE0000, "BI Tag")
local mem_s2m_bisnp_header_addr = ProtoField.new   ("Address << 6", "opencxl.mem.s2m.bisnp.addr", ftypes.UINT64, nil, base.HEX, UInt64(0xFFFFFFFE, 0x00007FFF), "Address")
local mem_s2m_bisnp_header_rsvd = ProtoField.new   ("Reserved", "opencxl.mem.s2m.bisnp.rsvd", ftypes.UINT16, nil, base.HEX, 0xFF8, "Reserved")


-- mem_s2m_ndr_header 
local mem_header_s2m_ndr_opcode_readable = {
    [tonumber("000", 2)] = "Cmp",
    [tonumber("001", 2)] = "Cmp-S",
    [tonumber("010", 2)] = "Cmp-E",
    [tonumber("011", 2)] = "Cmp-M",
    [tonumber("100", 2)] = "BI-ConflictAck",
    [tonumber("101", 2)] = "CmpTEE",
}

local mem_header_s2m_devload_readable = {
    [tonumber("00", 2)] = "Light",
    [tonumber("01", 2)] = "Optimal",
    [tonumber("10", 2)] = "Moderate",
    [tonumber("11", 2)] = "Severe",
}
local mem_s2m_ndr_header_valid = ProtoField.new   ("Valid", "opencxl.mem.s2m.ndr.valid", ftypes.UINT8, nil, base.HEX, 0x01, "Packet Valid?")
local mem_s2m_ndr_header_mem_opcode = ProtoField.new   ("Mem Opcode", "opencxl.mem.s2m.ndr.mem_opcode", ftypes.UINT8, mem_header_s2m_ndr_opcode_readable, base.HEX, 0x0E, "Opcode")
local mem_s2m_ndr_header_meta_field = ProtoField.new   ("Meta Field", "opencxl.mem.s2m.ndr.meta_field", ftypes.UINT8, nil, base.HEX, 0x30, "Meta Field")
local mem_s2m_ndr_header_meta_value = ProtoField.new   ("Meta Value", "opencxl.mem.s2m.ndr.meta_value", ftypes.UINT8, nil, base.HEX, 0xC0, "Meta Value")
local mem_s2m_ndr_header_tag = ProtoField.new   ("Tag", "opencxl.mem.s2m.ndr.tag", ftypes.UINT16, nil, base.HEX, 0xFFFF, "Tag")
local mem_s2m_ndr_ld_id = ProtoField.new   ("Logical Device Identifier", "opencxl.mem.s2m.ndr.ld_id", ftypes.UINT16, nil, base.HEX, 0x000F, "Logical Device Identifier within a Multiple-Logical Device")
local mem_s2m_ndr_dev_load = ProtoField.new   ("Device Load", "opencxl.mem.s2m.ndr.dev_load", ftypes.UINT16, mem_header_s2m_devload_readable, base.HEX, 0x0030, "For QoS enforcement")
local mem_s2m_ndr_rsvd = ProtoField.new   ("Reserved", "opencxl.mem.s2m.ndr.rsvd", ftypes.UINT16, nil, base.HEX, 0xFFC0, "Reserved")

-- mem_s2m_drs_header 
local mem_header_s2m_drs_opcode_readable = {
    [tonumber("000", 2)] = "MemData",
    [tonumber("001", 2)] = "MemData-NXM",
    [tonumber("010", 2)] = "MemDataTEE",
}
local mem_s2m_drs_header_valid = ProtoField.new   ("Valid", "opencxl.mem.s2m.drs.valid", ftypes.UINT8, nil, base.HEX, 0x01, "Packet Valid?")
local mem_s2m_drs_header_mem_opcode = ProtoField.new   ("Mem Opcode", "opencxl.mem.s2m.drs.mem_opcode", ftypes.UINT8, mem_header_s2m_drs_opcode_readable, base.HEX, 0x0E, "Opcode")
local mem_s2m_drs_header_meta_field = ProtoField.new   ("Meta Field", "opencxl.mem.s2m.drs.meta_field", ftypes.UINT8, nil, base.HEX, 0x30, "Meta Field")
local mem_s2m_drs_header_meta_value = ProtoField.new   ("Meta Value", "opencxl.mem.s2m.drs.meta_value", ftypes.UINT8, nil, base.HEX, 0xC0, "Meta Value")
local mem_s2m_drs_header_tag = ProtoField.new   ("Tag", "opencxl.mem.s2m.drs.tag", ftypes.UINT16, nil, base.HEX, 0xFFFF, "Tag")
local mem_s2m_drs_poison = ProtoField.new   ("Poison", "opencxl.mem.s2m.drs.poison", ftypes.UINT8, nil, base.HEX, 0x01, "Poison")
local mem_s2m_drs_ld_id = ProtoField.new   ("Logical Device Identifier", "opencxl.mem.s2m.drs.ld_id", ftypes.UINT8, nil, base.HEX, 0x1E, "Logical Device Identifier within a Multiple-Logical Device")
local mem_s2m_drs_dev_load = ProtoField.new   ("Device Load", "opencxl.mem.s2m.drs.dev_load", ftypes.UINT8, mem_header_s2m_devload_readable, base.HEX, 0x60, "For QoS enforcement")
local mem_s2m_drs_trp = ProtoField.new   ("Trailer Present", "opencxl.mem.s2m.drs.trp", ftypes.UINT8, nil, base.HEX, 0x80, "Trailer included after the 64B payload?")
local mem_s2m_drs_rsvd = ProtoField.new   ("Reserved", "opencxl.mem.s2m.drs.rsvd", ftypes.UINT8, nil, base.HEX, nil, "Reserved")
local mem_s2m_drs_data = ProtoField.new   ("Data (Hex)", "opencxl.mem.s2m.drs.data", ftypes.BYTES, nil, base.SPACE, nil, "Data")


----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set opencxl.fields to it, so as to avoid forgetting a field
opencxl.fields = { sys_header_payload_type, sys_header_payload_len, io_header_fmt_type, io_header_th, io_header_rsvd, io_header_attr_b2, io_header_t8, io_header_tc, io_header_t9, io_header_length_upper, io_header_at, io_header_attr, io_header_ep, io_header_td, io_header_length_lower, io_mreq_header_req_id, io_mreq_header_tag, io_mreq_header_first_dw_be, io_mreq_header_last_dw_be, io_mreq_header_addr_upper, io_mreq_header_rsvd, io_mreq_header_addr_lower, io_cpl_header_cpl_id, io_cpl_header_byte_upper, io_cpl_header_bcm, io_cpl_header_status, io_cpl_header_byte_lower, io_cpl_header_req_id, io_cpl_header_tag, io_cpl_lower_addr, io_cpl_rsvd, io_cpl_data_32b, io_cpl_data_64b, io_cfg_header_req_id, io_cfg_header_tag, io_cfg_header_first_dw_be, io_cfg_header_last_dw_be, io_cfg_header_dest_id, io_cfg_header_ext_reg_num, io_cfg_header_rsvd, io_cfg_header_r, io_cfg_header_reg_num, io_cfg_header_data, mem_header_req_id, mem_header_channel_t, mem_m2s_req_header_valid, mem_m2s_req_header_mem_opcode, mem_m2s_req_header_snp_type, mem_m2s_req_header_meta_field, mem_m2s_req_header_meta_value, mem_m2s_req_header_tag, mem_m2s_req_header_addr, mem_m2s_req_header_ld_id, mem_m2s_req_header_rsvd, mem_m2s_req_header_tc, mem_m2s_req_header_padding, mem_m2s_rwd_header_valid, mem_m2s_rwd_header_mem_opcode, mem_m2s_rwd_header_snp_type, mem_m2s_rwd_header_meta_field, mem_m2s_rwd_header_meta_value, mem_m2s_rwd_header_tag, mem_m2s_rwd_header_addr, mem_m2s_rwd_header_poison, mem_m2s_rwd_header_bep, mem_m2s_rwd_header_ld_id, mem_m2s_rwd_header_ck_id, mem_m2s_rwd_header_rsvd, mem_m2s_rwd_header_tc, mem_m2s_rwd_data, mem_m2s_birsp_header_valid, mem_m2s_birsp_header_mem_opcode, mem_m2s_birsp_header_bi_id, mem_m2s_birsp_header_bi_tag, mem_m2s_birsp_header_low_addr, mem_m2s_birsp_header_rsvd, mem_s2m_bisnp_header_valid, mem_s2m_bisnp_header_mem_opcode, mem_s2m_bisnp_header_bi_id, mem_s2m_bisnp_header_bi_tag, mem_s2m_bisnp_header_addr, mem_s2m_bisnp_rsvd, mem_s2m_bisnp_header_rsvd, mem_s2m_ndr_header_valid, mem_s2m_ndr_header_mem_opcode, mem_s2m_ndr_header_meta_field, mem_s2m_ndr_header_meta_value, mem_s2m_ndr_header_tag, mem_s2m_ndr_ld_id, mem_s2m_ndr_dev_load, mem_s2m_ndr_rsvd, mem_s2m_drs_header_valid, mem_s2m_drs_header_mem_opcode, mem_s2m_drs_header_meta_field, mem_s2m_drs_header_meta_value, mem_s2m_drs_header_tag, mem_s2m_drs_poison, mem_s2m_drs_ld_id, mem_s2m_drs_dev_load, mem_s2m_drs_trp, mem_s2m_drs_rsvd, mem_s2m_drs_data }


local ef_too_short = ProtoExpert.new("opencxl.too_short.expert", "OpenCXL message too short",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_sys_header = ProtoExpert.new("opencxl.sys_header.expert", "Packet information",
                                     expert.group.RESPONSE_CODE, expert.severity.CHAT)
opencxl.experts = { ef_too_short, ef_sys_header }

----------------------------------------
-- we don't just want to display our protocol's fields, we want to access the value of some of them too!
-- There are several ways to do that.  One is to just parse the buffer contents in Lua code to find
-- the values.  But since ProtoFields actually do the parsing for us, and can be retrieved using Field
-- objects, it's kinda cool to do it that way. So let's create some Fields to extract the values.
-- The following creates the Field objects, but they're not 'registered' until after this script is loaded.
-- Also, these lines can't be before the 'opencxl.fields = ...' line above, because the Field.new() here is
-- referencing fields we're creating, and they're not "created" until that line above.
-- Furthermore, you cannot put these 'Field.new()' lines inside the dissector function.
-- Before Wireshark version 1.11, you couldn't even do this concept (of using fields you just created).
local payload_type_field       = Field.new("opencxl.system.payload_type")
local payload_len_field      = Field.new("opencxl.system.payload_len")
local io_header_fmt_type_field      = Field.new("opencxl.io.fmt_type")
local io_header_len_upper_field      = Field.new("opencxl.io.length_upper")
local io_header_len_lower_field      = Field.new("opencxl.io.length_lower")
local io_mreq_header_addr_upper_field      = Field.new("opencxl.io.mreq.addr_upper")
local io_mreq_header_addr_lower_field     = Field.new("opencxl.io.mreq.addr_lower")
local io_cpl_header_addr_upper_field      = Field.new("opencxl.io.cpl.byte_upper")
local io_cpl_header_addr_lower_field     = Field.new("opencxl.io.cpl.byte_lower")
local mem_header_channel_t_field     = Field.new("opencxl.mem.channel_t")
local mem_m2s_req_header_opcode_field     = Field.new("opencxl.mem.m2s.req.mem_opcode")
local mem_m2s_req_header_addr_field   = Field.new("opencxl.mem.m2s.req.addr")
local mem_m2s_rwd_header_opcode_field     = Field.new("opencxl.mem.m2s.rwd.mem_opcode")
local mem_m2s_rwd_header_addr_field   = Field.new("opencxl.mem.m2s.rwd.addr")
local mem_m2s_birsp_header_opcode_field     = Field.new("opencxl.mem.m2s.birsp.mem_opcode")
local mem_m2s_birsp_header_low_addr_field   = Field.new("opencxl.mem.m2s.birsp.low_addr")
local mem_m2s_birsp_header_bi_id_field   = Field.new("opencxl.mem.m2s.birsp.bi_id")
local mem_m2s_birsp_header_bi_tag_field   = Field.new("opencxl.mem.m2s.birsp.bi_tag")
local mem_s2m_bisnp_header_opcode_field     = Field.new("opencxl.mem.s2m.bisnp.mem_opcode")
local mem_s2m_bisnp_header_addr_field   = Field.new("opencxl.mem.s2m.bisnp.addr")
local mem_s2m_bisnp_header_bi_id_field   = Field.new("opencxl.mem.s2m.bisnp.bi_id")
local mem_s2m_bisnp_header_bi_tag_field   = Field.new("opencxl.mem.s2m.bisnp.bi_tag")
local mem_s2m_ndr_header_opcode_field     = Field.new("opencxl.mem.s2m.ndr.mem_opcode")
local mem_s2m_drs_header_opcode_field     = Field.new("opencxl.mem.s2m.drs.mem_opcode")

-- here's a little helper function to access the response_field value later.
-- Like any Field retrieval, you can't retrieve a field's value until its value has been
-- set, which won't happen until we actually use our ProtoFields in TreeItem:add() calls.
-- So this isResponse() function can't be used until after the pf_flag_response ProtoField
-- has been used inside the dissector.
-- Note that calling the Field object returns a FieldInfo object, and calling that
-- returns the value of the field - in this case a boolean true/false, since we set the
-- "opencxl.flags.response" ProtoField to ftype.BOOLEAN way earlier when we created the
-- pf_flag_response ProtoField.  Clear as mud?
--
-- A shorter version of this function would be:
-- local function isResponse() return response_field()() end
-- but I though the below is easier to understand.

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.
local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

opencxl.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
                            "The debug printing level", debug_pref_enum)

opencxl.prefs.port  = Pref.uint("Port number", default_settings.port,
                            "The TCP port number for OpenCXL")

opencxl.prefs.heur  = Pref.bool("Heuristic enabled", default_settings.heur_enabled,
                            "Whether heuristic dissection is enabled or not")

----------------------------------------
-- a function for handling prefs being changed
function opencxl.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level  = opencxl.prefs.debug
    reset_debug_level()

    default_settings.heur_enabled = opencxl.prefs.heur

    if default_settings.port ~= opencxl.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            dprint2("removing OpenCXL from port",default_settings.port)
            DissectorTable.get("tcp.port"):remove(default_settings.port, opencxl)
        end
        -- set our new default
        default_settings.port = opencxl.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            dprint2("adding OpenCXL to port",default_settings.port)
            DissectorTable.get("tcp.port"):add(default_settings.port, opencxl)
        end
    end

end

dprint2("OpenCxl Prefs registered")


----------------------------------------
---- some constants for later use ----
-- the OpenCXL header size
local OPENCXL_HDR_LEN = 2

----------------------------------------
-- some forward "declarations" of helper functions we use in the dissector
-- I don't usually use this trick, but it'll help reading/grok'ing this script I think
-- if we don't focus on them.
local getQueryName

function get_cxl_header_type(val)
    return sys_header_payload_type_readable[val]
end

function get_cxl_io_type(val)
    return io_header_payload_type_readable[val]
end

function get_cxl_mem_type(val)
    return mem_header_channel_type_readable[val]
end

function get_cxl_mem_m2s_req_opcode_type(val)
    return mem_header_m2s_req_opcode_readable[val]
end

function get_cxl_mem_m2s_rwd_opcode_type(val)
    return mem_header_m2s_rwd_opcode_readable[val]
end

function get_cxl_mem_m2s_birsp_opcode_type(val)
    return mem_header_m2s_birsp_opcode_readable[val]
end

function get_cxl_mem_s2m_bisnp_opcode_type(val)
    return mem_header_s2m_bisnp_opcode_readable[val]
end

function get_cxl_mem_s2m_ndr_opcode_type(val)
    return mem_header_s2m_ndr_opcode_readable[val]
end

function get_cxl_mem_s2m_drs_opcode_type(val)
    return mem_header_s2m_drs_opcode_readable[val]
end

function handle_cpl_d()

end

function int(ud)
    return tonumber(tostring(ud()()))
end

----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "opencxl.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function opencxl.dissector(tvbuf,pktinfo,root)
    dprint2("opencxl.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("OpenCXL")

    -- We want to check that the packet size is rational during dissection, so let's get the length of the
    -- packet buffer (Tvb).
    -- Because OpenCXL has no additional payload data other than itself, and it rides on TCP without padding,
    -- we can use tvb:len() or tvb:reported_len() here; but I prefer tvb:reported_length_remaining() as it's safer.
    local pktlen = tvbuf:reported_length_remaining()

    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
    -- The second argument is how much of the buffer/packet this added tree item covers/represents - in this
    -- case (OpenCXL protocol) that's the remainder of the packet.
    local tree = root:add(opencxl, tvbuf:range(0,2))
    local system_header_tree = tree:add(opencxl_header, tvbuf:range(0,2))
    
    -- now let's check it's not too short
    if pktlen < OPENCXL_HDR_LEN then
        -- since we're going to add this protocol to a specific UDP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        -- the old way: tree:add_expert_info(PI_MALFORMED, PI_ERROR, "packet too short")
        -- the correct way now:
        tree:add_proto_expert_info(ef_too_short)
        dprint("packet length",pktlen,"too short")
        return
    end

    -- Now let's add our transaction id under our OpenCXL protocol tree we just created.
    -- The transaction id starts at offset 0, for 2 bytes length.
    system_header_tree:add_le(sys_header_payload_type, tvbuf:range(0,2):le_uint())
    system_header_tree:add_le(sys_header_payload_len, tvbuf:range(0,2):le_uint())
    system_header_tree:append_text(", Payload type: ".. get_cxl_header_type(payload_type_field()()) ..", Payload length: ".. payload_len_field()() .." bytes")
    pktinfo.cols.info:set("Type: ".. get_cxl_header_type(payload_type_field()()) .. " ")

    if get_cxl_header_type(payload_type_field()()) == "CXL.io" then 
        -- CXL.io cxl_io_header_t
        local io_header_tree = tree:add(opencxl_io_header, tvbuf:range(2,4))
        io_header_tree:add_le(io_header_fmt_type, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_th, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_rsvd, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_attr_b2, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_t8, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_tc, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_t9, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_length_upper, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_at, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_attr, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_ep, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_td, tvbuf:range(2,4):le_uint())
        io_header_tree:add_le(io_header_length_lower, tvbuf:range(2,4):le_uint())

        local io_header_len = ((int(io_header_len_upper_field) << 8) + int(io_header_len_lower_field))

        io_header_tree:append_text(", Type: ".. get_cxl_io_type(io_header_fmt_type_field()()) .. ", Length (in DWORDs): " .. io_header_len)
        pktinfo.cols.info:append( get_cxl_io_type(io_header_fmt_type_field()()) .. ", " .. io_header_len .. " DWORD" .. (io_header_len == 1 and "" or "s"))

        if get_cxl_io_type(io_header_fmt_type_field()()) == "MRD_32B" or get_cxl_io_type(io_header_fmt_type_field()()) == "MRD_64B" then
            -- mreq_header
            local io_mreq_header_tree = tree:add(opencxl_mreq_header, tvbuf:range(6,12))
            io_mreq_header_tree:add_le(io_mreq_header_req_id, tvbuf:range(6,2))
            io_mreq_header_tree:add_le(io_mreq_header_tag, tvbuf:range(8,1))
            io_mreq_header_tree:add_le(io_mreq_header_first_dw_be, tvbuf:range(9,1))
            io_mreq_header_tree:add_le(io_mreq_header_last_dw_be, tvbuf:range(9,1))
            io_mreq_header_tree:add(io_mreq_header_addr_upper, tvbuf:range(10,8))
            io_mreq_header_tree:add(io_mreq_header_addr_lower, tvbuf:range(10,8))
            io_mreq_header_tree:add_le(io_mreq_header_rsvd, tvbuf:range(10,8))

            io_mreq_header_tree:append_text(string.format(", Address: 0x%016x", ((int(io_mreq_header_addr_upper_field) << 8) | (int(io_mreq_header_addr_lower_field) << 2))))
        end

        if get_cxl_io_type(io_header_fmt_type_field()()) == "CPL_D" or get_cxl_io_type(io_header_fmt_type_field()()) == "CPL" then
            local io_cpl_header_tree = tree:add(opencxl_cpl_packet, tvbuf:range(6,8))
            io_cpl_header_tree:add_le(io_cpl_header_cpl_id, tvbuf:range(6,2))
            io_cpl_header_tree:add_le(io_cpl_header_byte_upper, tvbuf:range(8,1))
            io_cpl_header_tree:add_le(io_cpl_header_bcm, tvbuf:range(8,1))
            io_cpl_header_tree:add_le(io_cpl_header_status, tvbuf:range(8,1))
            io_cpl_header_tree:add_le(io_cpl_header_byte_lower, tvbuf:range(9,1))
            io_cpl_header_tree:add_le(io_cpl_header_req_id, tvbuf:range(10,2))
            io_cpl_header_tree:add_le(io_cpl_header_tag, tvbuf:range(12,1))
            io_cpl_header_tree:add_le(io_cpl_lower_addr, tvbuf:range(13,1))
            io_cpl_header_tree:add_le(io_cpl_rsvd, tvbuf:range(13,1))

            local total_bytes = (int(io_cpl_header_addr_upper_field) << 8) | int(io_cpl_header_addr_lower_field)

            if get_cxl_io_type(io_header_fmt_type_field()()) == "CPL_D" then
                if total_bytes == 4 then
                    io_cpl_header_tree:add_le(io_cpl_data_32b, tvbuf:range(14,4))
                elseif total_bytes == 8 then
                    io_cpl_header_tree:add_le(io_cpl_data_64b, tvbuf:range(14,8))
                end
            end
        end

        if string.sub(get_cxl_io_type(io_header_fmt_type_field()()), 1, 4) == "CFG_" then -- match CFG_WR and CFG_RD
            local io_cfg_header_tree = tree:add(opencxl_cfg_packet, tvbuf:range(6,8))
            io_cfg_header_tree:add_le(io_cfg_header_req_id, tvbuf:range(6,2))
            io_cfg_header_tree:add_le(io_cfg_header_tag, tvbuf:range(8,1))
            io_cfg_header_tree:add_le(io_cfg_header_first_dw_be, tvbuf:range(9,1))
            io_cfg_header_tree:add_le(io_cfg_header_last_dw_be, tvbuf:range(9,1))
            io_cfg_header_tree:add_le(io_cfg_header_dest_id, tvbuf:range(10,2))
            io_cfg_header_tree:add_le(io_cfg_header_ext_reg_num, tvbuf:range(12,1))
            io_cfg_header_tree:add_le(io_cfg_header_rsvd, tvbuf:range(12,1))
            io_cfg_header_tree:add_le(io_cfg_header_r, tvbuf:range(13,1))
            io_cfg_header_tree:add_le(io_cfg_header_reg_num, tvbuf:range(13,1))
            if string.sub(get_cxl_io_type(io_header_fmt_type_field()()), 1, 6) == "CFG_WR" then
                io_cfg_header_tree:add_le(io_cfg_header_data, tvbuf:range(14,4))
            end
        end
    elseif get_cxl_header_type(payload_type_field()()) == "CXL.mem" then
        local mem_header_tree = tree:add(opencxl_mem_header, tvbuf:range(2,2))
        mem_header_tree:add_le(mem_header_req_id, tvbuf:range(2,1))
        mem_header_tree:add_le(mem_header_channel_t, tvbuf:range(3,1))
        pktinfo.cols.info:append(get_cxl_mem_type(mem_header_channel_t_field()()))
        if get_cxl_mem_type(mem_header_channel_t_field()()) == "M2S_REQ" then
            local m2s_req_header_tree = tree:add(opencxl_m2s_req_header, tvbuf:range(4,13))
            m2s_req_header_tree:add_le(mem_m2s_req_header_valid, tvbuf:range(4,1))
            m2s_req_header_tree:add_le(mem_m2s_req_header_mem_opcode, tvbuf:range(4,1))
            m2s_req_header_tree:add_le(mem_m2s_req_header_snp_type, tvbuf:range(4,1))
            m2s_req_header_tree:add_le(mem_m2s_req_header_meta_field, tvbuf:range(5,1))
            m2s_req_header_tree:add_le(mem_m2s_req_header_meta_value, tvbuf:range(5,1))
            m2s_req_header_tree:add_le(mem_m2s_req_header_tag, tvbuf:range(5,3))
            m2s_req_header_tree:add_le(mem_m2s_req_header_addr, tvbuf:range(7,7))
            m2s_req_header_tree:add_le(mem_m2s_req_header_ld_id, tvbuf:range(13,1))
            m2s_req_header_tree:add_le(mem_m2s_req_header_rsvd, tvbuf:range(13,4))
            m2s_req_header_tree:add_le(mem_m2s_req_header_tc, tvbuf:range(16,1))
            m2s_req_header_tree:add_le(mem_m2s_req_header_padding, tvbuf:range(16,1))
            m2s_req_header_tree:append_text(", Type: " .. get_cxl_mem_m2s_req_opcode_type(mem_m2s_req_header_opcode_field()()) .. string.format(", Address: 0x%016x", (int(mem_m2s_req_header_addr_field) << 6)))
        elseif get_cxl_mem_type(mem_header_channel_t_field()()) == "M2S_RWD" then
            local m2s_rwd_header_tree = tree:add(opencxl_m2s_rwd_header, tvbuf:range(4))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_valid, tvbuf:range(4,1))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_mem_opcode, tvbuf:range(4,1))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_snp_type, tvbuf:range(4,1))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_meta_field, tvbuf:range(5,1))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_meta_value, tvbuf:range(5,1))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_tag, tvbuf:range(5,3))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_addr, tvbuf:range(7,7))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_poison, tvbuf:range(13,1))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_bep, tvbuf:range(13,1))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_ld_id, tvbuf:range(13,2))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_ck_id, tvbuf:range(14,2))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_rsvd, tvbuf:range(14,2))
            m2s_rwd_header_tree:add_le(mem_m2s_rwd_header_tc, tvbuf:range(16,1))

            m2s_rwd_header_tree:add_le(mem_m2s_rwd_data, tvbuf:range(17,64))
            m2s_rwd_header_tree:append_text(", Type: " .. get_cxl_mem_m2s_rwd_opcode_type(mem_m2s_rwd_header_opcode_field()()) .. string.format(", Address: 0x%016x", (int(mem_m2s_rwd_header_addr_field) << 6)))
        elseif get_cxl_mem_type(mem_header_channel_t_field()()) == "M2S_BIRSP" then
            local m2s_birsp_header_tree = tree:add(opencxl_m2s_birsp_header, tvbuf:range(4))
            m2s_birsp_header_tree:add_le(mem_m2s_birsp_header_valid, tvbuf:range(4,4))
            m2s_birsp_header_tree:add_le(mem_m2s_birsp_header_mem_opcode, tvbuf:range(4,4))
            m2s_birsp_header_tree:add_le(mem_m2s_birsp_header_bi_id, tvbuf:range(4,4))
            m2s_birsp_header_tree:add_le(mem_m2s_birsp_header_bi_tag, tvbuf:range(4,4))
            m2s_birsp_header_tree:add_le(mem_m2s_birsp_header_low_addr, tvbuf:range(4,4))
            m2s_birsp_header_tree:add_le(mem_m2s_birsp_header_rsvd, tvbuf:range(7,2))

            m2s_birsp_header_tree:append_text(", Type: " .. get_cxl_mem_m2s_birsp_opcode_type(mem_m2s_birsp_header_opcode_field()()) .. string.format(", BI-ID: 0x%03x", int(mem_m2s_birsp_header_bi_id_field)) .. string.format(", BI Tag: 0x%03x", int(mem_m2s_birsp_header_bi_tag_field)))

            -- TODO: trailing information could exist if bep == 1 (now the bit is for trailer included, AKA TRP)

        elseif get_cxl_mem_type(mem_header_channel_t_field()()) == "S2M_BISNP" then
            local s2m_bisnp_header_tree = tree:add(opencxl_s2m_bisnp_header, tvbuf:range(4))
            s2m_bisnp_header_tree:add_le(mem_s2m_bisnp_header_valid, tvbuf:range(4,4))
            s2m_bisnp_header_tree:add_le(mem_s2m_bisnp_header_mem_opcode, tvbuf:range(4,4))
            s2m_bisnp_header_tree:add_le(mem_s2m_bisnp_header_bi_id, tvbuf:range(4,4))
            s2m_bisnp_header_tree:add_le(mem_s2m_bisnp_header_bi_tag, tvbuf:range(4,4))
            s2m_bisnp_header_tree:add_le(mem_s2m_bisnp_header_addr, tvbuf:range(7,7))
            s2m_bisnp_header_tree:add_le(mem_s2m_bisnp_header_rsvd, tvbuf:range(13,1))

            s2m_bisnp_header_tree:append_text(", Type: " .. get_cxl_mem_s2m_bisnp_opcode_type(mem_s2m_bisnp_header_opcode_field()()) .. string.format(", BI-ID: 0x%03x", int(mem_s2m_bisnp_header_bi_id_field)) .. string.format(", BI Tag: 0x%03x", int(mem_s2m_bisnp_header_bi_tag_field)))
            
            
        elseif get_cxl_mem_type(mem_header_channel_t_field()()) == "S2M_NDR" then
            local s2m_ndr_header_tree = tree:add(opencxl_s2m_ndr_header, tvbuf:range(4))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_header_valid, tvbuf:range(4,1))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_header_mem_opcode, tvbuf:range(4,1))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_header_meta_field, tvbuf:range(4,1))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_header_meta_value, tvbuf:range(4,1))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_header_tag, tvbuf:range(5,2))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_ld_id, tvbuf:range(7,2))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_dev_load, tvbuf:range(7,2))
            s2m_ndr_header_tree:add_le(mem_s2m_ndr_rsvd, tvbuf:range(7,2))
            s2m_ndr_header_tree:append_text(", Type: " .. get_cxl_mem_s2m_ndr_opcode_type(mem_s2m_ndr_header_opcode_field()()))
        elseif get_cxl_mem_type(mem_header_channel_t_field()()) == "S2M_DRS" then
            local s2m_drs_header_tree = tree:add(opencxl_s2m_drs_header, tvbuf:range(4))
            s2m_drs_header_tree:add_le(mem_s2m_drs_header_valid, tvbuf:range(4,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_header_mem_opcode, tvbuf:range(4,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_header_meta_field, tvbuf:range(4,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_header_meta_value, tvbuf:range(4,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_header_tag, tvbuf:range(5,2))
            s2m_drs_header_tree:add_le(mem_s2m_drs_poison, tvbuf:range(7,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_ld_id, tvbuf:range(7,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_dev_load, tvbuf:range(7,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_trp, tvbuf:range(7,1))
            s2m_drs_header_tree:add_le(mem_s2m_drs_rsvd, tvbuf:range(8,1))

            s2m_drs_header_tree:add_le(mem_s2m_drs_data, tvbuf:range(9,64))

            s2m_drs_header_tree:append_text(", Type: " .. get_cxl_mem_s2m_drs_opcode_type(mem_s2m_drs_header_opcode_field()()))
        end
    end

    dprint2("opencxl.dissector returning", pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

----------------------------------------
-- we want to have our protocol dissection invoked for a specific UDP port,
-- so get the udp dissector table and add our protocol to it
DissectorTable.get("tcp.port"):add(default_settings.port, opencxl)


-- We're done!
-- our protocol (Proto) gets automatically registered after this script finishes loading
----------------------------------------
