---------------------------------------------------------------------------------------
-- Lua module to parse a Portable Executable (.exe , .dll, etc.) file and extract metadata.
--
-- Version 0.1, [copyright (c) 2013 - Thijs Schreijer](http://www.thijsschreijer.nl)
-- @name pe-parser
-- @class module

local M = {}

local function get_int(str)
  -- convert a byte-sequence to an integer
  assert(str)
  local r = 0
  for i = #str, 1, -1 do
    r = r*256 + string.byte(str,i,i)
  end
  return r
end

local function get_list(list, f, add_to)
  -- list of tables with 'size' and 'name' and is_str
  local r = add_to or {}
  for i, t in ipairs(list) do
    local val,err = f:read(t.size)  -- read specified size in bytes
    if t.is_str then
      for i = 1, #val do
        if val:sub(i,i) == "\0" then
          r[t.name] = val:sub(1,i-1)
          break
        end
      end
      r[t.name] = r[t.name] or val
    else
      r[t.name] = get_int(val)
    end
  end
  return r
end

--- Calculates the fileoffset of a given RVA.
-- This function is also available as a method on the parsed output table
-- @param obj a parsed object (return value from `parse`)
-- @param RVA an RVA value to convert to a fileoffset
-- @return fileoffset of the given RVA
M.get_fileoffset = function(obj, RVA)
  -- given an object with a section table, and an RVA, it returns
  -- the fileoffset for the data
  local section
  for i, s in ipairs(obj.Sections) do
    if s.VirtualAddress <= RVA and s.VirtualAddress + s.VirtualSize >= RVA then
      section = s
      break
    end
  end
  if not section then return nil, "No match RVA with Section list, RVA out of bounds" end
  return RVA - section.VirtualAddress + section.PointerToRawData
end

local function readstring(f)
  -- reads a null-terminated string from the current file posistion
  local name = ""
  while true do
    local c = f:read(1)
    if c == "\0" then break end
    name = name .. c
  end
  return name
end

--- Parses a file and extracts the information.
-- @return table with data, or nil + error
-- @usage local pe = require("pe-parser")
-- local obj = pe.parse("c:\lua\lua.exe")
-- obj:dump()
M.parse = function(target)
  
  local list = {    -- list of known architectures
    [332]   = "x86",       -- IMAGE_FILE_MACHINE_I386
    [512]   = "x86_64",    -- IMAGE_FILE_MACHINE_IA64
    [34404] = "x86_64",    -- IMAGE_FILE_MACHINE_AMD64
  }
  
  local f = assert(io.open(target, "rb"))
  
  local MZ = f:read(2)
  if MZ ~= "MZ" then
    f:close()
    return nil, "Not a valid image"
  end
  
  f:seek("set", 60)                    -- position of PE header position
  local peoffset = get_int(f:read(4))  -- read position of PE header
  
  f:seek("set", peoffset)              -- move to position of PE header
  local out = get_list({
        { size = 4,
          name = "PEheader",
          is_str = true },
        { size = 2,
          name = "Machine" },
        { size = 2,
          name = "NumberOfSections" },
        { size = 4,
          name = "TimeDateStamp" },
        { size = 4,
          name = "PointerToSymbolTable"},
        { size = 4,
          name = "NumberOfSymbols"},
        { size = 2,
          name = "SizeOfOptionalHeader"},
        { size = 2,
          name = "Characteristics"},
      }, f)
  
  if out.PEheader ~= "PE" then
    f:close()
    return nil, "Invalid PE header"
  end
  out.dump = M.dump  -- export dump function as a method
  
  if out.SizeOfOptionalHeader > 0 then
    -- parse optional header; standard
    get_list({
        { size = 2,
          name = "Magic" },
        { size = 1,
          name = "MajorLinkerVersion" },
        { size = 1,
          name = "MinorLinkerVersion"},
        { size = 4,
          name = "SizeOfCode"},
        { size = 4,
          name = "SizeOfInitializedData"},
        { size = 4,
          name = "SizeOfUninitializedData"},
        { size = 4,
          name = "AddressOfEntryPoint"},
        { size = 4,
          name = "BaseOfCode"},
      }, f, out)
    local plus = (out.Magic == 523)
    if not plus then -- plain PE32, not PE32+
      get_list({
          { size = 4,
            name = "BaseOfData" },
        }, f, out)
    end
    -- parse optional header; windows-fields
    local plussize = 4
    if plus then plussize = 8 end
    get_list({
        { size = plussize,
          name = "ImageBase"},
        { size = 4,
          name = "SectionAlignment"},
        { size = 4,
          name = "FileAlignment"},
        { size = 2,
          name = "MajorOperatingSystemVersion"},
        { size = 2,
          name = "MinorOperatingSystemVersion"},
        { size = 2,
          name = "MajorImageVersion"},
        { size = 2,
          name = "MinorImageVersion"},
        { size = 2,
          name = "MajorSubsystemVersion"},
        { size = 2,
          name = "MinorSubsystemVersion"},
        { size = 4,
          name = "Win32VersionValue"},
        { size = 4,
          name = "SizeOfImage"},
        { size = 4,
          name = "SizeOfHeaders"},
        { size = 4,
          name = "CheckSum"},
        { size = 2,
          name = "Subsystem"},
        { size = 2,
          name = "DllCharacteristics"},
        { size = plussize,
          name = "SizeOfStackReserve"},
        { size = plussize,
          name = "SizeOfStackCommit"},
        { size = plussize,
          name = "SizeOfHeapReserve"},
        { size = plussize,
          name = "SizeOfHeapCommit"},
        { size = 4,
          name = "LoaderFlags"},
        { size = 4,
          name = "NumberOfRvaAndSizes"},
      }, f, out)
    -- Read data directory entries
    for i = 1, out.NumberOfRvaAndSizes do
      out.DataDirectory = out.DataDirectory or {}
      out.DataDirectory[i] = get_list({
          { size = 4,
            name = "VirtualAddress"},
          { size = 4,
            name = "Size"},
        }, f)
    end
    for i, name in ipairs{"ExportTable", "ImportTable", "ResourceTable",
        "ExceptionTable", "CertificateTable", "BaseRelocationTable",
        "Debug", "Architecture", "GlobalPtr", "TLSTable",
        "LoadConfigTable", "BoundImport", "IAT",
        "DelayImportDescriptor", "CLRRuntimeHeader", "Reserved"} do
      out.DataDirectory[name] = out.DataDirectory[i]
      if out.DataDirectory[name] then out.DataDirectory[name].name = name end
    end
  end
  
  -- parse section table
  for i = 1, out.NumberOfSections do
    out.Sections = out.Sections or {}
    out.Sections[i] = get_list({
        { size = 8,
          name = "Name",
          is_str = true},
        { size = 4,
          name = "VirtualSize"},
        { size = 4,
          name = "VirtualAddress"},
        { size = 4,
          name = "SizeOfRawData"},
        { size = 4,
          name = "PointerToRawData"},
        { size = 4,
          name = "PointerToRelocations"},
        { size = 4,
          name = "PointerToLinenumbers"},
        { size = 2,
          name = "NumberOfRelocations"},
        { size = 2,
          name = "NumberOfLinenumbers"},
        { size = 4,
          name = "Characteristics"},
      }, f)
  end
  -- we now have section data, so add RVA convertion method
  out.get_fileoffset = M.get_fileoffset
  
  -- get the import table
  f:seek("set", out:get_fileoffset(out.DataDirectory.ImportTable.VirtualAddress))
  local done = false
  local cnt = 1
  while not done do
    local dll = get_list({
          { size = 4,
            name = "ImportLookupTableRVA"},
          { size = 4,
            name = "TimeDateStamp"},
          { size = 4,
            name = "ForwarderChain"},
          { size = 4,
            name = "NameRVA"},
          { size = 4,
            name = "ImportAddressTableRVA"},
        }, f)
    if dll.NameRVA == 0 then
      -- this is the final NULL entry, so we're done
      done = true
    else
      -- store the import entry
      out.DataDirectory.ImportTable[cnt] = dll
      cnt = cnt + 1
    end
  end
  -- resolve imported DLL names
  for i, dll in ipairs(out.DataDirectory.ImportTable) do
    f:seek("set", out:get_fileoffset(dll.NameRVA))
    dll.Name = readstring(f)
  end
  
  f:close()
  return out
end

function DEC_HEX(IN, len)
    local B,K,OUT,I,D=16,"0123456789ABCDEF","",0
    while IN>0 do
        I=I+1
        IN,D=math.floor(IN/B),math.mod(IN,B)+1
        OUT=string.sub(K,D,D)..OUT
    end
    len = len or string.len(OUT)
    if len<1 then len = 1 end
    return (string.rep("0",len) .. OUT):sub(-len,-1)
end

--- Dumps the output parsed.
-- This function is also available as a method on the parsed output table
M.dump = function(obj)
  for k,v in pairs(obj) do 
    if type(v) == "number" then
      print(DEC_HEX(v,8).."  ".. k)
    else
      if (k ~= "DataDirectory") and (k ~= "Sections") then
        print(k,v)
      end
    end
  end
  
  if obj.DataDirectory then
    print("DataDirectory (RVA, size):")
    for i, v in ipairs(obj.DataDirectory) do
      print("   Entry "..DEC_HEX(i-1).." "..DEC_HEX(v.VirtualAddress,8).." "..DEC_HEX(v.Size,8).." "..v.name)
    end
  end
  
  if obj.Sections then
    print("Sections:")
    print("idx name     RVA      VSize    Offset   RawSize")
    for i, v in ipairs(obj.Sections) do
      print("  "..i.." "..v.Name.. string.rep(" ",9-#v.Name)..DEC_HEX(v.VirtualAddress,8).." "..DEC_HEX(v.VirtualSize,8).." "..DEC_HEX(v.PointerToRawData,8).." "..DEC_HEX(v.SizeOfRawData,8))
    end
  end
  
  print("Imports:")
  for i, dll in ipairs(obj.DataDirectory.ImportTable) do
    print("   "..dll.Name)
  end
end

return M



