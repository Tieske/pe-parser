local pe = require("pe-parser")
local runtime = {"runtime", "dump", "help"}
for k,v in ipairs(runtime) do
  runtime["--"..v] = true
  runtime["-"..v] = true
  runtime[""..v] = true
end

local opt, argstart, argend
if (runtime[arg[1] or ""]) then 
  opt = 1
  argstart = 2
  argend = #arg
else
  argstart = 1
  argend = #arg
end
if ((arg[opt or ""] or ""):find("dump")) then 
  opt = nil  -- this is the default
end

if argstart>argend or ((arg[opt or ""] or ""):find("help")) then
  print[[PE-parser commandline utility for checking PE (Portable Executable) files (version 0.4)

USAGE: pe-parser [-dump|-runtime|-help] file1 [file2 [...] ]

Parses the file and dumps the output.
 fileX    : File name of binary file to examine

OPTIONS
 -dump    : Parses the file and dumps the output (default)
 -runtime : Only checks the MSVCRT version the binary uses. This
            will traverse the dependency tree of the file.
 -help    : displays this help text   
options can be prefixed with one (as above), two or no dashes
]]
  if argstart>=argend then os.exit(1) end -- no arguments, error
  os.exit() -- was 'help' option
end

local err = 0
for i = argstart, argend do
  if not opt then
    print("Now analyzing: '"..tostring(arg[i]).."'")
    local obj, errmsg = pe.parse(arg[i])
    if obj then
      obj:dump()
    else
      print("Failed: "..tostring(errmsg))
      err = err + 1
    end
    print("Done analyzing: '"..tostring(arg[i]).."'")
  else
    local rt, bin = pe.msvcrt(arg[i])
    if rt then
      print(rt.." found in '"..bin.."' is used by '"..arg[i].."'")
    else
      print("Runtime not found for '"..arg[i].."', an error occured: "..tostring(bin))
      err = err + 1
    end
  end
end

os.exit(err)  -- return number of errors
