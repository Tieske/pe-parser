-- update the target below to a valid binary file
local target = [[C:\Users\Public\Lua\5.1lfw\lua.exe]]

local pe = require("pe-parser")

local obj, err = pe.parse(target)
if obj then
  obj:dump()
  print(pe.msvcrt(target))
else 
  print(err)
end


