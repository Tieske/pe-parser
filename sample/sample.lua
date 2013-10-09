-- update the target below to a valid binary file
local target = [[C:\Users\Public\Lua\5.1\bin\lua.exe]]


local pe = require("pe-parser")

local obj = pe.parse(target)
obj:dump()

