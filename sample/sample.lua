-- update the target below to a valid binary file
local target = [[C:\Users\Public\Lua\5.1\bin\lua.exe]]
local target = [[C:\temp\DependencyWalker\lua5.1-64.dll]]

local pe = require("pe-parser")

local obj = pe.parse(target)
obj:dump()

