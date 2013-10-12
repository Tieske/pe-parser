package = "pe-parser"
version = "0.1.0-1"

description = {
   summary = "Portable Executable parser",
   detailed = [[
      Parses PE files (windows binaries, .dll, .exe, etc) to extract information
      from the executable.
   ]],
   license = "MIT X11",
   homepage = "https://github.com/Tieske/pe-parser",
}

dependencies = {
   "lua >= 5.1, <= 5.2"
}

source = {
   url = "https://github.com/Tieske/pe-parser/archive/version_0.1.tar.gz",
   dir = "pe-parser-version_0.1",
}

build = {
   type = "builtin",
   modules = {
      ["pe-parser"] = "src/pe-parser.lua"
   }
}
