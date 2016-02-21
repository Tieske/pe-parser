package = "pe-parser"
version = "0.5.0-1"

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
   "lua >= 5.1, <= 5.4"
}

source = {
   url = "https://github.com/Tieske/pe-parser/archive/version_0.5.tar.gz",
   dir = "pe-parser-version_0.5",
}

build = {
   type = "builtin",
   modules = {
      ["pe-parser"] = "src/pe-parser.lua"
   },
   copy_directories = { "doc" },
   install = {
      bin = {
         ["pe-parser"]   = "bin/pe-parser.lua",
      },
   },
}
