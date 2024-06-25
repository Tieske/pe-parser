local package_name = "pe-parser"
local package_version = "0.6"
local rockspec_revision = "1"
local github_account_name = "Tieske"
local github_repo_name = package_name


package = package_name
version = package_version.."-"..rockspec_revision

source = {
  url = "git+https://github.com/"..github_account_name.."/"..github_repo_name..".git",
  branch = (package_version == "scm") and "master" or nil,
  tag = (package_version ~= "scm") and "version_"..package_version or nil,
}

description = {
  summary = "Portable Executable parser",
  detailed = [[
    Parses PE files (windows binaries, .dll, .exe, etc) to extract information
    from the executable.
  ]],
  license = 'MIT <http://opensource.org/licenses/MIT>',
  homepage = "https://github.com/"..github_account_name.."/"..github_repo_name,
}

dependencies = {
   "lua >= 5.1, <= 5.4"
}

build = {
   type = "builtin",
   modules = {
      ["pe-parser"] = "src/pe-parser.lua"
   },
   copy_directories = { "docs" },
   install = {
      bin = {
         ["pe-parser"]   = "bin/pe-parser.lua",
      },
   },
}
