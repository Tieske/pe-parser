pe-parser
=========

Lua module to parse a Portable Executable (.exe , .dll, etc.) file and extract metadata. The implementation is far from complete, but it works for the basics. It was developed to check 32/64bit-ness of a binary and imported dll's.
Documentation is available in LDoc format, in the `doc` directory.

A commandline script is available, also by the name of `pe-parser`. Use `pe-parser -help` for information on the usage of this utility.

Limitations
===========

It uses regular Lua numbers (for file seeking), so for really large files it will not work properly because Lua numbers cannot hold 64bit integers. Generally this is not an issue as executable files don't tend to be that big. All numbers returned will be as hex formatted strings, so 64bit flag fields can be processed correctly.

PE info
=======

- [Portable Executable](http://en.wikipedia.org/wiki/Portable_Executable)
- [Peering Inside the PE: A Tour of the Win32 Portable Executable File Format](http://msdn.microsoft.com/en-us/magazine/ms809762.aspx)
- [Iczelion's Win32 Assembly Homepage - Tutorial 6: Import Table](http://win32assembly.programminghorizon.com/pe-tut6.html)
- [Understanding RVAs and Import Tables](http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm)


Copyright
=========

Copyright 2013-2024 Thijs Schreijer

License
=======

MIT X11

History
=======

#### Releasing new versions

- update copyright years + version in; `README.md`, `src/pe-parser.lua` (doc header and module constant)
- update rockspec file: rename and update version in contents
- generate documentation using `ldoc`
- commit the release as: "release X.Y"
- tag the release commit as "version_X.Y"
- push the release commit
- push the release tag
- upload the rock to luarocks

### unreleased

- fixed version numbers in code

### version 0.6, 25-Jun-2024

- Add detection of the universal runtime
