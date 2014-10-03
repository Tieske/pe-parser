pe-parser
=========

Lua module to parse a Portable Executable (.exe , .dll, etc.) file and extract metadata. The implementation is far from complete, but it works for the basics. It was developed to check 32/64bit-ness of a binary and imported dll's.
Documentation is available in LDoc format, in the `doc` directory.

A commandline script is available, also by the name of `pe-parser`. Use `pe-parser -help` for information on the usage of this utility.

Limitations
===========

It uses regular Lua numbers (for file seeking), so for really large files it will not work properly because Lua numbers cannot hold 64bit integers. Generally this is not an issue as executable files don't tend to be that big. All numbers returned will be as hex fromatted strings, so 64bit flag fields can be processed correctly.

PE info
=======

http://en.wikipedia.org/wiki/Portable_Executable
http://msdn.microsoft.com/en-us/magazine/ms809762.aspx
http://win32assembly.programminghorizon.com/pe-tut6.html
http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm


Copyright
=========

Copyright 2013-2014 Thijs Schreijer

License
=======

MIT X11 