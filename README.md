pe-parser
=========

Lua module to parse a Portable Executable (.exe , .dll, etc.) file and extract metadata. The implementation is far from complete, but it works for the basics. It was developed to check 32/64bit-ness of a binary and imported dll's.

Limitations
===========

It uses regular Lua numbers, so 64bit numbers will not work properly because they are to big. Generally this is not an issue as files don't tend to be so big. One exception to that is for some bit-flag fields in 64bit format, which simply cannot be handled this way.

PE info
=======

http://en.wikipedia.org/wiki/Portable_Executable
http://msdn.microsoft.com/en-us/magazine/ms809762.aspx
http://win32assembly.programminghorizon.com/pe-tut6.html
http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm


Copyright
=========

Copyright 2013 Thijs Schreijer

License
=======

MIT X11 