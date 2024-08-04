# LXFLoader

A Ghidra loader module for the Linear eXecutable Module Format.

## Installation

Download the ZIP file from the [releases](https://github.com/oshogbo/ghidra-lx-loader/releases) to the `GHIDRA_INSTALL_DIR/Extensions/Ghidra` directory and install the module from the `File > Install extensions...` menu on the main screen.

## Build

If you wish to build this extension manually:
* Provide `GHIDRA_INSTALL_DIR` environment variable containing a path to Ghidra version you want to compile against
* run `gradle buildExtension`
* the resulting .zip file will be placed in `dist` directory and can be installed as usual.

## ToDos

If you are interested in hellping:
* Implement rest of the source types.
* Implemented entry points (on the binaries I tested the section was 0s - so if you have another binary please contact me).
* Implement debug section.
* Code cleanup (I was rewriting everything from spec, and some methods/names could have better naming).
* Don't use hardcoded values.
* I'm not a java developer (get rid of the emitU functions).

## Author

Mariusz Zaborski <oshogbo@FreeBSD.org>

## Verficattion

I verified output of the module vs IDA Freeware 4.1 and swars source code.

## Resources

* [LX documentation](http://www.textfiles.com/programming/FORMATS/lxexe.txt)
* [dos4gw loader](https://github.com/BoomerangDecompiler/boomerang/tree/next/loader/exe/dos4gw)
* [swars](http://swars.vexillium.org/)
* [The tale of Syndicate Wars Port](https://gynvael.coldwind.pl/?id=279)
* [mortalkombat](http://blog.rewolf.pl/blog/?p=1837)
* [ghidra-switch-loader](https://github.com/Adubbz/Ghidra-Switch-Loader/)

## License
Apache license 2.0
