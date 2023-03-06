# VirtualTaggerPlugin
VirtualTaggerPlugin is a [Cutter](https://github.com/rizinorg/cutter) plugin that automatically adds named function definitions for virtual  functions defined in classes, making it easier to search for VMT functions

Tested on Windows Cutter release 2.2.0

### Notes
Generated names follow the form `vmt.[class name].[function name]` - if there is no symbol for the function name, Cutter will set `[function name]` to `virtual_[VMT offset]`

If multiple classes use the same function due to inheritance, VirtualTaggerPlugin will attempt to find and use the name of the highest-super class that uses the function.

If multiple classes use the same function without sharing a parent class, the name of the first class processed will be used.

VirtualTaggerPlugin doesn't trigger analysis of virtual functions, it only creates the Rizin function definition. This means only the first instruction of the function will be associated with the function.

### Install
Copy to your Cutter native plugin directory.  
You can find this directory in Cutter via `edit` -> `preferences` -> `Plugins` -> `Plugins are loaded from ...`

### Usage
The plugin should run automatically after analysis is finished.  
If you need to re-run the function namer, right click an instruction or function -> `plugins` -> `Force run virtual tagger` - note that this runs the tagger on ALL virtual functions.

### Compiling:
Add `[cutter install dir]/lib/cmake` to `CMAKE_PREFIX_PATH`  
Add QT5 cmake dir to `CMAKE_PREFIX_PATH` ( `Qt/[version]/[compiler]/lib/cmake/Qt5` on my machine)
```
md build
cd build
cmake ..
```
Compile using your compiler (compile in `release` mode if you want it to work with release builds of Cutter)
