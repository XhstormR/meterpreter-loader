@ echo off

if exist build rd /q /s build
if not exist build md build
cd build
cmake .. -G "MinGW Makefiles"
mingw32-make install
cd ..
