@ echo off

if exist cmake-build-default rd /q /s cmake-build-default
if not exist cmake-build-default md cmake-build-default
pushd cmake-build-default
cmake .. -G "MinGW Makefiles" -DCMAKE_C_COMPILER=clang;--target=x86_64-pc-windows-gnu %*
mingw32-make install package
popd
