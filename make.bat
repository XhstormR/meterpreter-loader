@ echo off

if exist cmake-build-default rd /q /s cmake-build-default
if not exist cmake-build-default md cmake-build-default
pushd cmake-build-default
cmake .. -G "MinGW Makefiles" %*
mingw32-make install
popd
