@echo off
mkdir C:\RGM-REGTEST\regtest 2>nul
copy rgm.conf C:\RGM-REGTEST\rgm.conf >nul
start rgm-qt.exe -regtest -datadir=C:\RGM-REGTEST
