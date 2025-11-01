@echo off
REM SQLite3 Amalgamation indirme scripti
echo SQLite3 Amalgamation dosyalarini indiriyorum...

REM SQLite3 version
set SQLITE_VERSION=3440200
set SQLITE_YEAR=2023

REM Download URL
set DOWNLOAD_URL=https://www.sqlite.org/%SQLITE_YEAR%/sqlite-amalgamation-%SQLITE_VERSION%.zip

echo Indiriliyor: %DOWNLOAD_URL%
powershell -Command "& {Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile 'sqlite-amalgamation.zip'}"

if exist sqlite-amalgamation.zip (
    echo Dosya indirildi, cikartiliyor...
    powershell -Command "& {Expand-Archive -Path 'sqlite-amalgamation.zip' -DestinationPath '.' -Force}"
    
    REM Dosyalari kopyala
    copy sqlite-amalgamation-%SQLITE_VERSION%\*.c .
    copy sqlite-amalgamation-%SQLITE_VERSION%\*.h .
    
    REM Temizlik
    rmdir /S /Q sqlite-amalgamation-%SQLITE_VERSION%
    del sqlite-amalgamation.zip
    
    echo SQLite3 basariyla indirildi ve hazir!
) else (
    echo HATA: Dosya indirilemedi!
)

pause

