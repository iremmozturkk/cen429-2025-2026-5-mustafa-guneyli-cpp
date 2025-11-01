@echo off
REM CMake PATH'e ekle (geçici - bu oturum için)
echo CMake PATH'e ekleniyor...
set PATH=%PATH%;C:\Program Files\CMake\bin

REM Test et
cmake --version

echo.
echo CMake başarıyla PATH'e eklendi!
echo Bu terminalde artık cmake komutunu kullanabilirsiniz.
echo.
pause

