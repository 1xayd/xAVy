@echo off
SET PROJECT_NAME=xavy
SET OUTPUT_DIR=builds

echo Building %PROJECT_NAME% project for all platforms...

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo.
echo === Building for Windows ===
set GOOS=windows
set GOARCH=386
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%.exe"

set GOARCH=amd64
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%.exe"

set GOARCH=arm64
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%.exe"

echo.
echo === Building for Linux ===
set GOOS=linux
set GOARCH=386
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%"

set GOARCH=amd64
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%"

set GOARCH=arm64
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%"

echo.
echo === Building for macOS ===
set GOOS=darwin
set GOARCH=amd64
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%"

set GOARCH=arm64
echo Building for %GOOS% %GOARCH%...
go build -trimpath -o "%OUTPUT_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%"

echo.
echo =============================
echo All builds completed!
echo Output directory: %OUTPUT_DIR%
