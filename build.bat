@echo off
REM Batch script to build and run letgo
REM Usage: run.bat

:menu
echo.
echo ========================================
echo   Letgo Build and Run Script
echo ========================================
echo.
echo 1. Build All (letgo.exe, letgo, letgo-amd64)
echo 2. Run One (letgo.exe, letgo, or letgo-amd64)
echo 3. Exit
echo.
set /p choice="Select an option (1-3): "

if "%choice%"=="1" goto build_all
if "%choice%"=="2" goto run_one
if "%choice%"=="3" goto end
echo Invalid option. Please try again.
goto menu

:build_all
echo.
echo Building all executables...
echo.

echo [1/3] Building letgo.exe (Windows)...
go build -o application/letgo.exe cmd/letgo/main.go
if %ERRORLEVEL% NEQ 0 (
    echo Build failed for letgo.exe!
    goto menu
)
echo ✓ letgo.exe built successfully

echo.
echo [2/3] Building letgo (current platform)...
go build -o application/letgo cmd/letgo/main.go
if %ERRORLEVEL% NEQ 0 (
    echo Build failed for letgo!
    goto menu
)
echo ✓ letgo built successfully

echo.
echo [3/3] Building letgo-amd64 (Linux amd64)...
set GOOS=linux
set GOARCH=amd64
go build -o application/letgo-amd64 cmd/letgo/main.go
set GOOS=
set GOARCH=
if %ERRORLEVEL% NEQ 0 (
    echo Build failed for letgo-amd64!
    goto menu
)
echo ✓ letgo-amd64 built successfully

echo.
echo ========================================
echo All builds completed successfully!
echo ========================================
echo.
pause
goto menu

:run_one
echo.
echo ========================================
echo   Run Executable
echo ========================================
echo.
echo 1. Run letgo.exe (Windows)
echo 2. Run letgo (current platform)
echo 3. Run letgo-amd64 (Linux amd64)
echo 4. Back to main menu
echo.
set /p run_choice="Select executable to run (1-4): "

if "%run_choice%"=="1" (
    if exist application\letgo.exe (
        echo Running letgo.exe...
        application\letgo.exe
    ) else (
        echo Error: letgo.exe not found! Please build it first.
        pause
    )
    goto menu
)
if "%run_choice%"=="2" (
    if exist application\letgo (
        echo Running letgo...
        application\letgo
    ) else (
        echo Error: letgo not found! Please build it first.
        pause
    )
    goto menu
)
if "%run_choice%"=="3" (
    if exist application\letgo-amd64 (
        echo Running letgo-amd64...
        application\letgo-amd64
    ) else (
        echo Error: letgo-amd64 not found! Please build it first.
        pause
    )
    goto menu
)
if "%run_choice%"=="4" goto menu
echo Invalid option. Please try again.
goto run_one

:end
echo.
echo Exiting...
exit /b 0

