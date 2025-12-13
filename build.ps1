# PowerShell script to build and run letgo
# Usage: .\run.ps1

$ErrorActionPreference = "Continue"

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Letgo Build and Run Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Build All (letgo.exe, letgo, letgo-amd64)" -ForegroundColor Yellow
    Write-Host "2. Run One (letgo.exe, letgo, or letgo-amd64)" -ForegroundColor Yellow
    Write-Host "3. Exit" -ForegroundColor Yellow
    Write-Host ""
}

function Build-All {
    Write-Host ""
    Write-Host "Building all executables..." -ForegroundColor Green
    Write-Host ""

    Write-Host "[1/3] Building letgo.exe (Windows)..." -ForegroundColor Cyan
    go build -o application/letgo.exe cmd/letgo/main.go
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed for letgo.exe!" -ForegroundColor Red
        return $false
    }
    Write-Host "✓ letgo.exe built successfully" -ForegroundColor Green

    Write-Host ""
    Write-Host "[2/3] Building letgo (current platform)..." -ForegroundColor Cyan
    go build -o application/letgo cmd/letgo/main.go
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed for letgo!" -ForegroundColor Red
        return $false
    }
    Write-Host "✓ letgo built successfully" -ForegroundColor Green

    Write-Host ""
    Write-Host "[3/3] Building letgo-amd64 (Linux amd64)..." -ForegroundColor Cyan
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    go build -o application/letgo-amd64 cmd/letgo/main.go
    $env:GOOS = $null
    $env:GOARCH = $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed for letgo-amd64!" -ForegroundColor Red
        return $false
    }
    Write-Host "✓ letgo-amd64 built successfully" -ForegroundColor Green

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "All builds completed successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    return $true
}

function Run-One {
    Clear-Host
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Run Executable" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Run letgo.exe (Windows)" -ForegroundColor Yellow
    Write-Host "2. Run letgo (current platform)" -ForegroundColor Yellow
    Write-Host "3. Run letgo-amd64 (Linux amd64)" -ForegroundColor Yellow
    Write-Host "4. Back to main menu" -ForegroundColor Yellow
    Write-Host ""
    
    $runChoice = Read-Host "Select executable to run (1-4)"
    
    switch ($runChoice) {
        "1" {
            if (Test-Path "application\letgo.exe") {
                Write-Host "Running letgo.exe..." -ForegroundColor Green
                & "application\letgo.exe"
            } else {
                Write-Host "Error: letgo.exe not found! Please build it first." -ForegroundColor Red
                Read-Host "Press Enter to continue"
            }
        }
        "2" {
            if (Test-Path "application\letgo") {
                Write-Host "Running letgo..." -ForegroundColor Green
                & "application\letgo"
            } else {
                Write-Host "Error: letgo not found! Please build it first." -ForegroundColor Red
                Read-Host "Press Enter to continue"
            }
        }
        "3" {
            if (Test-Path "application\letgo-amd64") {
                Write-Host "Running letgo-amd64..." -ForegroundColor Green
                & "application\letgo-amd64"
            } else {
                Write-Host "Error: letgo-amd64 not found! Please build it first." -ForegroundColor Red
                Read-Host "Press Enter to continue"
            }
        }
        "4" {
            return
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Read-Host "Press Enter to continue"
            Run-One
        }
    }
}

# Main loop
while ($true) {
    Show-Menu
    $choice = Read-Host "Select an option (1-3)"
    
    switch ($choice) {
        "1" {
            Build-All | Out-Null
            Read-Host "Press Enter to continue"
        }
        "2" {
            Run-One
        }
        "3" {
            Write-Host ""
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

