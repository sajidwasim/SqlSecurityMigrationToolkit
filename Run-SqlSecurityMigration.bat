@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "SSM_SCRIPT=%~dp0Invoke-SqlSecurityMigration-Generic.ps1"
if not exist "%SSM_SCRIPT%" (
 echo ERROR: Generic entry point not found: %SSM_SCRIPT%
 exit /b 1
)
set /p "SSM_PROFILE=Sanitized or approved profile JSON path: "
if not defined SSM_PROFILE exit /b 1
set /p "SSM_MODE=Mode [Plan/Apply, default Plan]: "
if not defined SSM_MODE set "SSM_MODE=Plan"
if /I not "%SSM_MODE%"=="Plan" if /I not "%SSM_MODE%"=="Apply" exit /b 1
echo.
echo Profile: %SSM_PROFILE%
echo Mode: %SSM_MODE%
echo No application-specific defaults are supplied by this launcher.
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%SSM_SCRIPT%" -ProfilePath "%SSM_PROFILE%" -Mode "%SSM_MODE%"
set "SSM_EXIT=%ERRORLEVEL%"
if "%SSM_EXIT%"=="0" echo Completed. Review the generated session artifacts.
if not "%SSM_EXIT%"=="0" echo Failed with exit code %SSM_EXIT%.
exit /b %SSM_EXIT%
