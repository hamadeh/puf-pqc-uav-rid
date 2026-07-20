{\rtf1\ansi\ansicpg1252\cocoartf2639
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx566\tx1133\tx1700\tx2267\tx2834\tx3401\tx3968\tx4535\tx5102\tx5669\tx6236\tx6803\pardirnatural\partightenfactor0

\f0\fs24 \cf0 @echo off\
setlocal EnableExtensions EnableDelayedExpansion\
\
rem Change this path only if LTspice is installed elsewhere.\
set "LTSPICE=C:\\Users\\JUST\\AppData\\Local\\Programs\\ADI\\LTspice\\LTspice.exe"\
\
rem Always run from the folder containing this batch file.\
pushd "%~dp0"\
\
if not exist "%LTSPICE%" (\
    echo ERROR: LTspice was not found at:\
    echo %LTSPICE%\
    echo.\
    echo Edit the LTSPICE path in run_all_100_PVT.bat.\
    pause\
    exit /b 1\
)\
\
echo ============================================\
echo Running 100 fixed-mismatch RO-PUF PVT chips\
echo ============================================\
\
for /L %%I in (1,1,3) do (\
    set "NUM=00%%I"\
    set "NUM=!NUM:~-3!"\
\
    set "NET=chip_!NUM!_PVT.net"\
    set "LOG=chip_!NUM!_PVT.log"\
\
    if exist "!LOG!" (\
        echo [SKIP] !LOG! already exists.\
    ) else (\
        echo.\
        echo [RUN ] !NET!\
\
        "%LTSPICE%" -b "!NET!"\
\
        if errorlevel 1 (\
            echo [FAIL] !NET!\
            echo !NET!>>failed_runs.txt\
        ) else (\
            if exist "!LOG!" (\
                echo [DONE] !LOG!\
            ) else (\
                echo [FAIL] No log produced for !NET!\
                echo !NET!>>failed_runs.txt\
            )\
        )\
    )\
)\
\
echo.\
echo ============================================\
echo Batch campaign finished\
echo ============================================\
\
if exist failed_runs.txt (\
    echo Check failed_runs.txt for unsuccessful simulations.\
) else (\
    echo No launcher-level failures were recorded.\
)\
\
popd\
pause}