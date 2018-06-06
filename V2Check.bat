@echo off
rem set code="C:\Users\Andrew\Documents\Work\VERS-2015\VPA"
rem set bin="C:\Program Files (x86)\Java\jre1.8.0_144\bin"
set code="J:\PROV\TECHNOLOGY MANAGEMENT\Application Development\VERS\VERS-1999\V2Check"
set bin="C:\Program Files (x86)\Java\jre1.8.0_144\bin"
rem set bin="C:\Program Files (x86)\Java\jre1.8.0_131\bin"
set versclasspath=%code%/dist/*
%bin%\java -classpath %versclasspath% VEOCheck.VEOCheck -all -dtd %code%/vers.dtd %*
