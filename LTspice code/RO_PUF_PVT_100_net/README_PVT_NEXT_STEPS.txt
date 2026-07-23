RO-PUF FIXED-MISMATCH PVT EXPERIMENT
====================================

Generated virtual chips: 100
Voltage values (V): 0.9 1 1.1
Temperature values (C): -20 25 80
PVT conditions per chip: 9
Initial TSTOP: 40 ns
Diagnostic edge: rising edge 100

NEXT STEPS
1. Ensure 45nm_HP.pm is in this directory.
2. Open chip_001_PVT.net in LTspice and run it.
3. Confirm nine stepped conditions are present in the log.
4. Confirm freq_ro0 through freq_ro127 each have nine values.
5. Confirm every edge100_ro* value is below TSTOP.
6. Confirm no Voltage not found, target not found, NaN, or convergence error occurs.
7. Keep the generated mismatch include file unchanged.
8. After the one-chip pilot succeeds, run chip_02_PVT.net through chip_100_PVT.net.
9. Preserve every .log file for MATLAB PVT reliability analysis.

The 1.0 V, 25 C condition inside each chip is its enrollment reference.
These chips are newly generated fixed devices and are not exact reconstructions
of the earlier LTspice gauss() process-run devices.
