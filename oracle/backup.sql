-- use parameter file
expdp system directory=dp_dir schemas=scott logfile=export_scott.log parallel=8

shell> more export_scott.par
directory=dp_dir
schemas=scott
logfile=export_scott.log
parallel=12
logtime=all
metrics=yes
exclude=statistics
dumpfile=dumpfile%U.dmp
filesize=5g
compression=all
compression_algorithm=medium

shell> expdp system parfile=export_scott.par

-- Consistency 
flashback_time=systimestamp
flashback_scn=<scn>

consistent=Y -- In Data Pump Legacy mode you can use consistent=Y
-- Dictionary Statistics, right before an export and immediately after an import
BEGIN
    DBMS_STATS.GATHER_SCHEMA_STATS('SYS');
    DBMS_STATS.GATHER_SCHEMA_STATS('SYSTEN');
END;
$ORACLE_HOME=/perl/bin/perl $ORACLE_HOME/rdbms/admin/catcon.pl \
    -l /tmp \
    -b gatherstats -- \
    --x"begin dbms_stats.gather_schema.stats('SYS'); dbms_stats.gather_schema.stats('SYSTEM'); end;"
