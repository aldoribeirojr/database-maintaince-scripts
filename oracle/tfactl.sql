-- Analyze logs and look for errors
shell> tfactl analyze -since 1d -- show summary of events from alert logs, system messages in last 5 hours
shell> tfactl analyze -comp os -since 1d -- show sumary of events from system messages in last 1 day
shell> tfactl analyze -search "ORA-" -since 2d -- search string ORA- in alert and system logs in past 2 days
shell> tfactl analyze -search "/Starting/c" -since 2d -- search case sensitive string "Starting" in past 2 days
shell> tfactl analyze -comp os -for "Oct/01/2020 11" -search "." -- show all system logs messages at time Oct/01/2020
shell> tfactl analyze -comp osw -since 6h -- show OSWatcher Top sumary in last 6 hours
shell> tfactl analyze -comp oswslabinfo -from "Oct/01/2020 06:00:01" -- show OSWatcher slabinfo sumary for specified time period
shell> tfactl analyze -since 1h -type generic -- analyze all generic messages in last one hour

-- how to connect to a hand database for diagnostics
shell> sqlplus -prelim / as sysdba
SQL> sql _prelim on
SQL> connect / as sysdba

-- Refer MOS Note 1428210.1
-- Useful SQLs for querying v$wait_chains:
SQL> SELECT chain_id, num_waiters, in_wait_secs, osid, blocker_osid, substr(wait_event_text,1,30)
FROM v$wait_chains; 

-- Additional Information (formatted) - Top 100 wait chain processes
set pages 1000
set lines 120
set heading off
column w_proc format a50 tru
column instance format a20 tru
column inst format a28 tru
column wait_event format a50 tru
column p1 format a16 tru
column p2 format a16 tru
column p3 format a15 tru
column Seconds format a50 tru
column sincelw format a50 tru
column blocker_proc format a50 tru
column waiters format a50 tru
column chain_signature format a100 wra
column blocker_chain format a100 wra

SELECT *
FROM (SELECT 'Current Process: '||osid W_PROC, 'SID '||i.instance_name INSTANCE,
'INST #: '||instance INST,'Blocking Process: '||decode(blocker_osid,null,'<none>',blocker_osid)||
' from Instance '||blocker_instance BLOCKER_PROC,'Number of waiters: '||num_waiters waiters,
'Wait Event: ' ||wait_event_text wait_event, 'P1: '||p1 p1, 'P2: '||p2 p2, 'P3: '||p3 p3,
'Seconds in Wait: '||in_wait_secs Seconds, 'Seconds Since Last Wait: '||time_since_last_wait_secs sincelw,
'Wait Chain: '||chain_id ||': '||chain_signature chain_signature,'Blocking Wait Chain: '||decode(blocker_chain_id,null,
'<none>',blocker_chain_id) blocker_chain
FROM v$wait_chains wc,
v$instance i
WHERE wc.instance = i.instance_number (+)
AND ( num_waiters > 0
OR ( blocker_osid IS NOT NULL
AND in_wait_secs > 10 ) )
ORDER BY chain_id,
num_waiters DESC)
WHERE ROWNUM < 101;

-- Final Blocking Session in 11.2
set pages 1000
set lines 120
set heading off
column w_proc format a50 tru
column instance format a20 tru
column inst format a28 tru
column wait_event format a50 tru
column p1 format a16 tru
column p2 format a16 tru
column p3 format a15 tru
column Seconds format a50 tru
column sincelw format a50 tru
column blocker_proc format a50 tru
column fblocker_proc format a50 tru
column waiters format a50 tru
column chain_signature format a100 wra
column blocker_chain format a100 wra

SELECT *
FROM (SELECT 'Current Process: '||osid W_PROC, 'SID '||i.instance_name INSTANCE,
'INST #: '||instance INST,'Blocking Process: '||decode(blocker_osid,null,'<none>',blocker_osid)||
' from Instance '||blocker_instance BLOCKER_PROC,
'Number of waiters: '||num_waiters waiters,
'Final Blocking Process: '||decode(p.spid,null,'<none>',
p.spid)||' from Instance '||s.final_blocking_instance FBLOCKER_PROC,
'Program: '||p.program image,
'Wait Event: ' ||wait_event_text wait_event, 'P1: '||wc.p1 p1, 'P2: '||wc.p2 p2, 'P3: '||wc.p3 p3,
'Seconds in Wait: '||in_wait_secs Seconds, 'Seconds Since Last Wait: '||time_since_last_wait_secs sincelw,
'Wait Chain: '||chain_id ||': '||chain_signature chain_signature,'Blocking Wait Chain: '||decode(blocker_chain_id,null,
'<none>',blocker_chain_id) blocker_chain
FROM v$wait_chains wc,
gv$session s,
gv$session bs,
gv$instance i,
gv$process p
WHERE wc.instance = i.instance_number (+)
AND (wc.instance = s.inst_id (+) AND wc.sid = s.sid (+)
AND wc.sess_serial# = s.serial# (+))
AND (s.final_blocking_instance = bs.inst_id (+) AND s.final_blocking_session = bs.sid (+))
AND (bs.inst_id = p.inst_id (+) AND bs.paddr = p.addr (+))
AND ( num_waiters > 0
OR ( blocker_osid IS NOT NULL
AND in_wait_secs > 10 ) )
ORDER BY chain_id,
num_waiters DESC)
WHERE ROWNUM < 101;

-- Query trace files using SQL
SQL> describe v$DIAG_TRACE_FILE;
SQL> describe v$DIAG_TRACE_FILE_CONTENTS;
SQL> SELECT trace_filename FROM v$diag_trace_file;

SQL> select payload from v$diag_trace_file_contents where trace_filename = 'ORCL_ora_19005.trc';

SQL> describe V$DIAG_SESS_SQL_TRACE_RECORDS;

SQL> SELECT sid, serial# FROM v$session where usename = 'SYS';
SQL> EXECUTE DBMS_SYSTEM.SET_SQL_TRACE_IN_SESSION(129, 6051, TRUE);
SQL> select unique trace_filename from V$DIAG_SESS_SQL_TRACE_RECORDS;
SQL> select payload from V$DIAG_SESS_SQL_TRACE_RECORDS where trace_filename = 'ORCL_ora_19005.trc';

-- Self analysis in MOS using TFA collections
-- ORA-00600 - Troubleshooting Tool
shell> tfactl diagcollect -srdc <srdc_type>
shell> tfactl diagcollect -srdc ORA-00600

-- sanitization
shell> tfactl orachk -preupgrade -sanitize
-- reverse map the sanitization
shell> tfactl orachk -rrmap entity_sanitized_name

-- Find if anything has changed
shell> tfactl changes

-- Detect and collect using SRDC
shell> tfactl diagcollect -srdc dbperf [-sr <sr_number>]
shell> tfactl diagcollect -srdc ORA-00600

-- Automatic Database Log Purge
shell> tfactl set manageLogsAutoPurge=ON -- TFA can automatically purge database logs
shell> tfactl set manageLogsAutoPurgePolicyAge=<n><d|h>
shell> tfactl set manageLogsAutoPurgeInterval=minutes

-- Manual Database Log Purge
shell> tfactl managelogs <options>
-- examples
shell> tfactl managelogs -show variation -older 30d 
shell> tfactl managelogs -purge -older 30d -dryrun
-- -show usage # show disk space usage per diagnostic directory for both
-- -database dbname
-- dryrun # Use with -purge to estimate how many files will be affected and how much disk space will freed by a potencial purge command

-- Monitor multiple logs
shell> tfactl tail

-- Monitor Database Performance
shell> tfactl run oratop -database ogg19c

-- Analyze OS Metrics
shell> tfactl run oswbb
