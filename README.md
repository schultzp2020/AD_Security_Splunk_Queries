# Splunk Queries for Active Directory Cyber Security Events using Wazuh

## Basic Queries

### Password Spray

``` splunk
index="ossec_logs" location=EventChannel 
| rename data.win.system.eventID as event_id, data.win.eventdata.ipAddress AS ip_address, data.win.eventdata.targetUserName AS username 
| search event_id=4624 username!=*$ 
| eval ip_address = trim(replace(ip_address, "::ffff:", "")) 
| stats distinct_count(username) as success_unique_username_count, values(username) as success_usernames by ip_address 
| sort -success_unique_username_count, -success_username 
| join ip_address 
    [ search index="ossec_logs" location=EventChannel 
    | rename data.win.system.eventID as event_id, data.win.eventdata.ipAddress AS ip_address, data.win.eventdata.targetUserName AS username 
    | search (event_id=4771 OR event_id=4768 OR event_id=4625) username!=*$ 
    | eval ip_address = trim(replace(ip_address, "::ffff:", "")) 
    | stats distinct_count(username) as failed_unique_username_count, values(username) as failed_usernames by ip_address 
    | where failed_unique_username_count >= 50 
    | lookup dnslookup clientip as ip_address OUTPUT clienthost as host 
    | regex host="^((?!\ REGEX TO REMOVE FALSE POSITIVES )[\s\S])*$" 
    | sort -failed_unique_username_count, -failed_usernames 
    | table host, ip_address, failed_unique_username_count, failed_usernames ] 
| table host, ip_address, failed_unique_username_count, failed_usernames, success_unique_username_count, success_usernames 
| eval failed_usernames = split(failed_usernames, " ")
| rename ip_address as "IP Address", host as "Host", failed_unique_username_count as "Number of Distinct Failed Logins Attempts", failed_usernames as "Accounts with Failed Logins Attempts", success_unique_username_count as "Number of Distinct Successful Logins Attempts", success_usernames as "Accounts with Successful Logins Attempts"
```

- The subquery finds an IP address with 50 or more distinct failed login attempts (Most likely malicious)
- The main query left joins with the subquery using the IP address to find any corresponding successful login attempts

### Kerberoasting

``` splunk
index="ossec_logs" location=EventChannel
| rename data.win.system.eventID as event_id, data.win.eventdata.ipAddress AS ip_address, data.win.eventdata.targetUserName AS username, data.win.eventdata.ticketEncryptionType AS ticket_encryption_type, data.win.eventdata.ticketOptions AS ticket_options, data.win.eventdata.serviceName as spn 
| search event_id=4769 username!=*$ (ticket_encryption_type=0x12 OR ticket_encryption_type=0x17) ticket_options=0x40810000 spn!=*$
| eval ip_address = trim(replace(ip_address, "::ffff:", ""))
| lookup dnslookup clientip as ip_address OUTPUT clienthost as host
| stats distinct_count(spn) as spn_count, values(spn) as spns by username, host, ip_address
| where spn_count >= 10
| sort -spn_count
| table username, host, ip_address, spn_count, spns
| rename username as Username, host as Host, ip_address as "IP Address", spns as SPNs, spn_count as "SPN Count"
```

- The query finds an IP address with 10 or more distinct failed kerberos attempts (Most likely malicious)

### WIP Querries

- If the Mean and Median are close, it may indicate malicious behavior over a large dataset
- If the Standard Deviation is small, it may indicate malicious behavior over a large dataset (Events are repeatitively close)
- Using "Standard deviation from the mean/median as a percent", you can come to the same conclusion by applying the same logic as above
- Max and Min are based on the original dataset (With outliers)
- The 15th and 85th percentile are used to remove outliers
- In the future I want to create some sort of score/formula to indicate malicious behavior

### (WIP) Password Spray Statistics

``` splunk
index="ossec_logs" location=EventChannel 
| rename data.win.system.eventID as event_id, data.win.eventdata.ipAddress AS ip_address, data.win.eventdata.targetUserName AS username 
| search (event_id=4771 OR event_id=4768 OR event_id=4625) username!=*$ 
| eval ip_address = trim(replace(ip_address, "::ffff:", "")) 
| lookup dnslookup clientip as ip_address OUTPUT clienthost as host 
| streamstats current=f last(_time) as last_time by ip_address, host
| eval gap = last_time - _time 
| eventstats perc85(gap) as gap_perc85, perc15(gap) as gap_perc15, max(gap) as gap_max, min(gap) as gap_min by ip_address, host
| eval gap = if(gap > gap_perc15 AND gap < gap_perc85, gap, null()) 
| eventstats avg(gap) as gap_avg, median(gap) as gap_med, stdev(gap) as gap_std by ip_address, host
| eval gap_avg = round(gap_avg, 3), gap_std = round(gap_std, 3) 
| eval gap_deviation_avg = round((gap_std / gap_avg), 3), gap_deviation_med = round((gap_std / gap_med), 3) 
| eval gap_deviation_avg = coalesce(gap_deviation_avg, 1.000), gap_deviation_med = coalesce(gap_deviation_med, 1.000) 
| stats distinct_count(username) as failed_unique_username_count, values(username) as failed_usernames, values(gap_avg) as gap_avg, values(gap_med) as gap_med, values(gap_std) as gap_std, values(gap_deviation_avg) as gap_deviation_avg, values(gap_deviation_med) as gap_deviation_med, values(gap_min) as gap_min, values(gap_max) as gap_max, values(gap_perc15) as gap_perc15, values(gap_perc85) as gap_perc85 by ip_address, host
| eval score = TODO: Create potential formula to indicate malicious behavior? 
| eval gap_deviation_avg = gap_deviation_avg * 100, gap_deviation_med = gap_deviation_med * 100 
| sort -failed_usernames 
| where (score_percent > 50 and failed_unique_username_count > 10) or failed_unique_username_count >= 50
| table host, gap_avg, gap_med, gap_std, gap_deviation_avg, gap_deviation_med, gap_min, gap_max, gap_perc15, gap_perc85
| rename host as "Host", gap_avg as "Mean of all time intervals between events", gap_med as "Median of all time intervals between events", gap_std as "Standard deviation of all time intervals between events", gap_deviation_avg as "Standard deviation from the mean as a percent", gap_deviation_med as "Standard deviation from the median as a percent", gap_min as "Minimum time interval between events", gap_max as "Maximum time interval between events", gap_perc15 as "Lower bound after outlier removal", gap_perc85 as "Upper bound after outlier removal"
```

### (WIP) Kerberoasting Statistics

``` splunk
index="ossec_logs" location=EventChannel 
| rename data.win.system.eventID as event_id, data.win.eventdata.ipAddress AS ip_address, data.win.eventdata.targetUserName AS username, data.win.eventdata.ticketEncryptionType AS ticket_encryption_type, data.win.eventdata.ticketOptions AS ticket_options, data.win.eventdata.serviceName as spn 
| search event_id=4769 username!=*$$ (ticket_encryption_type=0x12 OR ticket_encryption_type=0x17) ticket_options=0x40810000 spn!=*$
| eval ip_address = trim(replace(ip_address, "::ffff:", "")) 
| lookup dnslookup clientip as ip_address OUTPUT clienthost as host
| streamstats current=f last(_time) as last_time by username, ip_address, host
| eval gap = last_time - _time 
| eventstats perc85(gap) as gap_perc85, perc15(gap) as gap_perc15, max(gap) as gap_max, min(gap) as gap_min by username, ip_address, host
| eval gap = if(gap > gap_perc15 AND gap < gap_perc85, gap, null())
| eventstats avg(gap) as gap_avg, median(gap) as gap_med, stdev(gap) as gap_std by username, ip_address, host
| eval gap_avg = round(gap_avg, 3), gap_std = round(gap_std, 3) 
| eval gap_deviation_avg = round((gap_std / gap_avg), 3), gap_deviation_med = round((gap_std / gap_med), 3)
| eval gap_deviation_avg = coalesce(gap_deviation_avg, 1.000), gap_deviation_med = coalesce(gap_deviation_med, 1.000)
| stats count(spn) as spn_count, distinct_count(spn) as distinct_spn_count, values(spn) as spns, values(gap_avg) as gap_avg, values(gap_med) as gap_med, values(gap_std) as gap_std, values(gap_deviation_avg) as gap_deviation_avg, values(gap_deviation_med) as gap_deviation_med, values(gap_min) as gap_min, values(gap_max) as gap_max, values(gap_perc15) as gap_perc15, values(gap_perc85) as gap_perc85 by username, ip_address, host
| eval score = TODO: Create potential formula to indicate malicious behavior? 
| eval gap_deviation_avg = gap_deviation_avg * 100, gap_deviation_med = gap_deviation_med * 100
| table host, gap_avg, gap_med, gap_std, gap_deviation_avg, gap_deviation_med, gap_min, gap_max, gap_perc15, gap_perc85
| rename host as "Host", gap_avg as "Mean of all time intervals between events", gap_med as "Median of all time intervals between events", gap_std as "Standard deviation of all time intervals between events", gap_deviation_avg as "Standard deviation from the mean as a percent", gap_deviation_med as "Standard deviation from the median as a percent", gap_min as "Minimum time interval between events", gap_max as "Maximum time interval between events", gap_perc15 as "Lower bound after outlier removal", gap_perc85 as "Upper bound after outlier removal"
```
