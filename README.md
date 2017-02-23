# check_osquery
check_osquery returns results from an osquery (https://osquery.io) as a nagios check.

The query is expected to return a single result set. A result key is then evaluated against the provided thresholds 'warn' and 'crit'. If no thresholds are provided, the check returns "OK" (exit code 0) and only reports the query result in the check performance data part.

## Install
(tested with go1.7)

```bash
go get -v
go build
```

## Run
### Get help

```bash
./check_osquery -h
  -crit string
    	critical threshold. Must be empty or parseable as float64
  -log.format value
    	Set the log target and format. Example: "logger:syslog?appname=bob&local=7" or "logger:stdout?json=true" (default "logger:stderr")
  -log.level value
    	Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal] (default "info")
  -osquery string
    	osquery executable (default "osqueryi")
  -query string
    	osquery string. Must return a single osquery result. The value of the config parameter 'resultkey' is used in the threshold evaluation (default see there). All other key/value pairs can be used in the output text template as {{ index . "key" }}
  -resultkey string
    	osqueryResult key. Specifies the key within the osquery osqueryResult set that holds the value for threshold comparision. (default "count(*)")
  -template string
    	nagios osqueryResult text template (default "osquery returned result = {{ index . \"count(*)\" }}")
  -timeout string
    	osquery timeout. Value must be time.ParseDuration'able (default "5s")
  -warn string
    	warning threshold. Must be empty or parseable as float64
```

### Examples
#### get number of httpd processes

```bash
./check_osquery -query 'select count(*) from processes where name like "%httpd%" ;' \
  -warn 10 \
  -crit 50 \
  -template 'there are {{ index . "count(*)" }} httpd processes running'
```

example output

```
WARNING - there are 15 httpd processes running|result=91;10;50;; runtime=0.050957s;;;;
exit status 1
```
