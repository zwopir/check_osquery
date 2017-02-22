package main

import (
	"github.com/zwopir/gonag"
	_ "github.com/zwopir/check_osquery/model"
	"github.com/zwopir/check_osquery/osquery"
	"github.com/prometheus/common/log"
	"text/template"

	"flag"
	"bytes"
	"strconv"

	"fmt"
	"os"
)



func main() {
	const (
		defaultTemplateString = `osquery returned count = {{ index . "count" }}`
	)
	var (
		timeoutString = flag.String("timeout", "5s", "osquery timeout. Value must be time.ParseDuration'able")
		query = flag.String("query", "", "osquery string. Must return a single result set with at least one key/value named 'count'. " +
			"All other key/value pairs can be used in the output text template as {{ index . \"key\" }}")
		osqueryExecutable = flag.String("osquery","osqueryi", "osquery executable")
		templateString = flag.String("text template", defaultTemplateString, "nagios result text template")
		warn = flag.String("warn", "", "warning threshold. Must be empty or parseable as float64")
		crit = flag.String("crit", "", "critical threshold. Must be empty or parseable as float64")
	)
	flag.Parse()

	template, err := template.New("nagios output").Parse(*templateString)
	if err != nil {
		log.Fatalf("can't parse template %q", *templateString)
	}

	runner, err := osquery.NewRunner(*osqueryExecutable, *timeoutString)
	if err != nil {
		log.Fatalf("failed to create osquery runner:", err)
	}
	if *query == "" {
		log.Fatal("no osquery string provided as cmdline")
	}
	result, err := runner.Run(*query)
	if err != nil {
		log.Fatal("failed to run osquery:", err)
	}
	if len(result.Items) != 1 {
		log.Fatalf("expected one resultset from osquery, got %d", len(result.Items))
	}

	data := result.Items[0]

	if _, ok := data["count"]; !ok {
		log.Fatalf("osquery result doesn't contain a key 'count'")
	}
	count, err := strconv.ParseFloat(data["count"], 32)
	if err != nil {
		log.Fatalf("count key/value pair can't be parsed as float")
	}
	severity := gonag.OK
	if *warn != "" {
		if warning, err := strconv.ParseFloat(*warn, 32); err == nil {
			if count > warning {
				severity = gonag.WARNING
			}
		}
	}
	if *crit != "" {
		if critical, err := strconv.ParseFloat(*crit, 32); err == nil {
			if count > critical {
				severity = gonag.CRITICAL
			}
		}
	}


	resultText := bytes.NewBuffer([]byte(``))
	template.Execute(resultText, &data)

	_, countUOM, err := gonag.ParseValue(data["count"])
	if err != nil {
		log.Fatalf("failed to parse count uom")
	}
	runtime, timeUOM, err := gonag.ParseValue(fmt.Sprintf("%fs",result.Runtime.Seconds()))
	if err != nil {
		log.Fatalf("failed to parse runtime uom from %s", fmt.Sprintf("%fs",result.Runtime.Seconds()))
	}
	nagiosResult := gonag.CheckResult{
		ReturnCode: severity,
		Text: resultText.String(),
		Perfdata: gonag.Perfdata{
			{
				Label: "count",
				Value: data["count"],
				Thresholds: gonag.Thresholds{
					gonag.Warn: *warn,
					gonag.Crit: *crit,
				},
				UOM: countUOM,
			},
			{
				Label: "runtime",
				Value: runtime,
				Thresholds: gonag.Thresholds{				},
				UOM: timeUOM,
			},
		},

	}
	outputString, err := nagiosResult.RenderCheckResult(gonag.NagiosMRPEFormatter)
	if err != nil {
		log.Fatal("failed to render check result as nagios check")
	}
	fmt.Println(outputString)
	os.Exit(int(nagiosResult.ReturnCode))
}
