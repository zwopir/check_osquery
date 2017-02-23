package main

import (
	"github.com/prometheus/common/log"
	"github.com/zwopir/check_osquery/osquery"
	"github.com/zwopir/gonag"
	"text/template"

	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
)

func main() {
	const (
		defaultTemplateString = `osquery returned result = {{ index . "count(*)" }}`
	)
	var (
		timeoutString = flag.String("timeout", "5s", "osquery timeout. Value must be time.ParseDuration'able")
		query         = flag.String("query", "", "osquery string. Must return a single osqueryResult. The value of the config parameter 'resultkey' is used "+
			"in the threshold evaluation (default see there). All other key/value pairs can be used in the output text template as {{ index . \"key\" }}")
		resultKey = flag.String("resultkey", "count(*)", "osqueryResult key. Specifies the key within the osquery osqueryResult set that holds the "+
			"value for threshold comparision.")
		osqueryExecutable = flag.String("osquery", "osqueryi", "osquery executable")
		templateString    = flag.String("template", defaultTemplateString, "nagios osqueryResult text template")
		warn              = flag.String("warn", "", "warning threshold. Must be empty or parseable as float64")
		crit              = flag.String("crit", "", "critical threshold. Must be empty or parseable as float64")
	)
	flag.Parse()

	template, err := template.New("nagios output").Parse(*templateString)
	if err != nil {
		exitUnknown("can't parse template %q", *templateString)
	}

	runner, err := osquery.NewRunner(*osqueryExecutable, *timeoutString)
	if err != nil {
		exitUnknown("failed to create osquery runner:", err)
	}
	if *query == "" {
		log.Fatal("no osquery string provided as cmdline")
	}
	osqueryResult, err := runner.Run(*query)
	if err != nil {
		log.Fatal("failed to run osquery:", err)
	}
	if len(osqueryResult.Items) != 1 {
		exitUnknown("expected one resultset from osquery, got %d", len(osqueryResult.Items))
	}

	data := osqueryResult.Items[0]

	if _, ok := data[*resultKey]; !ok {
		exitUnknown("osquery osqueryResult doesn't contain a key %s", resultKey)
	}
	result, err := strconv.ParseFloat(data[*resultKey], 32)
	if err != nil {
		exitUnknown("%s key/value pair can't be parsed as float", resultKey)
	}
	severity := gonag.OK
	if *warn != "" {
		if warning, err := strconv.ParseFloat(*warn, 32); err == nil {
			if result > warning {
				severity = gonag.WARNING
			}
		}
	}
	if *crit != "" {
		if critical, err := strconv.ParseFloat(*crit, 32); err == nil {
			if result > critical {
				severity = gonag.CRITICAL
			}
		}
	}

	resultText := bytes.NewBuffer([]byte(``))
	template.Execute(resultText, &data)

	_, resultUOM, err := gonag.ParseValue(data[*resultKey])
	if err != nil {
		exitUnknown("failed to parse result uom")
	}
	runtime, timeUOM, err := gonag.ParseValue(fmt.Sprintf("%fs", osqueryResult.Runtime.Seconds()))
	if err != nil {
		exitUnknown("failed to parse runtime uom from %s", fmt.Sprintf("%fs", osqueryResult.Runtime.Seconds()))
	}
	nagiosResult := gonag.CheckResult{
		ReturnCode: severity,
		Text:       resultText.String(),
		Perfdata: gonag.Perfdata{
			{
				Label: "result",
				Value: data[*resultKey],
				Thresholds: gonag.Thresholds{
					gonag.Warn: *warn,
					gonag.Crit: *crit,
				},
				UOM: resultUOM,
			},
			{
				Label:      "runtime",
				Value:      runtime,
				Thresholds: gonag.Thresholds{},
				UOM:        timeUOM,
			},
		},
	}
	outputString, err := nagiosResult.RenderCheckResult(gonag.NagiosMRPEFormatter)
	if err != nil {
		log.Fatal("failed to render check osqueryResult as nagios check")
	}
	fmt.Println(outputString)
	os.Exit(int(nagiosResult.ReturnCode))
}

func exitUnknown(msgFormat string, a ...interface{}) {
	log.Errorf(msgFormat, a...)
	r := gonag.CheckResult{
		ReturnCode: gonag.UNKNOWN,
		Text:       fmt.Sprintf(msgFormat, a...),
		Perfdata:   gonag.Perfdata{},
	}
	returnString, _ := r.RenderCheckResult(gonag.NagiosMRPEFormatter)
	fmt.Println(returnString)
	os.Exit(int(r.ReturnCode))
}
