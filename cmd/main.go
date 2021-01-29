package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/briandowns/spinner"

	"github.com/citihub/probr"
	"github.com/citihub/probr/cmd/cli_flags"
	"github.com/citihub/probr/internal/config"
	"github.com/citihub/probr/internal/summary"
)

func main() {
	err := config.Init("") // Create default config
	if err != nil {
		log.Printf("[ERROR] error returned from config.Init: %v", err)
		exit(2)
	}

	if len(os.Args[1:]) > 0 {
		log.Printf("[DEBUG] Checking for CLI options or flags")
		cli_flags.HandleRequestForRequiredVars()
		cli_flags.HandlePackOption()
		// TODO: Find a way to get loglevel handling to work ABOVE this point,
		// or to move the Options handlers below the flags handler
		// Currently only ERROR will print prior to HandleFlags()
		cli_flags.HandleFlags()
	}

	config.LogConfigState()

	if showIndicator() {
		// At this loglevel, Probr is often silent for long periods. Add a visual runtime indicator.
		config.Spinner = spinner.New(spinner.CharSets[42], 500*time.Millisecond)
		config.Spinner.Start()
	}

	s, ts, err := probr.RunAllProbes()
	if err != nil {
		log.Printf("[ERROR] Error executing tests %v", err)
		exit(2) // Exit 2+ is for logic/functional errors
	}
	log.Printf("[INFO] Overall test completion status: %v", s)
	summary.State.SetProbrStatus()

	out := probr.GetAllProbeResults(ts)
	if out == nil || len(out) == 0 {
		summary.State.Meta["no probes completed"] = fmt.Sprintf(
			"Probe results not written to file, possibly due to all being excluded or permissions on the specified output directory: %s",
			config.CucumberDir(),
		)
	}
	summary.State.PrintSummary()
	exit(s)
}

// --silent disables, and otherwise only shows on ERROR/WARN
func showIndicator() bool {
	return (config.Vars.LogLevel == "ERROR" || config.Vars.LogLevel == "WARN") && !config.Vars.Silent
}

func exit(status int) {
	if showIndicator() {
		config.Spinner.Stop()
	}
	os.Exit(status)
}
