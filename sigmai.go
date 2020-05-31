package main

import (
	"fmt"
	"github.com/rs/zerolog"
	flag "github.com/spf13/pflag"
	"io"
	"os"
	"sigmai/lib/modifiers"
	"sigmai/lib/sources"
	"sigmai/lib/sources/misp"
	"sigmai/lib/sources/misp/api/workers"
	"sigmai/lib/targets"
	"sigmai/lib/targets/directory"
	"sigmai/lib/targets/stdout"
	"time"
)

// The main entry-point of the Sigmai CLI tool
func main() {
	// Define the exit code to use
	// This allows for other defers to be run before we exit
	ExitCode := 0
	defer func() {
		os.Exit(ExitCode)
	}()
	// Define a new set of flags
	f := flag.NewFlagSet("sigmai", flag.ContinueOnError)
	// Define Sigmai options
	o := &options{
		Target: string(targetStdout),
	}
	oFlags := bindOptions(o)
	f.AddFlagSet(oFlags)
	// Define modifier options
	oModifier := &modifiers.Options{}
	oModifierFlags := bindModifierOptions(oModifier)
	f.AddFlagSet(oModifierFlags)
	// Define MISP source options
	oMISP := &misp.Options{
		WorkerOptions: &workers.Options{
			Buffer: 500,
		},
		Workers: 20,
	}
	oMISPFlags := bindMISPOptions(oMISP)
	f.AddFlagSet(oMISPFlags)
	// Define Directory target options
	oDirectory := &directory.Options{}
	oDirectoryFlags := bindDirectoryOptions(oDirectory)
	f.AddFlagSet(oDirectoryFlags)
	// Parse the CLI arguments and send errors to stderr
	if err := f.Parse(os.Args[1:]); err != nil || o.Help {
		// Output the general usage
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\r\n%s", os.Args[0], f.FlagUsages())
		// If an error occurred, also output the error
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			// Exit with an error code
			ExitCode = ErrInvalidArgs
		}
		return
	}
	// Create a new logger
	out := io.Writer(os.Stderr)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	// Pretty print if we aren't expected to provide JSON
	if !o.JSON {
		out = zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
			PartsOrder: []string{
				zerolog.TimestampFieldName,
				zerolog.LevelFieldName,
				zerolog.CallerFieldName,
				zerolog.MessageFieldName,
			},
		}
	}
	// Capture the timestamp in the logs
	log := zerolog.New(out).Level(zerolog.InfoLevel).With().Timestamp().Logger()
	// Log debug messages if needed
	if !o.Verbose {
		log = log.Level(zerolog.DebugLevel)
	}
	// Define our source based on the `-s` flag
	var s sources.Source
	var serr error
	switch source(o.Source) {
	case sourceMISP:
		s, serr = misp.New(oMISP, log)
	default:
		serr = fmt.Errorf("unknown source %#v", o.Source)
	}
	if serr != nil {
		log.Err(serr).Msg("an error occurred setting up the source")
		ExitCode = ErrSource
		return
	}
	// Define our target based on the `-t` flag
	var t targets.Target
	var terr error
	switch target(o.Target) {
	case targetStdout:
		t = stdout.New()
	case targetDirectory:
		t = directory.New(oDirectory, log)
	default:
		terr = fmt.Errorf("unknown target %#v", o.Target)
	}
	if terr != nil {
		log.Err(terr).Msg("an error occurred setting up the target")
		ExitCode = ErrTarget
		return
	}
	// Generate a modifier
	m := modifiers.Modifier{Options: oModifier}
	// Check if it is a scheduled or one-time run
	if len(o.Interval) > 0 {
		// Parse the duration
		d, err := time.ParseDuration(o.Interval)
		if err != nil {
			log.Err(terr).Msg("an error occurred parsing the interval")
			ExitCode = ErrInvalidArgs
			return
		}
		// Abort if the interval is negative
		if d <= 0 {
			log.Err(fmt.Errorf("the interval %#v is invalid", d.String())).Msg("an error occurred parsing the interval")
			ExitCode = ErrInvalidArgs
			return
		}
		// Create a new ticker
		ticker := time.NewTicker(d)
		// Make an unscheduled run
		if err := convert(s, m, t); err != nil {
			log.Err(err).Send()
			ExitCode = ErrInvalidArgs
			return
		}
		// Run at each tick
		for {
			select {
			case <-ticker.C:
				// Make a synchronous run, unused ticks will be skipped
				if err := convert(s, m, t); err != nil {
					log.Err(err).Send()
					ExitCode = ErrRun
					return
				}
			}
		}
	} else {
		// Make a one-time run
		if err := convert(s, m, t); err != nil {
			log.Err(err).Send()
			ExitCode = ErrRun
		}
		return
	}
}

func convert(s sources.Source, m modifiers.Modifier, t targets.Target) error {
	// Get a channel of rules
	c, err := s.Rules()
	if err != nil {
		return err
	}
	// Send the rules to our target
	for rules := range c {
		// Ignore empty rules
		if len(rules) == 0 {
			continue
		}
		// Apply the modifier
		m.Process(rules)
		// Send the modified rule to our target
		if err := t.Process(rules); err != nil {
			return err
		}
	}
	return s.Error()
}

// The Sigmai options
type options struct {
	Source   string
	Help     bool
	Target   string
	Verbose  bool
	Interval string
	JSON     bool
}

// Define the available sources
type source string

const (
	sourceMISP source = "misp"
)

// Define the available targets
type target string

const (
	targetStdout    target = "stdout"
	targetDirectory target = "directory"
)

func bindOptions(o *options) *flag.FlagSet {
	f := flag.NewFlagSet("Sigmai", flag.ContinueOnError)
	f.StringVarP(&o.Source, "source", "s", "", fmt.Sprintf("Source backend [%s]", sourceMISP))
	f.StringVarP(&o.Target, "target", "t", string(targetStdout), fmt.Sprintf("Target backend [%s, %s]", targetStdout, targetDirectory))
	f.BoolVarP(&o.Help, "help", "h", false, "Display this help section")
	f.BoolVarP(&o.Verbose, "verbose", "v", o.Verbose, "Show debug information")
	f.StringVarP(&o.Interval, "interval", "i", o.Interval, "Continuous importing interval")
	f.BoolVar(&o.JSON, "json", o.JSON, "Output JSON instead of pretty print")
	return f
}

func bindMISPOptions(o *misp.Options) *flag.FlagSet {
	f := flag.NewFlagSet("MISP", flag.ContinueOnError)
	f.StringVar(&o.WorkerOptions.URL, "misp-url", o.WorkerOptions.URL, "MISP: Instance API base URL")
	f.BoolVar(&o.WorkerOptions.Insecure, "misp-insecure", o.WorkerOptions.Insecure, "MISP: Allow insecure connections when using SSL")
	f.StringVar(&o.WorkerOptions.Key, "misp-key", o.WorkerOptions.Key, "MISP: User API key")
	f.IntSliceVar(&o.WorkerOptions.Events, "misp-events", o.WorkerOptions.Events, "MISP: Only events with matching IDs")
	f.BoolVar(&o.WorkerOptions.IDSInclude, "misp-ids", o.WorkerOptions.IDSInclude, "MISP: Only IDS-enabled attributes")
	f.BoolVar(&o.WorkerOptions.IDSExclude, "misp-ids-exclude", o.WorkerOptions.IDSExclude, "MISP: Only IDS-disabled attributes")
	f.StringSliceVar(&o.WorkerOptions.Period, "misp-period", o.WorkerOptions.Period, "MISP: Only events within time-frame (4d, 3w, ...)")
	f.BoolVar(&o.WorkerOptions.PublishedInclude, "misp-published", o.WorkerOptions.PublishedInclude, "MISP: Only published events")
	f.BoolVar(&o.WorkerOptions.PublishedExclude, "misp-published-exclude", o.WorkerOptions.PublishedExclude, "MISP: Only unpublished events")
	f.IntVar(&o.WorkerOptions.Buffer, "misp-buffer", o.WorkerOptions.Buffer, "MISP: Size of the event buffer")
	f.BoolVar(&o.WorkerOptions.WarningExclude, "misp-warning-exclude", o.WorkerOptions.WarningExclude, "MISP: Only attributes without warning-list")
	f.StringArrayVar(&o.WorkerOptions.Tags, "misp-tags", o.WorkerOptions.Tags, "MISP: Only events with matching tags")
	f.StringArrayVar(&o.WorkerOptions.ThreatLevel, "misp-levels", o.WorkerOptions.ThreatLevel, fmt.Sprintf("MISP: Only events with matching threat levels [1-4]"))
	f.IntVar(&o.Workers, "misp-workers", o.Workers, "MISP: Number of concurrent workers")
	return f
}

func bindDirectoryOptions(o *directory.Options) *flag.FlagSet {
	f := flag.NewFlagSet("Directory", flag.ContinueOnError)
	f.StringVar(&o.Path, "directory-path", o.Path, "Directory: Path to save rules")
	return f
}

func bindModifierOptions(o *modifiers.Options) *flag.FlagSet {
	f := flag.NewFlagSet("Modifier", flag.ContinueOnError)
	f.StringArrayVar(&o.TagsAdd, "tags-add", o.TagsAdd, "Add tags on all rules")
	f.StringArrayVar(&o.TagsRm, "tags-rm", o.TagsRm, "Remove tags from all rules")
	f.StringArrayVar(&o.TagsSet, "tags-set", o.TagsSet, "Set tags on all rules")
	f.BoolVar(&o.TagsClear, "tags-clear", o.TagsClear, "Clear tags from all rules")
	return f
}

const (
	ErrInvalidArgs int = iota + 1
	ErrSource
	ErrTarget
	ErrRun
)
