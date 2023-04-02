package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"

	flag "github.com/spf13/pflag"
	"github.com/surface-security/scanner-go-entrypoint/scanner"
)

type localOptions struct {
	all       bool // resolve for all record types
	lineLimit int  // split input to have (partial) results sooner
}

func scan(s *scanner.Scanner, moreOptions *localOptions, input, output string) {
	// pass temporary file to dnsx instead of final path, as only finished files should be placed there
	file, err := os.CreateTemp("", "dnsx")
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer os.Remove(file.Name())

	flags := []string{
		"-json",
		"-o", file.Name(),
		"-duc",
		"-l",
		input,
	}
	if moreOptions.all {
		flags = append(
			flags,
			"-a", "-aaaa", "-cname",
			"-ns", "-txt", "-srv",
			"-ptr", "-mx", "-soa",
			"-axfr", "-caa",
		)
	}
	err = s.Exec(flags...)
	if err != nil {
		log.Fatalf("Failed to run scanner: %v", err)
	}

	realOutputFile := path.Join(s.Options.Output, output)
	outputFile, err := os.Create(realOutputFile)
	if err != nil {
		log.Fatalf("Couldn't open dest file: %v", err)
	}
	defer outputFile.Close()
	_, err = io.Copy(outputFile, file)
	if err != nil {
		log.Fatalf("Writing to output file failed: %v", err)
	}
}

func main() {
	s := scanner.Scanner{
		Name: "dnsx",
	}
	moreOptions := &localOptions{}
	options := s.BuildOptions()
	flag.BoolVar(&moreOptions.all, "all", false, "Resolve for all DNS record types (same as using all the extra flags `-a -aaaa -cname ...` together)")
	flag.IntVarP(&moreOptions.lineLimit, "line-limit", "l", 0, "Split input to have (partial) results sooner")
	scanner.ParseOptions(options)

	err := os.MkdirAll(options.Output, 0755)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if moreOptions.lineLimit == 0 {
		scan(&s, moreOptions, options.Input, "output.txt")
	} else {
		file, err := os.CreateTemp("", "dnsx")
		if err != nil {
			log.Fatalf("%v", err)
		}
		defer os.Remove(file.Name())
		pending := 0
		block := 0

		scanner.ReadInputLines(options, func(hostname string) bool {
			file.Write([]byte(hostname))
			file.Write([]byte("\n"))
			pending++
			if pending >= moreOptions.lineLimit {
				block++
				scan(&s, moreOptions, file.Name(), fmt.Sprintf("output_%d.txt", block))
				pending = 0
				file.Truncate(0)
				file.Seek(0, 0)
			}
			return true
		})
		if pending > 0 {
			block++
			scan(&s, moreOptions, file.Name(), fmt.Sprintf("output_%d.txt", block))
		}
	}
}
