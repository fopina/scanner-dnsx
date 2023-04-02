package main

import (
	"io"
	"log"
	"os"
	"path"

	flag "github.com/spf13/pflag"
	"github.com/surface-security/scanner-go-entrypoint/scanner"
)

type localOptions struct {
	all bool // resolve for all record types
}

func main() {
	s := scanner.Scanner{
		Name: "dnsx",
	}
	moreOptions := &localOptions{}
	options := s.BuildOptions()
	flag.BoolVar(&moreOptions.all, "all", false, "Resolve for all DNS record types (same as using all the extra flags `-a -aaaa -cname ...` together)")
	scanner.ParseOptions(options)

	err := os.MkdirAll(options.Output, 0755)
	if err != nil {
		log.Fatalf("%v", err)
	}

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
		options.Input,
	}
	if moreOptions.all {
		flags = append(
			flags,
			"-a",
			"-aaaa",
			"-cname",
			"-ns",
			"-txt",
			"-srv",
			"-ptr",
			"-mx",
			"-soa",
			"-axfr",
			"-caa",
		)
	}
	err = s.Exec(flags...)
	if err != nil {
		log.Fatalf("Failed to run scanner: %v", err)
	}

	realOutputFile := path.Join(options.Output, "output.txt")
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
