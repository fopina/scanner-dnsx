package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path"

	"github.com/fopina/scanner-go-entrypoint/scanner"
)

func main() {
	s := scanner.Scanner{
		Name: "dnsx",
	}
	options := s.BuildOptions()
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

	flags := append(
		[]string{
			"-json",
			"-o", file.Name(),
			"-duc",
			"-l",
			options.Input,
		},
		options.ExtraFlags...,
	)
	cmd := exec.Command(options.BinPath, flags...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

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
