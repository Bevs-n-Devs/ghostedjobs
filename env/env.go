package env

import (
	"bufio"
	"os"
	"strings"
)

/*
LoadEnv parses a file with environment variables in the format KEY=VALUE and
sets the variables in the current process's environment.

Lines starting with "#" are ignored as are empty lines. If a line does not
contain a "=", it is skipped.

Any errors encountered while reading the file are returned.
*/
func LoadEnv(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// ignore empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// split key-calue pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// set environment variable
		os.Setenv(key, value)
	}
	return scanner.Err()
}
