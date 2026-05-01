package main

import "os"

const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiBlue      = "\033[34m"
	ansiGreen     = "\033[32m"
	ansiYellow    = "\033[33m"
	ansiRed       = "\033[31m"
	ansiUnderline = "\033[4m"
)

var colorsEnabled = shouldEnableColors()

func shouldEnableColors() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	if os.Getenv("TERM") == "dumb" {
		return false
	}

	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	return (info.Mode() & os.ModeCharDevice) != 0
}

func paint(text, color string) string {
	if !colorsEnabled {
		return text
	}

	return color + text + ansiReset
}

func paintBold(text string) string {
	if !colorsEnabled {
		return text
	}

	return ansiBold + text + ansiReset
}

func paintURL(text string) string {
	if !colorsEnabled {
		return text
	}

	return ansiUnderline + ansiBlue + text + ansiReset
}
