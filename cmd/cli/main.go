package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "election":
		handleElectionCommand(args)
	case "booth":
		handleBoothCommand(args)
	case "voter":
		handleVoterCommand(args)
	case "vote":
		handleVoteCommand(args)
	case "keys":
		handleKeysCommand(args)
	case "results":
		handleResultsCommand(args)
	case "export":
		handleExportCommand(args)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("E-Voting Demo CLI")
	fmt.Println("\nUsage:")
	fmt.Println("  evoting-cli <command> [args]")
	fmt.Println("\nCommands:")
	fmt.Println("  election    Manage election (create, reset)")
	fmt.Println("  booth       Manage booths (assign)")
	fmt.Println("  voter       Manage voters (add, freeze)")
	fmt.Println("  vote        Voting operations (cast, publish, verify)")
	fmt.Println("  keys        Key management (release)")
	fmt.Println("  results     Show election results")
	fmt.Println("  export      Export election data")
}
