package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"xAVy/analyzer"
	"xAVy/ml"
)

func main() {
	if len(os.Args) < 2 {
		printUsageAndExit()
	}

	cmd := os.Args[1]

	model := ml.LoadOrCreateModel("av_model.json")
	defer model.Save("av_model.json")

	switch cmd {
	case "train":
		path, isMalicious := parsePathAndYNOrExit("train")
		trainFile(model, path, isMalicious)

	case "trainondir":
		dir, isMalicious := parsePathAndYNOrExit("trainondir")
		trainOnDirectory(model, dir, isMalicious)

	case "scan":
		path := parseJoinedPathOrExit("scan")
		scanFile(model, path)

	case "scandir":
		dir := parseJoinedPathOrExit("scandir")
		scanOnDirectory(model, dir)

	case "stats":
		showStats(model)

	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printUsageAndExit()
	}
}

func printUsageAndExit() {
	fmt.Println("Usage: xavy.exe [command] [args]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("train <file> y|n         Train the model with a single file")
	fmt.Println("trainondir <dir> y|n     Train on all files in a directory")
	fmt.Println("scan <file>              Scan and predict file status")
	fmt.Println("scandir <dir>            Scan all files in a directory")
	fmt.Println("stats                    Show model statistics")
	os.Exit(1)
}

func parsePathAndYNOrExit(cmd string) (string, bool) {
	if len(os.Args) < 4 {
		fmt.Printf("Missing arguments for %s\n", cmd)
		if cmd == "train" {
			fmt.Println("Usage: xavy.exe train <file> y|n")
		} else {
			fmt.Println("Usage: xavy.exe trainondir <dir> y|n")
		}
		os.Exit(1)
	}

	yn := strings.ToLower(os.Args[len(os.Args)-1])
	if yn != "y" && yn != "n" {
		fmt.Println("Last argument must be y|n")
		if cmd == "train" {
			fmt.Println("Usage: xavy.exe train <file> y|n")
		} else {
			fmt.Println("Usage: xavy.exe trainondir <dir> y|n")
		}
		os.Exit(1)
	}

	path := strings.Join(os.Args[2:len(os.Args)-1], " ")
	if strings.TrimSpace(path) == "" {
		fmt.Println("Error: Empty path")
		os.Exit(1)
	}

	return path, yn == "y"
}

func parseJoinedPathOrExit(cmd string) string {
	if len(os.Args) < 3 {
		fmt.Printf("Missing argument for %s\n", cmd)
		if cmd == "scan" {
			fmt.Println("Usage: xavy.exe scan <file>")
		} else {
			fmt.Println("Usage: xavy.exe scandir <dir>")
		}
		os.Exit(1)
	}

	path := strings.Join(os.Args[2:], " ")
	if strings.TrimSpace(path) == "" {
		fmt.Println("Error: Empty path")
		os.Exit(1)
	}
	return path
}

func trainFile(model *ml.RLModel, path string, isMalicious bool) {
	features, err := analyzer.ExtractFeatures(path)
	if err != nil {
		fmt.Printf("Error analyzing file: %v\n", err)
		os.Exit(1)
	}

	prediction := model.Predict(features)

	reward := -1.0
	if (prediction > 0.5 && isMalicious) || (prediction <= 0.5 && !isMalicious) {
		reward = 1.0
		fmt.Println("Correct prediction - Model rewarded")
	} else {
		fmt.Println("Incorrect prediction - Model penalized")
	}

	model.Train(features, isMalicious, reward)

	fmt.Printf("File: %s\n", path)
	fmt.Printf("Actual: %s\n", map[bool]string{true: "MALICIOUS", false: "CLEAN"}[isMalicious])
	fmt.Printf("Prediction Score: %.4f\n", prediction)
	fmt.Printf("Features: Entropy=%.4f, Sections=%d, Imports=%d\n",
		features.Entropy, features.SectionCount, features.ImportCount)
}

func trainOnDirectory(model *ml.RLModel, directory string, isMalicious bool) {
	fmt.Printf("Directory: %s\n", directory)
	fmt.Printf("Label: %s\n\n", map[bool]string{true: "MALICIOUS", false: "CLEAN"}[isMalicious])

	var successCount, failCount int

	err := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("⚠ Error accessing path %s: %v\n", path, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}

		fmt.Printf("Processing: %s\n", path)

		features, err := analyzer.ExtractFeatures(path)
		if err != nil {
			fmt.Printf("  Failed to analyze: %v\n", err)
			failCount++
			return nil
		}

		prediction := model.Predict(features)

		reward := -1.0
		if (prediction > 0.5 && isMalicious) || (prediction <= 0.5 && !isMalicious) {
			reward = 1.0
			fmt.Printf("  Correct prediction (%.4f)\n", prediction)
		} else {
			fmt.Printf("  Incorrect prediction (%.4f)\n", prediction)
		}

		model.Train(features, isMalicious, reward)
		successCount++
		return nil
	})

	if err != nil {
		fmt.Printf("\nError walking directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully trained: %d files\n", successCount)
	fmt.Printf("Failed to process: %d files\n", failCount)
	fmt.Printf("Total files processed: %d\n", successCount+failCount)

	if successCount > 0 {
		stats := model.GetStats()
		if stats.TrainingSamples > 0 {
			accuracy := float64(stats.CorrectPredictions) / float64(stats.TrainingSamples) * 100
			fmt.Printf("Current model accuracy: %.2f%%\n", accuracy)
		}
	}
}

func scanFile(model *ml.RLModel, path string) {
	features, err := analyzer.ExtractFeatures(path)
	if err != nil {
		fmt.Printf("Error analyzing file: %v\n", err)
		os.Exit(1)
	}

	prediction := model.Predict(features)
	status := "CLEAN"
	if prediction > 0.5 {
		status = "MALICIOUS"
	}

	fmt.Printf("File: %s\n", path)
	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Malware Score: %.2f\n", prediction*100)

	fmt.Printf("\nFeature Analysis:\n")
	fmt.Printf(" Entropy: %.4f %s\n", features.Entropy,
		map[bool]string{true: "(HIGH - Suspicious)", false: ""}[features.Entropy > 7.0])
	fmt.Printf(" Sections: %d\n", features.SectionCount)
	fmt.Printf(" Imports: %d\n", features.ImportCount)
	fmt.Printf(" Exports: %d\n", features.ExportCount)
	fmt.Printf(" Suspicious APIs: %d\n", features.SuspiciousAPIs)
	fmt.Printf(" File Size: %d bytes\n", features.FileSize)
}

func scanOnDirectory(model *ml.RLModel, directory string) {
	fmt.Printf("Directory: %s\n\n", directory)

	var total, clean, malicious, failed int

	err := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			failed++
			fmt.Printf("Error accessing %s: %v\n", path, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			failed++
			fmt.Printf("Error reading info %s: %v\n", path, err)
			return nil
		}
		if info.Size() == 0 {
			return nil
		}

		features, err := analyzer.ExtractFeatures(path)
		if err != nil {
			failed++
			fmt.Printf("Failed to analyze: %s (%v)\n", path, err)
			return nil
		}

		p := model.Predict(features)
		total++
		if p > 0.5 {
			malicious++
			fmt.Printf("MALICIOUS  %.2f%%  %s\n", p*100, path)
		} else {
			clean++
			fmt.Printf("CLEAN      %.2f%%  %s\n", p*100, path)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nScanned: %d files\n", total)
	fmt.Printf("Clean: %d\n", clean)
	fmt.Printf("Malicious: %d\n", malicious)
	fmt.Printf("Failed: %d\n", failed)
}

func showStats(model *ml.RLModel) {
	stats := model.GetStats()
	fmt.Printf("Training Samples: %d\n", stats.TrainingSamples)
	fmt.Printf("Correct Predictions: %d\n", stats.CorrectPredictions)
	fmt.Printf("Incorrect Predictions: %d\n", stats.IncorrectPredictions)

	if stats.TrainingSamples > 0 {
		accuracy := float64(stats.CorrectPredictions) / float64(stats.TrainingSamples) * 100
		fmt.Printf("Accuracy: %.2f%%\n", accuracy)
	}
	fmt.Printf("Learning Rate: %.4f\n", stats.LearningRate)
}
