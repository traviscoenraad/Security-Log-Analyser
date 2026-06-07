import argparse
from analyser.ingestion import load_log_file
from analyser.detection.engine import run_all_detectors
from analyser.reporter import generate_report

def main():
    # Define the CLI arguments for the tool to accept
    parser = argparse.ArgumentParser(
        description = "Security Log Analyser - detects threats in authentication logs"
    )
    parser.add_argument(
        "--log",
        required = True,
        help = "Path to the log file to analyse"
    )
    args = parser.parse_args()

    # Load and parse the log file
    try:
        entries = load_log_file(args.log)
    except FileNotFoundError:
        print(f"Error: Log file '{args.log}' not found.")
        return

    #Run all detectors and generate report
    threats = run_all_detectors(entries)
    report = generate_report(threats, args.log)
    print(report)

if __name__ == "__main__":
    main()