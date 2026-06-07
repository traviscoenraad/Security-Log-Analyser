from analyser.parser import parse_line, LogEntry

def load_log_file(filepath: str) -> list[LogEntry]:
    
    # Read the log file and parse every line into a LogEntry object
    entries = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line: entries.append(parse_line(line))
    
    return entries