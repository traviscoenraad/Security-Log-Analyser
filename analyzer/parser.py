from dataclasses import dataclass
from datetime import datetime

@dataclass
#Creating a class to store Log entry data
class LogEntry:
    timestamp: datetime
    status: str
    user: str
    ip: str

#This function parses each log line and takes the relevant information
def parse_line(line: str) -> LogEntry:
    line = line.strip()
    parts = line.split(" ")

    date_str = parts[0]
    time_str = parts[1]
    status = parts[2]
    user = parts[4].split("=")[1]
    ip = parts[5].split("=")[1]

    #Combines the date and time into one object 
    timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")

    #Returns a LogEntry object with the parsed data
    return LogEntry(timestamp = timestamp, status = status, user = user, ip = ip)
