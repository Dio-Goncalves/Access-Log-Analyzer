import re
from datetime import datetime
import sys
from collections import Counter

# First, we'll use the re.compile function to create a regular expression object. This will set the a fixed pattern for future comparison.
# A raw expression with a regular variable could be used too. More info at https://docs.python.org/3/library/re.html#re.compile
PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"$')


# To keep main as small as possible, all it will do is call the log file, using sys.argv, and execute the "load_entries" function with the log file as an argument, to load all entries onto the "entries" variable.
# Then, if there are no errors, it will simply print the output of the "format_report" function, which will print onto the terminal the parsing results.
# The function is programmed to abort via sys.exit if the number of arguments of the command isn't correct, if the file isn't valid/does not exit or if it doesn't have any valid log entries inside.
def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python project.py LOGFILE")
    file = sys.argv[1]
    try:
        entries = load_entries(file)
    except FileNotFoundError:
        sys.exit(f"File not found: {file}")
    if not entries:
        sys.exit("No valid log entries found")
    print(format_report(entries, file))


# Function that will match the log with our pattern and parse it.
def parse_log(log):
    match = PATTERN.match(log.strip())
    if not match:
        return None
    entry = match.groupdict()
    entry["status"] = int(entry["status"])
    entry["size"] = 0 if entry["size"] == "-" else int(entry["size"])
    entry["time"] = datetime.strptime(entry["time"], "%d/%b/%Y:%H:%M:%S %z")
    return entry


# Function that will open the log file, parse its entries and load the valid parsed entries onto a list.
def load_entries(path):
    entries = []
    with open(path) as file:
        for line in file:
            entry = parse_log(line)
            if entry is not None:
                entries.append(entry)
    return entries


# This function counts how many times each status code appears in the logs.
def count_statuses(entries):
    counts = Counter()
    for entry in entries:
        counts[entry["status"]] += 1
    return counts


# This function counts how many times an error code appears in the logs and then divides that number by the amount of entries in the log, giving us the error rate. Simply multiply by 100 to get the %.
# It is also important to mention that to avoid having 0 dividing by itself, the function starts with an if condition that automatically returns 0 if there are no log entries in the file.
def error_rate(entries):
    if not entries:
        return 0
    errors = 0
    for entry in entries:
        if entry["status"] >= 400:
            errors += 1
    return errors/len(entries)


# This function counts how many times each IP appears in the logs. Then, with *n* as an argument, uses the .most_common object to return the *n* most common IPs.
def top_ips(entries, n):
    return Counter(entry["ip"] for entry in entries).most_common(n)

# Here I define the threshold global variable to be used in the functions below. If this value needs to be changed, change this variable ONLY.
THRESHOLD = 5

# This function starts by counting the amount of times each IP has an error code associated to it. Then, it proceeds to return the IPs that have a count equal to or larger than the threshold.
# For example, the second argument **threshold** is setup to be equal to *5*. That means that if an IP has 5 or more entries with error codes ( code >= 400 ), that IP will be returned.
# NOTE: if the threshold argument needs to be changed, make sure to changed the THRESHOLD variable set up above.
def flag_suspicious(entries, threshold=THRESHOLD):
    counts = Counter(entry["ip"] for entry in entries if entry["status"] >= 400)
    return [(ip, count) for ip, count in counts.most_common() if count >= threshold]


# This function is responsible for formatting the report. Using formatted strings and the .append object, we build a list of list of lines and join them, in the end. Returning a string, instead of printing.
# It was built in a modular way for easier reading, testing and maintainability.
def format_report(entries, path):
    lines = [
        f"Log report: {path}",
        "=" * 40,
        f"Total requests:  {len(entries)}",
        f"Error rate:      {error_rate(entries):.1%}",
        "",
        "Status count",
    ]
# This makes use of the 'count_statuses' function to count how many times each status code appears and then presents those counts in the form of columns.
    for status, count in sorted(count_statuses(entries).items()):
        lines.append(f"  {status:<6}{count:>3}")
# The part below, appends to the list the entries for the top 5 busiest IPs. It makes use of the 'top_ips' function, with the second argument dicating how many entries we want to appear.
# For example, since we want the "top 5 busiest IPs", the second argument of the function, has to be 5.
    lines.append("") # This adds an empty line to the block to separate things, once we join all the content.
    lines.append("Top 5 IPs")
    for ip, count in top_ips(entries, 5):
        lines.append(f" {ip:<18}{count:>6}")
# Below is the part responsible for handling the suspicious IPs. It references the threshold variable that was setup before defining the 'flag_suspicious' and 'format_report' functions.
    lines.append("")
    lines.append(f"Suspicious IPs ({THRESHOLD} or more errors)")
    suspicious = flag_suspicious(entries)
    if suspicious:
        for ip, count in suspicious:
            lines.append(f" {ip:<18}{count:>6} errors")
    else:
        lines.append("(none found)")
# This part below, joins all the values in the "lines" variable as a multiline string and returns them.
    return "\n".join(lines)


if __name__ == "__main__":
    main()
