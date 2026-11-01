from project import parse_log, load_entries, count_statuses, error_rate, top_ips, flag_suspicious, format_report
from datetime import datetime, timedelta, timezone

# To test 'parse_log' we store in a variable what would be a valid Apache log entry. Then, we proceed to process said variable using the 'parse_log' function;
# We then assert that each key of the resulting dictionary ("ip", "time", ...) holds the expected value.
def test_parse_log():
    log = '168.177.107.132 - - [26/Oct/2026:17:17:12 +0100] "POST /explore HTTP/1.0" 200 5081 "https://www.miller-robinson.com/category/wp-content/bloglogin.htm" "Mozilla/5.0 (iPod; U; CPU iPhone OS 4_2 like Mac OS X; bo-CN) AppleWebKit/535.36.2 (KHTML, like Gecko) Version/3.0.5 Mobile/8B112 Safari/6535.36.2"'
    entry = parse_log(log)
    assert entry["ip"] == "168.177.107.132"
    assert entry["time"] == datetime(
        2026, 10, 26, 17, 17, 12, tzinfo=timezone(timedelta(hours=1)))
    assert entry["method"] == "POST"
    assert entry["path"] == "/explore"
    assert entry["status"] == 200
    assert entry["size"] == 5081
    assert entry["referer"] == "https://www.miller-robinson.com/category/wp-content/bloglogin.htm"
    assert entry["agent"] == "Mozilla/5.0 (iPod; U; CPU iPhone OS 4_2 like Mac OS X; bo-CN) AppleWebKit/535.36.2 (KHTML, like Gecko) Version/3.0.5 Mobile/8B112 Safari/6535.36.2"

# Since the 'parse_log' function is programmed to return 'None' when it is given an invalid entry in a log, thats exactly what we write on the test below. Give it an invalid dummy line and make it return "None.
def test_parse_log_invalid():
    assert parse_log("this is not a log line") is None

# Here we make use of 'tmp_path', a built-in pytest feature that provides a unique object, pointing to a temporary directory that we can use for tesst functions;
# For this function, we write to a log file 2 dummy lines, 1 of which is invalid. The 'load_entries' function should return only 1 valid entry, with its respective values.
def test_load_entries(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        '1.2.3.4 - - [26/Oct/2026:17:17:12 +0100] "GET /list HTTP/1.0" 200 100 "http://a.com" "Mozilla/5.0"\n'
        "this line is garbage\n"
    )
    entries = load_entries(log_file)
    assert len(entries) == 1
    assert entries[0]["ip"] == "1.2.3.4"

# To test the 'count_statuses' function, we create a dummy "entries" dictionary with status codes and then assert the expected values it should return, according to the function's logic.
def test_count_statuses():
    entries = [{"status": 200}, {"status": 200}, {"status": 404}]
    assert count_statuses(entries) == {200: 2, 404: 1}

# The 'count_statuses' function, should return an empty dictionary for an empty entry.
def test_count_statuses_empty():
    assert count_statuses([]) == {}

# To test the 'error_rate' function, we proceed to create yet another dummy dictionary with more http status codes;
# By passing a dictionary onto the function, where half the values are error codes we assert that the output of the function should be 0.5, matching the function's logic.
def test_error_rate():
    entries = [{"status": 200}, {"status": 200},
               {"status": 404}, {"status": 500}]
    assert error_rate(entries) == 0.5

# If there are no error codes, the function should simply output a value of 0.
def test_error_rate_no_errors():
    assert error_rate([{"status": 200}, {"status": 301}]) == 0

# If there are no codes at all, the function should also output the value of 0.
def test_error_rate_empty():
    assert error_rate([]) == 0

# To test the 'top_ips' function, we create a dictionary with dummy IP entries;
# Following the function's logic, we should assert that the function should output a list of tuples, each containing an IP address and the corresponding count of times that it appears in the logs;
# The second argument (2), in this case says that we want the top 2 busiest IPs.
def test_top_ips():
    entries = [
        {"ip": "1.1.1.1"},
        {"ip": "2.2.2.2"},
        {"ip": "1.1.1.1"},
        {"ip": "3.3.3.3"},
        {"ip": "1.1.1.1"},
        {"ip": "2.2.2.2"},
    ]
    assert top_ips(entries, 2) == [("1.1.1.1", 3), ("2.2.2.2", 2)]

# Here we assert that if we ask for the top 3 busiest IPs but we then proceed to pass an empty value, we will be returned an empty list.
def test_top_ips_empty():
    assert top_ips([], 3) == []

# To test the 'flag_suspicious' function, we create a dummy entry with the variable 'entries'. This dummy entry contains 3 error entries and 1 valid entry for the IP 1.1.1.1 and 1 invalid entry for the IP 2.2.2.2;
# Since we assume a threshold of 3, we only want IPs that present 3 or more invalid entries;
# We then proceed to assert that we should only be returned a tuple with the 1.1.1.1 IP and the count of the 3 invalid entries it presents, following the function's logic.
def test_flag_suspicious():
    entries = (
        [{"ip": "1.1.1.1", "status": 404}] * 3
        + [{"ip": "2.2.2.2", "status": 404}]
        + [{"ip": "1.1.1.1", "status": 200}]
    )
    assert flag_suspicious(entries, threshold=3) == [("1.1.1.1", 3)]

# Here, we create a dummy entry of 10 invalid entries and assert we should be returned an empty list.
def test_flag_suspicious_none():
    entries = [{"ip": "1.1.1.1", "status": 200}] * 10
    assert flag_suspicious(entries) == []

# To test the 'format_report' function, we pass a small list of entries, with the necessary keys to the functions ("ip" and "status");
# We then proceed to check the resulting text for the key lines - two of the four entries are errors, so the error rate has to be 50%;
# No IP reaches the threshold of 5 errors, so the suspicious IP part, should output "(none found)".
def test_format_report():
    entries = [
        {"ip": "1.1.1.1", "status": 200},
        {"ip": "1.1.1.1", "status": 404},
        {"ip": "2.2.2.2", "status": 200},
        {"ip": "3.3.3.3", "status": 500},
    ]
    report = format_report(entries, "test.log")
    assert "Total requests:  4" in report
    assert "Error rate:      50.0%" in report
    assert "(none found)" in report
