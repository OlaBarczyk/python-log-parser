import sys


def read_log(file_path, keyword=None):
    """
    Read log file line by line and optionally filter by keyword.
    """
    matched = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                text = line.strip()
                if keyword and keyword.lower() not in text.lower():
                    continue
                print(text)
                matched += 1

        print(f"\n---")
        if keyword:
            print(f"Matched {matched} line(s) containing '{keyword}'.")
        else:
            print(f"Read {matched} line(s) from log file.")

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {file_path}")
    except PermissionError:
        print(f"[ERROR] Permission denied when reading: {file_path}")
    except Exception as e:
        print(f"[ERROR] Unexpected error while reading log: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python log_parser.py /path/to/logfile.log [keyword]")
        sys.exit(1)

    path = sys.argv[1]
    keyword = sys.argv[2] if len(sys.argv) >= 3 else None

    read_log(path, keyword=keyword)
