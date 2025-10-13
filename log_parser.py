def read_log(file_path):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                print(line.strip())
    except FileNotFoundError:
        print("Log file not found. Please check the path.")

if __name__ == "__main__":
    path = input("Enter log file path: ")
    read_log(path)
