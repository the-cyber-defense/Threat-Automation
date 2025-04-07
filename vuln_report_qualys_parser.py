import csv

def parse_qualys(file_path):
    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(f"Host: {row['IP']} | Vulnerability: {row['QID']} - {row['Title']}")

if __name__ == "__main__":
    parse_qualys('sample_qualys_report.csv')