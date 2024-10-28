import subprocess
import requests
from bs4 import BeautifulSoup
import os

# Function to run Nmap scan
def run_nmap_scan(target):
    print(f"Running Nmap scan on {target}...")
    nmap_output_file = "nmap_scan.txt"
    # Correcting the nmap command, removing unwanted spaces
    nmap_command = ["nmap", "-sS", "-A", "-T4", target, "-oN", nmap_output_file]
    subprocess.run(nmap_command, check=True)  # Using check=True to raise errors if Nmap fails
    print(f"Nmap scan completed. Results saved in {nmap_output_file}")

# Function to run Nikto scan
def run_nikto_scan(target):
    print(f"Running Nikto scan on {target}...")
    nikto_output_file = "nikto_scan.txt"
    # Ensure Nikto is correctly executed
    nikto_command = ["nikto", "-h", target, "-o", nikto_output_file]
    subprocess.run(nikto_command, check=True)
    print(f"Nikto scan completed. Results saved in {nikto_output_file}")

# Function to run SQLmap for SQL injection check
def run_sqlmap(target):
    print(f"Running SQLmap on {target}...")
    # Correcting the SQLmap command, specifying the target properly and adding verbosity for clarity
    sqlmap_command = ["sqlmap", "-u", target, "--batch", "--risk=3", "--level=5", "--output-dir=./sqlmap_results"]
    subprocess.run(sqlmap_command, check=True)
    print(f"SQLmap scan completed. Results saved in sqlmap_results/")

# Function to fuzz directories using requests library
def fuzz_directories(target):
    print(f"Fuzzing directories on {target}...")
    # Using a well-known wordlist from GitHub for directory fuzzing (common wordlist for fuzzing)
    wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    response = requests.get(wordlist_url)
    wordlist = response.text.splitlines()

    found_directories = []
    for word in wordlist:
        url = f"{target}/{word}"
        res = requests.get(url)
        if res.status_code == 200:
            found_directories.append(url)
            print(f"Found directory: {url}")

    if not found_directories:
        print("No directories found.")
    else:
        print(f"Total directories found: {len(found_directories)}")

# Function to parse a webpage using BeautifulSoup (or alternates like lxml)
def scrape_page(target):
    print(f"Scraping the page at {target}...")
    try:
        response = requests.get(target)
        response.raise_for_status()  # Ensure the request is successful
        soup = BeautifulSoup(response.text, 'lxml')  # Using 'lxml' parser for faster processing

        # Extract and display the page title
        title = soup.title.string if soup.title else 'No title found'
        print(f"Title of the page: {title}")

        # Extract and display the meta description
        meta_description = None
        for meta in soup.find_all('meta'):
            if 'description' in meta.attrs.get('name', '').lower():
                meta_description = meta.attrs.get('content', 'No description content')
                break
        if meta_description:
            print(f"Meta description: {meta_description}")
        else:
            print("No meta description found.")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scraping: {e}")

# Main function to automate the pentesting process
def automated_pentest(target):
    # Step 1: Nmap Scan
    print("..........Running Nmap.........." )
    run_nmap_scan(target)

    # Step 2: Nikto Scan
    print("..........Running Nikto..........")
    run_nikto_scan(target)

    # Step 3: SQL Injection Check with SQLmap
    print("..........Running SQLmap..........")
    run_sqlmap(target)

    # Step 4: Fuzz Directories
    print("..........Fuzzing Directories..........")
    fuzz_directories(target)

    # Step 5: Scrape the website
    print("..........Scraping the Webpage..........")
    scrape_page(target)

if __name__ == "__main__":
    target_website = input("Enter the website URL to test (e.g., http://example.com): ")
    automated_pentest(target_website)
