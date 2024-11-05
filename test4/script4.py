import subprocess
import os

def run_command(command):
    """Runs a shell command and returns the output"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"Error running command: {command}")
            print(result.stderr)
    except Exception as e:
        print(f"Exception occurred: {e}")

def create_output_directories(domain):
    """Create the output directory structure"""
    if not os.path.exists('output'):
        os.mkdir('output')
    domain_folder = os.path.join('output', domain)
    if not os.path.exists(domain_folder):
        os.mkdir(domain_folder)
    return domain_folder

def gather_subdomains(domain, domain_folder):
    """Use subfinder to gather subdomains"""
    print("[*] Gathering subdomains...")
    output_path = os.path.join(domain_folder, 'urls.txt')
    command = f"subfinder -d {domain} -all -recursive -o {output_path}"
    run_command(command)
    print(f"[+] Subdomains saved to {output_path}")

def filter_alive_domains(domain_folder):
    """Use httpx to filter alive domains"""
    print("[*] Filtering alive domains...")
    input_path = os.path.join(domain_folder, 'urls.txt')
    output_path = os.path.join(domain_folder, 'alive.txt')
    command = f"httpx -l {input_path} -o {output_path}"
    run_command(command)
    print(f"[+] Alive domains saved to {output_path}")

def extract_urls(domain_folder):
    """Use waybackurls to extract URLs"""
    print("[*] Extracting URLs using waybackurls...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'all_endpoints.txt')
    command = f"waybackurls < {input_path} > {output_path}"
    run_command(command)
    print(f"[+] All endpoints saved to {output_path}")

def filter_parameterized_urls(domain_folder):
    """Filter parameterized URLs"""
    print("[*] Filtering parameterized URLs...")
    input_path = os.path.join(domain_folder, 'all_endpoints.txt')
    output_path = os.path.join(domain_folder, 'parameterized_urls.txt')
    with open(input_path, 'r') as f:
        lines = f.readlines()
    with open(output_path, 'w') as f:
        for line in lines:
            if '?' in line:
                f.write(line)
    print(f"[+] Parameterized URLs saved to {output_path}")

def main():
    domain = input("Enter the domain (e.g., apple.com): ")
    domain_folder = create_output_directories(domain)
    gather_subdomains(domain, domain_folder)
    filter_alive_domains(domain_folder)
    extract_urls(domain_folder)
    filter_parameterized_urls(domain_folder)

if __name__ == "__main__":
    main()