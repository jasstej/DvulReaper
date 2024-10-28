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

def extract_wayback_urls(domain_folder):
    """Extract URLs using waybackurls"""
    print("[*] Extracting URLs using waybackurls...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'all_endpoints.txt')
    command = f"cat {input_path} | waybackurls | tee -a {output_path}"
    run_command(command)
    print(f"[+] All endpoints saved to {output_path}")

def filter_parameterized_urls(domain_folder):
    """Filter parameterized URLs from wayback results"""
    print("[*] Filtering parameterized URLs...")
    input_path = os.path.join(domain_folder, 'all_endpoints.txt')
    output_path = os.path.join(domain_folder, 'param.txt')

    with open(input_path, 'r') as f:
        lines = f.readlines()

    parameterized_urls = [line for line in lines if '?' in line]

    with open(output_path, 'w') as f:
        f.writelines(parameterized_urls)

    print(f"[+] Parameterized URLs saved to {output_path}")

def run_google_dorking(domain, domain_folder):
    """Use Google Dorking to find potential secret files"""
    print("[*] Running Google Dorking for secret files...")
    dorks = [
        f"site:{domain} ext:config",
        f"site:{domain} ext:txt",
        f"site:{domain} ext:env",
        f"site:{domain} ext:log",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login"
    ]

    output_path = os.path.join(domain_folder, 'dork_results.txt')

    with open(output_path, 'w') as f:
        for dork in dorks:
            command = f"googlesearch {dork}"
            result = run_command(command)
            if result:
                f.write(f"Dork: {dork}\n{result}\n\n")

    print(f"[+] Google Dorking results saved to {output_path}")

def run_nmap(domain_folder):
    """Run nmap on alive domains"""
    print("[*] Running Nmap scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nmap_results.txt')
    command = f"nmap -iL {input_path} -oN {output_path}"
    run_command(command)
    print(f"[+] Nmap results saved to {output_path}")

def run_sqlmap(domain_folder):
    """Run sqlmap on parameterized URLs"""
    print("[*] Running SQLMap on parameterized URLs...")
    input_path = os.path.join(domain_folder, 'param.txt')
    command = f"sqlmap -m {input_path} --batch --level=2 --risk=3 -o"
    run_command(command)
    print("[+] SQLMap completed. Check the output folder.")

def run_nikto(domain_folder):
    """Run Nikto on alive domains"""
    print("[*] Running Nikto scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nikto_results.txt')
    command = f"nikto -h {input_path} -o {output_path}"
    run_command(command)
    print(f"[+] Nikto results saved to {output_path}")

def run_xss_scan(domain_folder):
    """Run dalfox for XSS testing"""
    print("[*] Running dalfox for XSS testing...")
    input_path = os.path.join(domain_folder, 'param.txt')
    output_path = os.path.join(domain_folder, 'xss_results.txt')
    command = f"cat {input_path} | dalfox pipe -o {output_path}"
    run_command(command)
    print(f"[+] XSS scan results saved to {output_path}")

def run_nuclei_scan(scan_type, template, domain_folder):
    """Run nuclei for a specific scan"""
    print(f"[*] Running Nuclei for {scan_type} scanning...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, f'{scan_type}_results.txt')
    command = f"nuclei -l {input_path} -t {template} -o {output_path}"
    run_command(command)
    print(f"[+] {scan_type} scan results saved to {output_path}")

def main():
    domain = input("Enter the domain (e.g., apple.com): ").strip()
    domain_folder = create_output_directories(domain)

    # Step 1: Gather subdomains
    gather_subdomains(domain, domain_folder)

    # Step 2: Filter alive domains using httpx
    filter_alive_domains(domain_folder)

    # Step 3: Extract wayback URLs and filter parameterized URLs
    extract_wayback_urls(domain_folder)
    filter_parameterized_urls(domain_folder)

    # Step 4: Run Google Dorking for secret files
    run_google_dorking(domain, domain_folder)

    # Step 5: Run vulnerability scans
    run_nmap(domain_folder)
    run_sqlmap(domain_folder)
    run_nikto(domain_folder)
    run_xss_scan(domain_folder)

    # Step 6: Run nuclei scans for various vulnerabilities
    run_nuclei_scan("ssrf", "nuclei-templates/ssrf", domain_folder)
    run_nuclei_scan("csrf", "nuclei-templates/csrf", domain_folder)
    run_nuclei_scan("rce", "nuclei-templates/rce", domain_folder)
    run_nuclei_scan("lfi", "nuclei-templates/lfi", domain_folder)
    run_nuclei_scan("open_redirect", "nuclei-templates/open-redirect", domain_folder)
    run_nuclei_scan("ssti", "nuclei-templates/ssti", domain_folder)

    print("[*] All tasks completed successfully! Check the output directory for detailed results.")

if __name__ == "__main__":
    main()
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

def extract_wayback_urls(domain_folder):
    """Extract URLs using waybackurls"""
    print("[*] Extracting URLs using waybackurls...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'all_endpoints.txt')
    command = f"cat {input_path} | waybackurls | tee -a {output_path}"
    run_command(command)
    print(f"[+] All endpoints saved to {output_path}")

def filter_parameterized_urls(domain_folder):
    """Filter parameterized URLs from wayback results"""
    print("[*] Filtering parameterized URLs...")
    input_path = os.path.join(domain_folder, 'all_endpoints.txt')
    output_path = os.path.join(domain_folder, 'param.txt')

    with open(input_path, 'r') as f:
        lines = f.readlines()

    parameterized_urls = [line for line in lines if '?' in line]

    with open(output_path, 'w') as f:
        f.writelines(parameterized_urls)

    print(f"[+] Parameterized URLs saved to {output_path}")

def run_google_dorking(domain, domain_folder):
    """Use Google Dorking to find potential secret files"""
    print("[*] Running Google Dorking for secret files...")
    dorks = [
        f"site:{domain} ext:config",
        f"site:{domain} ext:txt",
        f"site:{domain} ext:env",
        f"site:{domain} ext:log",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login"
    ]

    output_path = os.path.join(domain_folder, 'dork_results.txt')

    with open(output_path, 'w') as f:
        for dork in dorks:
            command = f"googlesearch {dork}"
            result = run_command(command)
            if result:
                f.write(f"Dork: {dork}\n{result}\n\n")

    print(f"[+] Google Dorking results saved to {output_path}")

def run_nmap(domain_folder):
    """Run nmap on alive domains"""
    print("[*] Running Nmap scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nmap_results.txt')
    command = f"nmap -iL {input_path} -oN {output_path}"
    run_command(command)
    print(f"[+] Nmap results saved to {output_path}")

def run_sqlmap(domain_folder):
    """Run sqlmap on parameterized URLs"""
    print("[*] Running SQLMap on parameterized URLs...")
    input_path = os.path.join(domain_folder, 'param.txt')
    command = f"sqlmap -m {input_path} --batch --level=2 --risk=3 -o"
    run_command(command)
    print("[+] SQLMap completed. Check the output folder.")

def run_nikto(domain_folder):
    """Run Nikto on alive domains"""
    print("[*] Running Nikto scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nikto_results.txt')
    command = f"nikto -h {input_path} -o {output_path}"
    run_command(command)
    print(f"[+] Nikto results saved to {output_path}")

def run_xss_scan(domain_folder):
    """Run dalfox for XSS testing"""
    print("[*] Running dalfox for XSS testing...")
    input_path = os.path.join(domain_folder, 'param.txt')
    output_path = os.path.join(domain_folder, 'xss_results.txt')
    command = f"cat {input_path} | dalfox pipe -o {output_path}"
    run_command(command)
    print(f"[+] XSS scan results saved to {output_path}")

def run_nuclei_scan(scan_type, template, domain_folder):
    """Run nuclei for a specific scan"""
    print(f"[*] Running Nuclei for {scan_type} scanning...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, f'{scan_type}_results.txt')
    command = f"nuclei -l {input_path} -t {template} -o {output_path}"
    run_command(command)
    print(f"[+] {scan_type} scan results saved to {output_path}")

def main():
    domain = input("Enter the domain (e.g., apple.com): ").strip()
    domain_folder = create_output_directories(domain)

    # Step 1: Gather subdomains
    gather_subdomains(domain, domain_folder)

    # Step 2: Filter alive domains using httpx
    filter_alive_domains(domain_folder)

    # Step 3: Extract wayback URLs and filter parameterized URLs
    extract_wayback_urls(domain_folder)
    filter_parameterized_urls(domain_folder)

    # Step 4: Run Google Dorking for secret files
    run_google_dorking(domain, domain_folder)

    # Step 5: Run vulnerability scans
    run_nmap(domain_folder)
    run_sqlmap(domain_folder)
    run_nikto(domain_folder)
    run_xss_scan(domain_folder)

    # Step 6: Run nuclei scans for various vulnerabilities
    run_nuclei_scan("ssrf", "nuclei-templates/ssrf", domain_folder)
    run_nuclei_scan("csrf", "nuclei-templates/csrf", domain_folder)
    run_nuclei_scan("rce", "nuclei-templates/rce", domain_folder)
    run_nuclei_scan("lfi", "nuclei-templates/lfi", domain_folder)
    run_nuclei_scan("open_redirect", "nuclei-templates/open-redirect", domain_folder)
    run_nuclei_scan("ssti", "nuclei-templates/ssti", domain_folder)

    print("[*] All tasks completed successfully! Check the output directory for detailed results.")

if __name__ == "__main__":
    main()
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

def extract_wayback_urls(domain_folder):
    """Extract URLs using waybackurls"""
    print("[*] Extracting URLs using waybackurls...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'all_endpoints.txt')
    command = f"cat {input_path} | waybackurls | tee -a {output_path}"
    run_command(command)
    print(f"[+] All endpoints saved to {output_path}")

def filter_parameterized_urls(domain_folder):
    """Filter parameterized URLs from wayback results"""
    print("[*] Filtering parameterized URLs...")
    input_path = os.path.join(domain_folder, 'all_endpoints.txt')
    output_path = os.path.join(domain_folder, 'param.txt')

    with open(input_path, 'r') as f:
        lines = f.readlines()

    parameterized_urls = [line for line in lines if '?' in line]

    with open(output_path, 'w') as f:
        f.writelines(parameterized_urls)

    print(f"[+] Parameterized URLs saved to {output_path}")

def run_google_dorking(domain, domain_folder):
    """Use Google Dorking to find potential secret files"""
    print("[*] Running Google Dorking for secret files...")
    dorks = [
        f"site:{domain} ext:config",
        f"site:{domain} ext:txt",
        f"site:{domain} ext:env",
        f"site:{domain} ext:log",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login"
    ]

    output_path = os.path.join(domain_folder, 'dork_results.txt')

    with open(output_path, 'w') as f:
        for dork in dorks:
            command = f"googlesearch {dork}"
            result = run_command(command)
            if result:
                f.write(f"Dork: {dork}\n{result}\n\n")

    print(f"[+] Google Dorking results saved to {output_path}")

def run_nmap(domain_folder):
    """Run nmap on alive domains"""
    print("[*] Running Nmap scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nmap_results.txt')
    command = f"nmap -iL {input_path} -oN {output_path}"
    run_command(command)
    print(f"[+] Nmap results saved to {output_path}")

def run_sqlmap(domain_folder):
    """Run sqlmap on parameterized URLs"""
    print("[*] Running SQLMap on parameterized URLs...")
    input_path = os.path.join(domain_folder, 'param.txt')
    command = f"sqlmap -m {input_path} --batch --level=2 --risk=3 -o"
    run_command(command)
    print("[+] SQLMap completed. Check the output folder.")

def run_nikto(domain_folder):
    """Run Nikto on alive domains"""
    print("[*] Running Nikto scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nikto_results.txt')
    command = f"nikto -h {input_path} -o {output_path}"
    run_command(command)
    print(f"[+] Nikto results saved to {output_path}")

def run_xss_scan(domain_folder):
    """Run dalfox for XSS testing"""
    print("[*] Running dalfox for XSS testing...")
    input_path = os.path.join(domain_folder, 'param.txt')
    output_path = os.path.join(domain_folder, 'xss_results.txt')
    command = f"cat {input_path} | dalfox pipe -o {output_path}"
    run_command(command)
    print(f"[+] XSS scan results saved to {output_path}")

def run_nuclei_scan(scan_type, template, domain_folder):
    """Run nuclei for a specific scan"""
    print(f"[*] Running Nuclei for {scan_type} scanning...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, f'{scan_type}_results.txt')
    command = f"nuclei -l {input_path} -t {template} -o {output_path}"
    run_command(command)
    print(f"[+] {scan_type} scan results saved to {output_path}")

def main():
    domain = input("Enter the domain (e.g., apple.com): ").strip()
    domain_folder = create_output_directories(domain)

    # Step 1: Gather subdomains
    gather_subdomains(domain, domain_folder)

    # Step 2: Filter alive domains using httpx
    filter_alive_domains(domain_folder)

    # Step 3: Extract wayback URLs and filter parameterized URLs
    extract_wayback_urls(domain_folder)
    filter_parameterized_urls(domain_folder)

    # Step 4: Run Google Dorking for secret files
    run_google_dorking(domain, domain_folder)

    # Step 5: Run vulnerability scans
    run_nmap(domain_folder)
    run_sqlmap(domain_folder)
    run_nikto(domain_folder)
    run_xss_scan(domain_folder)

    # Step 6: Run nuclei scans for various vulnerabilities
    run_nuclei_scan("ssrf", "nuclei-templates/ssrf", domain_folder)
    run_nuclei_scan("csrf", "nuclei-templates/csrf", domain_folder)
    run_nuclei_scan("rce", "nuclei-templates/rce", domain_folder)
    run_nuclei_scan("lfi", "nuclei-templates/lfi", domain_folder)
    run_nuclei_scan("open_redirect", "nuclei-templates/open-redirect", domain_folder)
    run_nuclei_scan("ssti", "nuclei-templates/ssti", domain_folder)

    print("[*] All tasks completed successfully! Check the output directory for detailed results.")

if __name__ == "__main__":
    main()
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

def extract_wayback_urls(domain_folder):
    """Extract URLs using waybackurls"""
    print("[*] Extracting URLs using waybackurls...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'all_endpoints.txt')
    command = f"cat {input_path} | waybackurls | tee -a {output_path}"
    run_command(command)
    print(f"[+] All endpoints saved to {output_path}")

def filter_parameterized_urls(domain_folder):
    """Filter parameterized URLs from wayback results"""
    print("[*] Filtering parameterized URLs...")
    input_path = os.path.join(domain_folder, 'all_endpoints.txt')
    output_path = os.path.join(domain_folder, 'param.txt')

    with open(input_path, 'r') as f:
        lines = f.readlines()

    parameterized_urls = [line for line in lines if '?' in line]

    with open(output_path, 'w') as f:
        f.writelines(parameterized_urls)

    print(f"[+] Parameterized URLs saved to {output_path}")

def run_google_dorking(domain, domain_folder):
    """Use Google Dorking to find potential secret files"""
    print("[*] Running Google Dorking for secret files...")
    dorks = [
        f"site:{domain} ext:config",
        f"site:{domain} ext:txt",
        f"site:{domain} ext:env",
        f"site:{domain} ext:log",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login"
    ]

    output_path = os.path.join(domain_folder, 'dork_results.txt')

    with open(output_path, 'w') as f:
        for dork in dorks:
            command = f"googlesearch {dork}"
            result = run_command(command)
            if result:
                f.write(f"Dork: {dork}\n{result}\n\n")

    print(f"[+] Google Dorking results saved to {output_path}")

def run_nmap(domain_folder):
    """Run nmap on alive domains"""
    print("[*] Running Nmap scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nmap_results.txt')
    command = f"nmap -iL {input_path} -oN {output_path}"
    run_command(command)
    print(f"[+] Nmap results saved to {output_path}")

def run_sqlmap(domain_folder):
    """Run sqlmap on parameterized URLs"""
    print("[*] Running SQLMap on parameterized URLs...")
    input_path = os.path.join(domain_folder, 'param.txt')
    command = f"sqlmap -m {input_path} --batch --level=2 --risk=3 -o"
    run_command(command)
    print("[+] SQLMap completed. Check the output folder.")

def run_nikto(domain_folder):
    """Run Nikto on alive domains"""
    print("[*] Running Nikto scan...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, 'nikto_results.txt')
    command = f"nikto -h {input_path} -o {output_path}"
    run_command(command)
    print(f"[+] Nikto results saved to {output_path}")

def run_xss_scan(domain_folder):
    """Run dalfox for XSS testing"""
    print("[*] Running dalfox for XSS testing...")
    input_path = os.path.join(domain_folder, 'param.txt')
    output_path = os.path.join(domain_folder, 'xss_results.txt')
    command = f"cat {input_path} | dalfox pipe -o {output_path}"
    run_command(command)
    print(f"[+] XSS scan results saved to {output_path}")

def run_nuclei_scan(scan_type, template, domain_folder):
    """Run nuclei for a specific scan"""
    print(f"[*] Running Nuclei for {scan_type} scanning...")
    input_path = os.path.join(domain_folder, 'alive.txt')
    output_path = os.path.join(domain_folder, f'{scan_type}_results.txt')
    command = f"nuclei -l {input_path} -t {template} -o {output_path}"
    run_command(command)
    print(f"[+] {scan_type} scan results saved to {output_path}")

def main():
    domain = input("Enter the domain (e.g., apple.com): ").strip()
    domain_folder = create_output_directories(domain)

    # Step 1: Gather subdomains
    gather_subdomains(domain, domain_folder)

    # Step 2: Filter alive domains using httpx
    filter_alive_domains(domain_folder)

    # Step 3: Extract wayback URLs and filter parameterized URLs
    extract_wayback_urls(domain_folder)
    filter_parameterized_urls(domain_folder)

    # Step 4: Run Google Dorking for secret files
    run_google_dorking(domain, domain_folder)

    # Step 5: Run vulnerability scans
    run_nmap(domain_folder)
    run_sqlmap(domain_folder)
    run_nikto(domain_folder)
    run_xss_scan(domain_folder)

    # Step 6: Run nuclei scans for various vulnerabilities
    run_nuclei_scan("ssrf", "nuclei-templates/ssrf", domain_folder)
    run_nuclei_scan("csrf", "nuclei-templates/csrf", domain_folder)
    run_nuclei_scan("rce", "nuclei-templates/rce", domain_folder)
    run_nuclei_scan("lfi", "nuclei-templates/lfi", domain_folder)
    run_nuclei_scan("open_redirect", "nuclei-templates/open-redirect", domain_folder)
    run_nuclei_scan("ssti", "nuclei-templates/ssti", domain_folder)

    print("[*] All tasks completed successfully! Check the output directory for detailed results.")

if __name__ == "__main__":
    main()
