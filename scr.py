import requests
from bs4 import BeautifulSoup

def scrape_page(target):
    try:
        print(f"Scraping the page at {target}...")
        response = requests.get(target)
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)
        
        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Print the title of the page, if it exists
        title = soup.title.string if soup.title else 'No title found'
        print(f"Title of the page: {title}")
        
        # Find and print the meta description, if it exists
        print("Meta description:")
        meta_description = None
        for meta in soup.find_all('meta'):
            if 'description' in meta.attrs.get('name', '').lower():
                meta_description = meta.attrs.get('content', 'No description content')
                break
        if meta_description:
            print(meta_description)
        else:
            print("No meta description found.")
            
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scraping: {e}")

# Example usage:
# scrape_page('https://example.com')
