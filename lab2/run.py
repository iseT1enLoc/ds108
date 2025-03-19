import requests
from bs4 import BeautifulSoup
import datetime
import os
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Base URL for CVE details
BASE_URL = "https://www.cvedetails.com"

# Headers to mimic a real browser request
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    "Referer": "https://www.google.com/",
    "Accept-Language": "en-US,en;q=0.9",
}

# Mapping month names to numbers
month_mapping = {
    "January": "01", "February": "02", "March": "03", "April": "04", "May": "05", "June": "06",
    "July": "07", "August": "08", "September": "09", "October": "10", "November": "11", "December": "12"
}

# List of years and months to fetch
years = [str(year) for year in range(2015, 2026)]
months = list(month_mapping.keys())

# Function to get CVE type from its details page
def get_cve_type(url):
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            soup = BeautifulSoup(r.content, "html.parser")
            div = soup.find("div", {"id": "cve_catslabelsnotes_div"})
            span = div.find("span", {"class": "ssc-vuln-cat"})
            return span.text.strip() if span else "N/A"
    except Exception as e:
        print(f"Error fetching CVE type from {url}: {e}")
    return "N/A"

# Function to process a single page and extract CVE records
def process_single_page(url, month_text, month_num, year, page_number):
    """
    Fetches a single page of CVE data and extracts relevant information.
    Returns a tuple: (list of CVE records, has_next_page)
    """
    try:
        full_url = f"{BASE_URL}/vulnerability-list/year-{year}/month-{month_num}/{month_text}.html?page={page_number}"
        print(f"Fetching {full_url}")

        r = requests.get(full_url, headers=headers)
        if r.status_code != 200:
            print(f"Failed to fetch {full_url}, status code: {r.status_code}")
            return [], False

        soup = BeautifulSoup(r.content, "html.parser")
        cve_entries = soup.find_all("div", {"data-tsvfield": "cveinfo"})

        # If no CVE entries found, stop
        if not cve_entries:
            print(f"No more records on {month_text} {year}, stopping at page {page_number}")
            return [], False

        cve_data = []
        for entry in cve_entries:
            cve_id = entry.find("h3", {"data-tsvfield": "cveId"}).text.strip()
            cve_link = BASE_URL + entry.find("a")["href"]
            cve_type = get_cve_type(cve_link)
            description = entry.find("div", {"data-tsvfield": "summary"}).text.strip()
            max_cvss = entry.find("div", {"data-tsvfield": "maxCvssBaseScore"}).text.strip()
            epss_score = entry.find("div", {"data-tsvfield": "epssScore"}).text.strip()
            published_date = entry.find("div", {"data-tsvfield": "publishDate"}).text.strip()
            updated_date = entry.find("div", {"data-tsvfield": "updateDate"}).text.strip()

            cve_data.append({
                "CVE ID": cve_id,
                "CVE_type": cve_type,
                "Description": description,
                "Max CVSS": max_cvss,
                "EPSS Score": epss_score,
                "Published": published_date,
                "Updated": updated_date,
            })

        # Check if there is a "Next Page" button
        next_page_link = soup.find("a", string="Next")
        has_next_page = next_page_link is not None

        return cve_data, has_next_page

    except Exception as e:
        print(f"Error processing page {page_number} of {month_text} {year}: {e}")
        return [], False

# Function to fetch all pages for a given month-year and save to CSV
def fetch_and_save_cve(year, month):
    page_number = 1
    records = []
    
    while True:  # Keep fetching until no more pages exist
        single_record, has_next_page = process_single_page(BASE_URL, month, month_mapping[month], year, str(page_number))

        if not single_record:  # If an empty page is encountered, stop fetching
            break

        records.extend(single_record)
        page_number += 1  # Move to the next page

        # Wait 2 seconds between requests to avoid getting blocked
        time.sleep(2)

        # Stop if no more pages exist
        if not has_next_page:
            print(f"Finished fetching {month} {year}, stopping at page {page_number}")
            break

    # Export to CSV if records exist
    if records:
        output_dir = "storage"
        os.makedirs(output_dir, exist_ok=True)
        filename = os.path.join(output_dir, f"CVE_{year}_{month}.csv")

        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)

        print(f"Exported: {filename}")

# Main execution with concurrency
if __name__ == "__main__":
    start_time = datetime.datetime.now()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_and_save_cve, year, month): (year, month) for year in years for month in months}

        for future in as_completed(futures):
            year, month = futures[future]
            try:
                future.result()  # Ensure any exception is raised
            except Exception as e:
                print(f"Error processing {year}-{month}: {e}")

    end_time = datetime.datetime.now()
    print(f"Total Time Needed: {end_time - start_time}")
