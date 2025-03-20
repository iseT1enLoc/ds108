package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly"
)

// CVE struct to hold vulnerability data
type CVE struct {
	ID          string
	Type        string
	Description string
	MaxCVSS     string
	EPSSScore   string
	Published   string
	Updated     string
}

// Constants
const BaseURL = "https://www.cvedetails.com"

// Mapping month names to numbers
var monthMapping = map[string]string{
	"January": "01", "February": "02", "March": "03", "April": "04", "May": "05", "June": "06",
	"July": "07", "August": "08", "September": "09", "October": "10", "November": "11", "December": "12",
}

// Years and months to scrape
var years = []string{"2015", "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025"}
var months = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}

// Function to get CVE type from its details page
func getCVEType(url string) string {
	c := colly.NewCollector()
	var cveType string = "N/A"

	c.OnHTML("#cve_catslabelsnotes_div span.ssc-vuln-cat", func(e *colly.HTMLElement) {
		cveType = strings.TrimSpace(e.Text)
	})

	err := c.Visit(url)
	if err != nil {
		log.Println("Error fetching CVE type:", err)
	}
	return cveType
}

// Function to scrape CVEs from a single page
func scrapePage(year, monthText, monthNum string, page int, resultsChan chan<- []CVE) {
	url := fmt.Sprintf("%s/vulnerability-list/year-%s/month-%s/%s.html?page=%d&order=1", BaseURL, year, monthNum, monthText, page)
	fmt.Println("Fetching:", url)

	c := colly.NewCollector()

	var cves []CVE

	c.OnHTML("div[data-tsvfield='cveinfo']", func(e *colly.HTMLElement) {
		cveID := e.ChildText("h3[data-tsvfield='cveId']")
		cveLink := BaseURL + e.ChildAttr("a", "href")
		description := e.ChildText("div[data-tsvfield='summary']")
		maxCVSS := e.ChildText("div[data-tsvfield='maxCvssBaseScore']")
		epssScore := e.ChildText("div[data-tsvfield='epssScore']")
		published := e.ChildText("div[data-tsvfield='publishDate']")
		updated := e.ChildText("div[data-tsvfield='updateDate']")

		cveType := getCVEType(cveLink) // Fetch CVE type separately

		cves = append(cves, CVE{
			ID:          cveID,
			Type:        cveType,
			Description: description,
			MaxCVSS:     maxCVSS,
			EPSSScore:   epssScore,
			Published:   published,
			Updated:     updated,
		})
	})

	err := c.Visit(url)
	if err != nil {
		log.Println("Error fetching page:", err)
	}

	// Send results to channel
	resultsChan <- cves
}

// Function to save CVEs to CSV
func saveToCSV(year, month string, records []CVE) {
	if len(records) == 0 {
		return
	}

	outputDir := "storage"
	os.MkdirAll(outputDir, os.ModePerm)
	filename := filepath.Join(outputDir, fmt.Sprintf("CVE_%s_%s.csv", year, month))

	file, err := os.Create(filename)
	if err != nil {
		log.Println("Error creating CSV file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"CVE ID", "CVE Type", "Description", "Max CVSS", "EPSS Score", "Published", "Updated"})

	// Write rows
	for _, record := range records {
		writer.Write([]string{record.ID, record.Type, record.Description, record.MaxCVSS, record.EPSSScore, record.Published, record.Updated})
	}

	fmt.Println("✅ Exported:", filename)
}

// Function to fetch all pages for a given month-year
func fetchAndSaveCVE(wg *sync.WaitGroup, year, month string) {
	defer wg.Done()

	monthNum := monthMapping[month]
	page := 1
	resultsChan := make(chan []CVE, 10)
	var allRecords []CVE

	for {
		go scrapePage(year, month, monthNum, page, resultsChan)

		// Simulate random delay to avoid getting blocked
		time.Sleep(time.Duration(rand.Intn(3)+2) * time.Second)

		records := <-resultsChan
		if len(records) == 0 {
			break
		}

		allRecords = append(allRecords, records...)
		page++
	}

	saveToCSV(year, month, allRecords)
}

func main() {
	startTime := time.Now()

	var wg sync.WaitGroup

	for _, year := range years {
		for _, month := range months {
			wg.Add(1)
			go fetchAndSaveCVE(&wg, year, month)
		}
	}

	wg.Wait()
	fmt.Println("⏳ Total Time Needed:", time.Since(startTime))
}
