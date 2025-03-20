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

type CVE struct {
	ID          string
	Type        string
	Description string
	MaxCVSS     string
	EPSSScore   string
	Published   string
	Updated     string
}

const BaseURL = "https://www.cvedetails.com"

var monthMapping = map[string]string{
	"January": "01", "February": "02", "March": "03", "April": "04", "May": "05", "June": "06",
	"July": "07", "August": "08", "September": "09", "October": "10", "November": "11", "December": "12",
}

var years = []string{"2015", "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025"}
var months = []string{
	"January", "February", "March", "April", "May", "June",
	"July", "August", "September", "October", "November", "December",
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
}

var proxyList = []string{
	"http://proxy1:port",
	"http://proxy2:port",
	"http://proxy3:port",
}

const (
	maxRetries       = 3
	concurrencyLimit = 2
	logFile          = "scrape.log"
)

// Initialize logger
func init() {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(file)
}

// Log fetched URLs to the log file
func logFetchedURL(url string) {
	log.Printf("Fetched URL: %s\n", url)
}

// Random sleep between requests to avoid getting blocked
func randomSleep() {
	delay := time.Duration(rand.Intn(3000)+2000) * time.Millisecond // 2-5 seconds
	time.Sleep(delay)
}

// Get CVE type from details page
func getCVEType(url string) string {
	c := colly.NewCollector()

	// Set random User-Agent
	c.UserAgent = userAgents[rand.Intn(len(userAgents))]

	// Set Proxy (if available)
	if len(proxyList) > 0 {
		c.SetProxy(proxyList[rand.Intn(len(proxyList))])
	}

	var cveType string = "N/A"

	c.OnHTML("#cve_catslabelsnotes_div span.ssc-vuln-cat", func(e *colly.HTMLElement) {
		cveType = strings.TrimSpace(e.Text)
	})

	for i := 0; i < maxRetries; i++ {
		err := c.Visit(url)
		if err == nil {
			return cveType
		}
		log.Printf("Retrying CVE type fetch: %d/%d after error: %v", i+1, maxRetries, err)
		time.Sleep(5 * time.Second) // Backoff before retry
	}

	return cveType
}

// Scrape single page
func scrapePage(year, monthText, monthNum string, page int) ([]CVE, error) {
	url := fmt.Sprintf("%s/vulnerability-list/year-%s/month-%s/%s.html?page=%d&order=1", BaseURL, year, monthNum, monthText, page)
	fmt.Println("Fetching:", url)

	// Log the fetched URL
	logFetchedURL(url)

	randomSleep() // Add human-like delay

	c := colly.NewCollector()

	// Set random User-Agent
	c.UserAgent = userAgents[rand.Intn(len(userAgents))]

	// Set Proxy (if available)
	if len(proxyList) > 0 {
		c.SetProxy(proxyList[rand.Intn(len(proxyList))])
	}

	var cves []CVE

	c.OnHTML("div[data-tsvfield='cveinfo']", func(e *colly.HTMLElement) {
		cveID := e.ChildText("h3[data-tsvfield='cveId']")
		cveLink := BaseURL + e.ChildAttr("a", "href")
		description := e.ChildText("div[data-tsvfield='summary']")
		maxCVSS := e.ChildText("div[data-tsvfield='maxCvssBaseScore']")
		epssScore := e.ChildText("div[data-tsvfield='epssScore']")
		published := e.ChildText("div[data-tsvfield='publishDate']")
		updated := e.ChildText("div[data-tsvfield='updateDate']")

		// Get CVE type from details page
		cveType := getCVEType(cveLink)

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

	for i := 0; i < maxRetries; i++ {
		err := c.Visit(url)
		if err == nil {
			break
		}
		log.Printf("Retry %d/%d for %s: %v", i+1, maxRetries, url, err)
		time.Sleep(5 * time.Second) // Backoff
	}

	return cves, nil
}

// Save data to CSV
func saveToCSV(year, month string, records []CVE) {
	if len(records) == 0 {
		return
	}

	outputDir := filepath.Join("storage", year)
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		log.Printf("Error creating output directory: %v", err)
		return
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("CVE_%s_%s.csv", year, month))
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Error creating CSV file: %v", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"CVE ID", "CVE Type", "Description", "Max CVSS", "EPSS Score", "Published", "Updated"})

	for _, record := range records {
		writer.Write([]string{record.ID, record.Type, record.Description, record.MaxCVSS, record.EPSSScore, record.Published, record.Updated})
	}

	fmt.Println("✅ Saved to:", filename)
	log.Printf("✅ Saved to: %s", filename)
}

// Worker for concurrency
func worker(year, month string, semaphore chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	monthNum := monthMapping[month]
	page := 1
	var allRecords []CVE

	for {
		semaphore <- struct{}{}

		records, err := scrapePage(year, month, monthNum, page)
		if err != nil || len(records) == 0 {
			<-semaphore
			break
		}

		allRecords = append(allRecords, records...)
		page++
		<-semaphore
	}

	saveToCSV(year, month, allRecords)
}

func main() {
	startTime := time.Now()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrencyLimit)

	for _, year := range years {
		for _, month := range months {
			wg.Add(1)
			go worker(year, month, semaphore, &wg)
		}
	}

	wg.Wait()
	fmt.Println("✅ Completed all downloads in:", time.Since(startTime))
}
