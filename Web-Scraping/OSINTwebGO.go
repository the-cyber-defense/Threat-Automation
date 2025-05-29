// OSINT Web Scraper in Go
// Description: OSINT tool that recursively scrapes target websites to collect email addresses and social media profiles (LinkedIn, GitHub). Includes CLI flags, JSON reporting, and subpage crawling.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type OSINTResult struct {
	Emails     []string `json:"emails"`
	LinkedIn   []string `json:"linkedin"`
	GitHub     []string `json:"github"`
	VisitedURLs []string `json:"visited_urls"`
}

var visited = make(map[string]bool)

func fetchHTML(targetURL string) (*goquery.Document, string) {
	resp, err := http.Get(targetURL)
	if err != nil {
		log.Printf("[!] Failed to GET %s: %v", targetURL, err)
		return nil, ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[!] Failed to read response body: %v", err)
		return nil, ""
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		log.Printf("[!] Failed to parse HTML: %v", err)
		return nil, ""
	}
	return doc, string(body)
}

func extractLinks(doc *goquery.Document) []string {
	var links []string
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && strings.HasPrefix(href, "http") {
			links = append(links, href)
		}
	})
	return links
}

func extractEmails(body string) []string {
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}`)
	return emailRegex.FindAllString(body, -1)
}

func crawl(urlStr string, depth int, maxDepth int, result *OSINTResult) {
	if visited[urlStr] || depth > maxDepth {
		return
	}
	visited[urlStr] = true
	fmt.Printf("[*] Crawling: %s\n", urlStr)
	result.VisitedURLs = append(result.VisitedURLs, urlStr)

	doc, body := fetchHTML(urlStr)
	if doc == nil {
		return
	}

	// Extract social links
	links := extractLinks(doc)
	for _, link := range links {
		if strings.Contains(link, "linkedin.com") {
			result.LinkedIn = append(result.LinkedIn, link)
		} else if strings.Contains(link, "github.com") {
			result.GitHub = append(result.GitHub, link)
		}
	}

	// Extract emails
	emails := extractEmails(body)
	result.Emails = append(result.Emails, emails...)

	// Recurse into links on the same domain
	base, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	for _, link := range links {
		parsed, err := url.Parse(link)
		if err == nil && parsed.Hostname() == base.Hostname() {
			crawl(link, depth+1, maxDepth, result)
		}
	}
}

func main() {
	target := flag.String("url", "", "Target URL to scrape")
	depth := flag.Int("depth", 1, "Recursion depth for crawling")
	output := flag.String("output", "osint_result.json", "Output file for JSON report")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: go run main.go -url https://example.com [-depth 2] [-output result.json]")
		os.Exit(1)
	}

	fmt.Println("[*] Starting OSINT scrape on:", *target)
	start := time.Now()
	result := &OSINTResult{}

	crawl(*target, 0, *depth, result)

	// Deduplicate results
	result.Emails = unique(result.Emails)
	result.LinkedIn = unique(result.LinkedIn)
	result.GitHub = unique(result.GitHub)

	// Write to file
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("[!] Failed to marshal JSON: %v", err)
	}
	ioutil.WriteFile(*output, jsonData, 0644)
	fmt.Printf("\n[✓] OSINT scan complete in %v\n[*] Report saved to %s\n", time.Since(start), *output)
}

func unique(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, val := range input {
		if !seen[val] {
			seen[val] = true
			result = append(result, val)
		}
	}
	return result
}
