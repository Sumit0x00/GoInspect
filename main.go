package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/joho/godotenv"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type cve struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

var apiKey string

func main() {
	// Print the banner
	printBanner()

	url := flag.String("u", "", "URL to analyze")
	apiFlag := flag.String("a", "", "API key for the NVD service")

	flag.Parse()

	if *url == "" {
		log.Fatal("URL is required. Use -u flag to specify the URL.")
	}

	SetApi(apiFlag)

	resp, err := http.DefaultClient.Get(*url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatal(err)
	}

	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)

	// Color setup
	titleColor := color.New(color.FgGreen).Add(color.Bold).PrintlnFunc()
	highlightColor := color.New(color.FgYellow).SprintFunc()
	errorColor := color.New(color.FgRed).SprintFunc()

	titleColor("Technologies detected:")
	for tech := range fingerprints {
		fmt.Printf("- %s\n", highlightColor(tech))
	}

	titleColor("\nChecking for CVEs:")
	for tech := range fingerprints {
		fmt.Printf("- %s\n", highlightColor(tech))
		CVE(tech, highlightColor, errorColor)
	}
}

func SetApi(apiFlag *string) {
	err := godotenv.Load("NVDapi.env")
	if err != nil {
		log.Println("Error loading .env file; trying flag input or environment variables.")
	}

	apiKey = os.Getenv("NVD_API_KEY")
	if *apiFlag != "" {
		apiKey = *apiFlag
	}

	if apiKey == "" {
		log.Fatal("NVD_API_KEY is not set. Use the -a flag to provide an API key.")
	}

	log.Printf("Using API key: %s", apiKey)
}

func CVE(technology string, highlightColor, errorColor func(a ...interface{}) string) {
	BaseUrl := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s", technology)

	req, err := http.NewRequest("GET", BaseUrl, nil)
	if err != nil {
		fmt.Println(errorColor("Error while creating request:", err))
		return
	}

	req.Header.Set("api_key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(errorColor("Error while getting response:", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Println(errorColor("Non-200 response:", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(errorColor("Error while reading response:", err))
		return
	}

	var nvdResponse cve

	err = json.Unmarshal(body, &nvdResponse)
	if err != nil {
		fmt.Println(errorColor("Error while parsing CVE response:", err))
		return
	}

	if len(nvdResponse.Vulnerabilities) == 0 {
		fmt.Printf("No CVE found for %s\n", highlightColor(technology))
	} else {
		fmt.Printf("CVEs found for %s:\n", highlightColor(technology))
		for _, vuln := range nvdResponse.Vulnerabilities {
			fmt.Printf("CVE ID: %s\n", highlightColor(vuln.CVE.ID))
			for _, desc := range vuln.CVE.Descriptions {
				if desc.Lang == "en" {
					fmt.Printf("Description: %s\n", highlightColor(desc.Value))
				}
			}
		}
	}
}

func printBanner() {
	bannerColor := color.New(color.FgBlue).Add(color.Bold).PrintlnFunc()
	devColor := color.New(color.FgCyan).PrintlnFunc()

	bannerColor(`
 ____      ___                           _
 / ___| ___|_ _|_ __  ___ _ __   ___  ___| |_
| |  _ / _ \| || '_ \/ __| '_ \ / _ \/ __| __|
| |_| | (_) | || | | \__ \ |_) |  __/ (__| |_
 \____|\___/___|_| |_|___/ .__/ \___|\___|\__|
                         |_|
`)
	devColor("Developed by: Sumit0x00")
}
