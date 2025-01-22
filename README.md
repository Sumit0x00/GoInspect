# GoInspect

GoInspect is a lightweight tool written in Go for detecting technologies used by a website and identifying known CVEs (Common Vulnerabilities and Exposures) based on the detected technologies and their versions.

## Features
- Detects technologies used on a website.
- Checks for CVEs for the detected technologies using the NVD API.
- Provides CVE IDs, descriptions, and severity ratings.

---

## Setup

### Step 1: Clone the Repository
```bash
git clone https://github.com/YourUsername/GoInspect.git
cd GoInspect
```


### Step 2: Set Up the NVD API Key

1. Create a file named NVDapi.env in the project root.
2. Add the following content to the file: 
```bash
NVD_API_KEY=your_nvd_api_key
```
Replace your_nvd_api_key with your actual NVD API key.

If you don’t have an API key, you can register for one on the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).


### Step 3: Install Dependencies
Install the required Go packages listed in the requirements.txt file. Run:
```bash
go mod tidy
```

## Usage

Run the following command:
```bash
go run . -u <url> -a <api_key>
```
Replace <url> with the website URL you want to analyze.
Replace <api_key> with your NVD API key (optional if already set in NVDapi.env).

Example:
```bash
go run . -u https://example.com
```

### Contributing
Feel free to fork this repository, make changes, and submit a pull request.
