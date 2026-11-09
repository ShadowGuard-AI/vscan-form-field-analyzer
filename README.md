# vscan-form-field-analyzer

![Logo](logo.png)

![Banner](banner.png)

Identifies and analyzes HTML form fields for potential vulnerabilities such as missing input validation or auto-completion enabled on sensitive fields. It is part of a lightweight web application vulnerability scanning toolkit focused on common misconfigurations.

The analyzer walks input, select, and textarea fields. A missing autocomplete attribute is reported as "not set", not as "off". Password fields are flagged when autocomplete is "on" or not set: the correct tokens new-password and current-password are not flagged. Card fields are detected by their cc-number or cc-csc autocomplete token even when typed as plain text. A prefilled value that fails the field format is flagged as potential missing validation only when the field also carries no validation attributes (pattern, maxlength, min, max, step). A page returned with an HTTP error status is still analyzed, because its body can still hold forms.

## Install
`git clone https://github.com/ShadowGuard-AI/vscan-form-field-analyzer`

Then install the dependencies: `pip install -r requirements.txt` (BeautifulSoup 4 is required and used to parse the page).

## Usage
`python3 main.py <url> [params]`

Example: `python3 main.py http://127.0.0.1:8000/login`

Field records carry the field name, its type, and whether a value was present. Input value attributes are never printed or saved. If a fetched page has no forms, the tool prints that no forms were found to analyze and exits with status 1. A failed fetch (no response received) also exits with status 1.

## Parameters
- `-h`: Show help message and exit
- `-o`, `--output`: Output file to save the results (optional, JSON).
- `-v`, `--verbose`: Enable verbose output for debugging.

## License
MIT. See LICENSE.
