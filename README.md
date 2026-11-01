# vscan-form-field-analyzer
Identifies and analyzes HTML form fields for potential vulnerabilities such as missing input validation or auto-completion enabled on sensitive fields. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-form-field-analyzer`

## Usage
`./vscan-form-field-analyzer [params]`

Field records carry the field name, its type, and whether a value was present. Input value attributes are never printed or saved. If a fetched page has no forms, the tool prints that no forms were found to analyze and exits with status 1. A failed fetch also exits with status 1.

## Parameters
- `-h`: Show help message and exit
- `-o`: No description provided
- `-v`: Enable verbose output for debugging.

## License
Copyright (c) ShadowStrikeHQ
