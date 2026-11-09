import argparse
import requests
from bs4 import BeautifulSoup
import logging
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-form-field-analyzer: Identifies and analyzes HTML form fields for potential vulnerabilities.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-o", "--output", help="Output file to save the results (optional).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    return parser.parse_args()


def analyze_form_fields(html_content, url):
    """
    Analyzes HTML form fields for potential vulnerabilities.

    Args:
        html_content (str): The HTML content of the page.
        url (str): The URL of the page being analyzed (for context in logs/reports).

    Returns:
        list: A list of dictionaries, where each dictionary represents a form field
              and its potential vulnerabilities.  Returns None if no forms are found.
              A field record carries whether a value was present, never the value itself.
    """

    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')
    results = []

    if not forms:
        logging.warning(f"No forms found on {url}")
        return None

    for form in forms:
        # Inputs, selects, and textareas are all walked, so a form built
        # out of selects or textareas no longer reads as a form holding
        # no fields at all. For a select or textarea the tag name is
        # recorded as the field type.
        fields = form.find_all(['input', 'select', 'textarea'])
        for input_field in fields:
            field_value = input_field.get('value')
            if input_field.name in ('select', 'textarea'):
                field_type = input_field.name
            else:
                # HTML type values are case-insensitive; normalise so an
                # upper case PASSWORD is still treated as a password.
                field_type = (input_field.get('type', 'text') or 'text').lower()
            raw_autocomplete = input_field.get('autocomplete')
            # A missing autocomplete attribute is recorded as "not set",
            # not as "off": browsers apply their default behaviour when
            # the attribute is absent, so recording "off" made the most
            # exposed sensitive fields read as safe.
            autocomplete = raw_autocomplete.strip().lower() if raw_autocomplete else 'not set'
            field_data = {
                'name': input_field.get('name', 'N/A'),
                'type': field_type,
                'autocomplete': autocomplete,
                'required': input_field.has_attr('required'),
                'readonly': input_field.has_attr('readonly'),
                'disabled': input_field.has_attr('disabled'),
                'value_present': input_field.has_attr('value'),
                'placeholder': input_field.get('placeholder', 'N/A'),
                'vulnerabilities': []
            }

            # Check for missing input validation. A prefilled value that
            # fails the field's own format is only flagged when the field
            # also carries no validation attributes (pattern, maxlength,
            # min, max, step) that would catch it, so a field backed by
            # real checks is no longer scored the wrong way round.
            validation_attrs = ('pattern', 'maxlength', 'min', 'max', 'step')
            has_validation = any(input_field.has_attr(attr) for attr in validation_attrs)
            if not has_validation and field_value is not None:
                if field_type == 'email' and not re.match(r"[^@]+@[^@]+\.[^@]+", field_value):
                    field_data['vulnerabilities'].append("Potential missing email validation.")
                elif field_type in ('number', 'tel') and not field_value.isdigit():
                    field_data['vulnerabilities'].append("Potential missing numerical validation.")

            # Check for autocomplete enabled on sensitive fields.
            # credit-card and cvv are autocomplete tokens (cc-number and
            # cc-csc), not input types, so card fields are detected by
            # their autocomplete token even when typed as plain text.
            # For password fields, the correct tokens new-password and
            # current-password are not flagged; a password field is
            # flagged when autocomplete is "on" or not set at all.
            ac_tokens = autocomplete.split()
            if field_type == 'password':
                if autocomplete not in ('off', 'new-password', 'current-password'):
                    field_data['vulnerabilities'].append("Autocomplete is enabled or not set for sensitive field of type 'password'. This is generally discouraged")
            elif 'cc-number' in ac_tokens or 'cc-csc' in ac_tokens or field_type in ('credit-card', 'cvv'):
                if autocomplete != 'off':
                    field_data['vulnerabilities'].append(f"Autocomplete is enabled for sensitive card field '{field_data['name']}'. This is generally discouraged")

            # Check for missing required attribute
            if field_data['type'] not in ('hidden', 'submit', 'button') and not field_data['required']:
               field_data['vulnerabilities'].append("Missing 'required' attribute. Consider adding for important fields")

            if field_data['vulnerabilities']:
                logging.warning(f"Potential vulnerabilities found in field '{field_data['name']}' on {url}")

            results.append(field_data)

    return results


def fetch_html_content(url):
    """
    Fetches the HTML content from the given URL.

    Args:
        url (str): The URL to fetch.

    Returns:
        str: The HTML content, or None on error.
    """
    try:
        response = requests.get(url, timeout=10)
        # An HTTP error status is not a fetch failure: the body of an
        # error page can still hold forms worth analysing, so it is
        # returned whatever the status. None is reserved for a request
        # that produced no response.
        if response.status_code >= 400:
            logging.warning(f"URL {url} returned HTTP {response.status_code}; analysing the response body anyway.")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        return None



def save_results(results, filename):
    """
    Saves the analysis results to a file.

    Args:
        results (list): The analysis results (list of dictionaries).
        filename (str): The name of the file to save to.
    """
    try:
        with open(filename, 'w') as f:
            import json
            json.dump(results, f, indent=4)  # Save as JSON for readability
        logging.info(f"Results saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving results to {filename}: {e}")


def main():
    """
    Main function to orchestrate the vulnerability scanning process.
    """
    args = setup_argparse()

    # Input validation
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Enable debug logging

    html_content = fetch_html_content(args.url)

    if html_content:
        results = analyze_form_fields(html_content, args.url)

        if results is None:
            print("No forms were found to analyze.")
            sys.exit(1)

        if results:
            print("Form field analysis results:")
            for field in results:
                print(f"  Field Name: {field['name']}")
                print(f"    Type: {field['type']}")
                print(f"    Autocomplete: {field['autocomplete']}")
                print(f"    Required: {field['required']}")
                print(f"    Value Present: {field['value_present']}")
                print(f"    Vulnerabilities: {field['vulnerabilities'] or 'None'}")
                print("-" * 20)

            if args.output:
                save_results(results, args.output)
        else:
            print("Forms were found on the page, but they contained no input, select, or textarea fields.")

    else:
        print("Failed to fetch HTML content. Check the URL and your network connection.")
        sys.exit(1)



if __name__ == "__main__":
    main()