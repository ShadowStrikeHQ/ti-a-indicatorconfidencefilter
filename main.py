import argparse
import logging
import json
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Filters threat intelligence indicators based on confidence scores.")
    parser.add_argument("-i", "--input", dest="input_file", required=True,
                        help="Path to the input JSON file containing threat intelligence indicators.")
    parser.add_argument("-c", "--confidence", dest="min_confidence", type=int, default=50,
                        help="Minimum confidence score (0-100) for indicators to be included. Default is 50.")
    parser.add_argument("-o", "--output", dest="output_file",
                        help="Path to the output JSON file to store the filtered indicators. If not specified, prints to stdout.")

    return parser.parse_args()


def validate_indicator(indicator):
     """
     Validates if the indicator has the required structure and data types.
     Protects against attribute errors.
     """
     if not isinstance(indicator, dict):
          logging.error("Indicator is not a dictionary. Skipping validation.")
          return False

     if "indicator" not in indicator:
          logging.warning("Indicator missing 'indicator' field. Skipping.")
          return False

     if "confidence" not in indicator:
          logging.warning("Indicator missing 'confidence' field. Setting confidence to 0.")
          indicator["confidence"] = 0 #Set to 0 to ensure it's filtered out if the user sets a >0 threshold

     if not isinstance(indicator["confidence"], int):
          logging.warning("Indicator 'confidence' is not an integer. Skipping.")
          return False
     return True


def filter_indicators(indicators, min_confidence):
    """
    Filters threat intelligence indicators based on the provided minimum confidence score.
    Args:
        indicators (list): A list of dictionaries, where each dictionary represents a threat intelligence indicator.
        min_confidence (int): The minimum confidence score for indicators to be included.

    Returns:
        list: A list of filtered threat intelligence indicators.
    """
    filtered_indicators = []
    for indicator in indicators:
        if not validate_indicator(indicator):
            continue  # Skip invalid indicators

        try:
            if indicator["confidence"] >= min_confidence:
                filtered_indicators.append(indicator)
        except (KeyError, TypeError) as e:
            logging.error(f"Error processing indicator: {e}.  Skipping indicator.")
            continue #Skip if error occur

    return filtered_indicators


def load_indicators_from_file(input_file):
    """
    Loads threat intelligence indicators from a JSON file.

    Args:
        input_file (str): The path to the input JSON file.

    Returns:
        list: A list of threat intelligence indicators (dictionaries).
    """
    try:
        with open(input_file, "r") as f:
            try:
                indicators = json.load(f)
                if not isinstance(indicators, list):
                    logging.error("Input file does not contain a list of indicators.")
                    return None
                return indicators
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from file: {e}")
                return None
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        return None
    except IOError as e:
        logging.error(f"Error reading input file: {e}")
        return None


def write_indicators_to_file(indicators, output_file):
    """
    Writes filtered threat intelligence indicators to a JSON file.

    Args:
        indicators (list): A list of filtered threat intelligence indicators.
        output_file (str): The path to the output JSON file.
    """
    try:
        with open(output_file, "w") as f:
            json.dump(indicators, f, indent=4)
        logging.info(f"Filtered indicators written to: {output_file}")
    except IOError as e:
        logging.error(f"Error writing to output file: {e}")


def main():
    """
    Main function to execute the indicator filtering process.
    """
    args = setup_argparse()

    # Input Validation
    if not 0 <= args.min_confidence <= 100:
        logging.error("Minimum confidence score must be between 0 and 100.")
        sys.exit(1)

    indicators = load_indicators_from_file(args.input_file)
    if indicators is None:
        sys.exit(1)  # Exit if loading indicators failed.

    filtered_indicators = filter_indicators(indicators, args.min_confidence)

    if args.output_file:
        write_indicators_to_file(filtered_indicators, args.output_file)
    else:
        print(json.dumps(filtered_indicators, indent=4))  # Print to stdout

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Filter indicators from input.json with a minimum confidence of 75 and save to output.json:
#    python main.py -i input.json -c 75 -o output.json
#
# 2. Filter indicators from input.json with the default minimum confidence (50) and print to stdout:
#    python main.py -i input.json
#
# 3. Filter indicators from input.json with a minimum confidence of 20 and print to stdout:
#    python main.py -i input.json -c 20
#
# Example input.json:
# [
#     {"indicator": "8.8.8.8", "type": "IP", "confidence": 90},
#     {"indicator": "example.com", "type": "DOMAIN", "confidence": 60},
#     {"indicator": "1.2.3.4", "type": "IP", "confidence": 30},
#     {"indicator": "malware.exe", "type": "HASH", "confidence": 80}
# ]