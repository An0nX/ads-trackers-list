#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

import requests

try:
    import router_common_pb2
except ImportError:
    print(
        "Error: 'router_common_pb2.py' not found. "
        "Please generate it from router_common.proto using protoc.",
        file=sys.stderr
    )
    sys.exit(1)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)

USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
REQUEST_TIMEOUT: int = 60  # seconds

# Rule type mapping to our internal representation
Rule = Tuple[str, str]

# Pre-compiled regex patterns for parsing efficiency
HOSTS_PATTERN = re.compile(r"^(?:127\.0\.0\.1|0\.0\.0\.0)\s+([\w\.-]+)")
ADGUARD_PATTERN = re.compile(r"^\|\|([\w\.-]+)\^")
RAW_DOMAIN_PATTERN = re.compile(r"^([\w\.-]+\.[\w]+)$")


def parse_blocklist(content: str) -> Set[Rule]:
    """Parses the content of a blocklist file.

    This function iterates through each line of the blocklist content,
    applies various parsing rules (hosts, AdGuard, raw domain), and
    extracts domains.

    Args:
        content: The blocklist content as a string.

    Returns:
        A set of tuples, where each tuple contains the rule type
        (e.g., 'full', 'domain') and the extracted domain. Using a set
        ensures uniqueness of rules within the list.
    """
    rules: Set[Rule] = set()
    lines: List[str] = content.splitlines()

    for line in lines:
        line = line.strip()

        if not line or line.startswith(("#", "!", "/")):
            continue

        hosts_match = HOSTS_PATTERN.match(line)
        if hosts_match:
            domain = hosts_match.group(1).lower()
            rules.add(("full", domain))
            continue

        adguard_match = ADGUARD_PATTERN.match(line)
        if adguard_match:
            domain = adguard_match.group(1).lower()
            rules.add(("domain", domain))
            continue

        # Treat as a raw domain list as a fallback
        parts = line.split()
        if not parts:
            continue
        
        # Check if the first part of the line is a valid domain
        raw_domain_match = RAW_DOMAIN_PATTERN.match(parts[0])
        if raw_domain_match:
            domain = raw_domain_match.group(1).lower()
            rules.add(("domain", domain))
            
    return rules


def fetch_blocklist(url: str) -> str:
    """Fetches blocklist content from a given URL.

    Args:
        url: The URL of the blocklist.

    Returns:
        The content of the blocklist as a string.

    Raises:
        requests.exceptions.RequestException: If the network request fails.
    """
    headers: Dict[str, str] = {"User-Agent": USER_AGENT}
    try:
        response = requests.get(
            url, headers=headers, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error("Failed to fetch %s: %s", url, e)
        raise


def main() -> None:
    """Main function to generate the dlc.dat file."""
    parser = argparse.ArgumentParser(
        description="Generate a V2Ray dlc.dat file from a list of blocklist URLs."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the input file containing 'name,url' pairs.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Directory to place the generated file.",
    )
    parser.add_argument(
        "--output-name",
        type=str,
        default="dlc.dat",
        help="Name of the generated dat file.",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        logging.error("Input file not found: %s", args.input)
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    blocklists: Dict[str, Set[Rule]] = {}
    all_rules: Set[Rule] = set()

    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                name, url = [item.strip() for item in line.split(",", 1)]
            except ValueError:
                logging.warning("Skipping invalid line: %s", line)
                continue

            logging.info("Fetching list: %s from %s", name, url)
            try:
                content = fetch_blocklist(url)
                rules = parse_blocklist(content)
                logging.info("Parsed %d rules for list '%s'", len(rules), name)
                blocklists[name] = rules
                all_rules.update(rules)
            except requests.exceptions.RequestException:
                # Error is already logged in fetch_blocklist
                continue

    # Add the combined list
    if all_rules:
        blocklists["blocklists-all"] = all_rules
        logging.info("Created combined list 'blocklists-all' with %d rules", len(all_rules))

    # Create protobuf list
    geosite_list = router_common_pb2.GeoSiteList()
    rule_type_map: Dict[str, int] = {
        "domain": router_common_pb2.Domain.RootDomain,
        "full": router_common_pb2.Domain.Full,
        "regexp": router_common_pb2.Domain.Regex,
        "keyword": router_common_pb2.Domain.Plain,
    }

    for name, rules in blocklists.items():
        site = router_common_pb2.GeoSite()
        site.country_code = name.upper()
        
        for rule_type, value in rules:
            domain_entry = site.domain.add()
            domain_entry.type = rule_type_map.get(
                rule_type, router_common_pb2.Domain.Plain
            )
            domain_entry.value = value
        
        geosite_list.entry.append(site)

    # Sort for reproducible output
    geosite_list.entry.sort(key=lambda s: s.country_code)

    # Serialize and write to file
    output_path = args.output_dir / args.output_name
    try:
        with open(output_path, "wb") as f:
            f.write(geosite_list.SerializeToString())
        logging.info("'%s' has been generated successfully at %s", args.output_name, output_path)
    except IOError as e:
        logging.error("Failed to write output file: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
