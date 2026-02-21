"""Blocklist compiler for V2Ray/Xray.

Downloads domain blocklists from various sources and compiles them
into a single GeoSiteList protobuf .dat file compatible with
V2Ray/Xray routing rules.

All network I/O is performed asynchronously via aiohttp with
concurrent downloads through ``asyncio.TaskGroup``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from pathlib import Path

try:
    import aiohttp

    import router_common_pb2
except ImportError:
    logging.basicConfig(level=logging.ERROR)
    _bootstrap_logger = logging.getLogger(__name__)
    _bootstrap_logger.error(
        "Required dependencies missing. "
        "Install them: pip install aiohttp protobuf"
    )
    sys.exit(1)

logger = logging.getLogger(__name__)

Rule = tuple[str, str]

RULE_TYPE_MAP: dict[str, int] = {
    "domain": router_common_pb2.Domain.RootDomain,
    "full": router_common_pb2.Domain.Full,
    "regexp": router_common_pb2.Domain.Regex,
    "keyword": router_common_pb2.Domain.Plain,
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/134.0.0.0 Safari/537.36"
)
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=60)
MAX_CONCURRENT_REQUESTS = 10

HOSTS_PATTERN = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(.+)$")
ADGUARD_PATTERN = re.compile(r"^\|\|([a-zA-Z0-9._-]+)\^$")
V2FLY_PREFIX_PATTERN = re.compile(r"^(domain|full|regexp|keyword):(.+)$")
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$")


async def fetch_blocklist(
    session: aiohttp.ClientSession,
    url: str,
) -> str:
    """Download blocklist content from a URL.

    Args:
        session: The aiohttp client session to use.
        url: The URL to download the blocklist from.

    Returns:
        The raw text content of the blocklist.

    Raises:
        aiohttp.ClientError: If the download fails.
    """
    async with session.get(url) as response:
        response.raise_for_status()
        return await response.text()


def parse_blocklist(content: str) -> list[Rule]:
    """Parse blocklist content into a list of domain rules.

    Supports multiple formats:
        - Hosts file format (0.0.0.0 or 127.0.0.1 prefix).
        - AdGuard format (||domain.com^).
        - V2Fly domain-list-community format
          (domain:, full:, regexp:, keyword:).
        - Raw domain format (one domain per line).

    Lines starting with ``include:`` are skipped because they reference
    external v2fly lists that are not available locally.

    Args:
        content: Raw text content of a blocklist.

    Returns:
        A list of (rule_type, domain) tuples.
    """
    rules: list[Rule] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith(("#", "!", "[")):
            continue

        line_no_comment = line.split("#")[0].strip()
        if not line_no_comment:
            continue

        hosts_match = HOSTS_PATTERN.match(line_no_comment)
        if hosts_match:
            domain = hosts_match.group(1).strip().lower()
            if domain and domain != "localhost":
                rules.append(("domain", domain))
            continue

        adguard_match = ADGUARD_PATTERN.match(line_no_comment)
        if adguard_match:
            domain = adguard_match.group(1).strip().lower()
            if domain:
                rules.append(("domain", domain))
            continue

        v2fly_match = V2FLY_PREFIX_PATTERN.match(line_no_comment)
        if v2fly_match:
            rule_type = v2fly_match.group(1).lower()
            value = v2fly_match.group(2).strip().lower()
            if value and rule_type in RULE_TYPE_MAP:
                value = value.split(" ")[0].strip()
                rules.append((rule_type, value))
            continue

        if line_no_comment.startswith("include:"):
            continue

        domain_match = DOMAIN_PATTERN.match(line_no_comment)
        if domain_match:
            rules.append(("domain", line_no_comment.lower()))

    return rules


def build_geosite_list(
    categorized_rules: dict[str, set[Rule]],
) -> router_common_pb2.GeoSiteList:
    """Build a GeoSiteList protobuf message from categorized rules.

    Args:
        categorized_rules: A dict mapping category names to sets of
            (rule_type, domain) tuples.

    Returns:
        A populated GeoSiteList protobuf message.
    """
    geosite_list = router_common_pb2.GeoSiteList()

    for category_name, rules in sorted(categorized_rules.items()):
        entry = router_common_pb2.GeoSite()
        entry.country_code = category_name.upper()

        for rule_type, domain in sorted(rules):
            domain_entry = router_common_pb2.Domain()
            domain_entry.type = RULE_TYPE_MAP.get(
                rule_type, router_common_pb2.Domain.RootDomain
            )
            domain_entry.value = domain
            entry.domain.append(domain_entry)

        geosite_list.entry.append(entry)
        logger.info(
            "Category '%s': %d rules",
            category_name,
            len(rules),
        )

    return geosite_list


def parse_input_file(input_path: Path) -> list[tuple[str, str]]:
    """Parse the input file containing blocklist names and URLs.

    Each non-empty, non-comment line must have the format::

        name url

    Args:
        input_path: Path to the input file.

    Returns:
        A list of (name, url) tuples.

    Raises:
        SystemExit: If the input file is not found.
    """
    try:
        text = input_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.error("Input file not found: %s", input_path)
        sys.exit(1)

    entries: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:  # noqa: PLR2004
            entries.append((parts[0], parts[1]))

    return entries


async def download_and_parse(
    session: aiohttp.ClientSession,
    name: str,
    url: str,
) -> tuple[str, set[Rule]] | None:
    """Download a single blocklist and parse its rules.

    Args:
        session: The aiohttp client session to use.
        name: The category name for this blocklist.
        url: The URL to download the blocklist from.

    Returns:
        A tuple of (name, rules_set) on success, or ``None`` on failure.
    """
    logger.info("Downloading: %s (%s)", name, url)
    try:
        content = await fetch_blocklist(session, url)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        logger.exception("Failed to download %s", url)
        return None

    rules = parse_blocklist(content)
    if not rules:
        logger.warning("No rules parsed from %s", name)
        return None

    logger.info("Parsed %d rules from %s", len(rules), name)
    return name, set(rules)


def write_stats(
    stats_path: Path,
    categorized_rules: dict[str, set[Rule]],
    failed_lists: list[str],
    output_path: Path,
) -> None:
    """Write compilation statistics to a JSON file.

    Args:
        stats_path: Path to write the JSON stats file.
        categorized_rules: Successfully compiled rules by category.
        failed_lists: Names of blocklists that failed to download.
        output_path: Path to the compiled .dat file.
    """
    file_size = output_path.stat().st_size
    categories = {
        name: len(rules)
        for name, rules in sorted(categorized_rules.items())
    }

    stats = {
        "total_categories": len(categorized_rules),
        "total_rules": sum(len(r) for r in categorized_rules.values()),
        "file_size_bytes": file_size,
        "categories": categories,
        "failed": failed_lists,
    }

    stats_path.write_text(
        json.dumps(stats, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Stats written to %s", stats_path)


async def main() -> None:
    """Entry point for the blocklist compiler.

    Parses CLI arguments, downloads blocklists concurrently, and
    compiles them into a single .dat file.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Download blocklists and compile into a .dat file.",
    )
    parser.add_argument(
        "-i",
        "--input",
        default="blocklists.txt",
        help="Input file with blocklist names and URLs "
        "(default: blocklists.txt)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=".",
        help="Output directory for the .dat file (default: .)",
    )
    parser.add_argument(
        "-n",
        "--name",
        default="dlc.dat",
        help="Output filename (default: dlc.dat)",
    )
    parser.add_argument(
        "--stats-file",
        default=None,
        help="Path to write JSON build statistics (optional)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    entries = parse_input_file(input_path)
    if not entries:
        logger.error("No blocklist entries found in %s", input_path)
        sys.exit(1)

    logger.info("Found %d blocklist(s) to process", len(entries))

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS)
    headers = {"User-Agent": USER_AGENT}

    categorized_rules: dict[str, set[Rule]] = {}
    failed_lists: list[str] = []
    entry_names = {name for name, _ in entries}

    async with aiohttp.ClientSession(
        connector=connector,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    ) as session:
        async with asyncio.TaskGroup() as tg:
            tasks = [
                tg.create_task(download_and_parse(session, name, url))
                for name, url in entries
            ]

    for task in tasks:
        result = task.result()
        if result is None:
            continue
        name, rules = result
        if name in categorized_rules:
            categorized_rules[name].update(rules)
        else:
            categorized_rules[name] = rules

    failed_lists = sorted(entry_names - set(categorized_rules.keys()))

    if not categorized_rules:
        logger.error("No rules collected from any blocklist")
        sys.exit(1)

    geosite_list = build_geosite_list(categorized_rules)

    output_path = output_dir / args.name
    output_path.write_bytes(geosite_list.SerializeToString())

    total_rules = sum(len(r) for r in categorized_rules.values())
    logger.info(
        "Compiled %d categories with %d total rules to %s",
        len(categorized_rules),
        total_rules,
        output_path,
    )

    if args.stats_file:
        write_stats(
            Path(args.stats_file),
            categorized_rules,
            failed_lists,
            output_path,
        )


def cli_entry() -> None:
    """Synchronous wrapper for the async entry point.

    Used by the ``[project.scripts]`` console entry point so that
    ``blocklist-compiler`` works as a plain CLI command.
    """
    asyncio.run(main())


if __name__ == "__main__":
    cli_entry()
