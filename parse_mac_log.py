#!/usr/bin/env python
import argparse
import json
import logging
from collections.abc import Generator
from pathlib import Path

from dissect.cstruct import cstruct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STRUCT = """
struct header_name {
    uint32_t unknown_len;
    uint32_t name_len;
    char     name[name_len];
}

struct item_body {
    uint32_t    line_len;
    uint32_t    line_count;
    uint32_t    line_offset[line_count];
    char        body[line_len - 8 - line_count * 4];
}

struct item_header {
    uint32_t    header_len;
    uint32_t    num_fields;
    uint32_t    field_offset[num_fields];
    header_name header_name[num_fields];
}

struct log_item {
    char        magic[4];
    uint32_t    item_len;
    uint32_t    blob_len;
    char        blob[blob_len - 8];
    item_header header;
    item_body   body;
}

struct mac_log {
    char        magic[4];
    uint32_t    blob_len;
    uint32_t    item_count;
    uint32_t    file_size;
    char        unknown_1[blob_len - 0x10];  
    log_item    log_item[item_count];
}
"""


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filename",
        help="The log file(s) to parse",
        nargs="*",
    )
    return parser.parse_args()


def get_parser() -> cstruct:
    return cstruct(endian="<").load(STRUCT)


def get_headers(log_item: cstruct) -> list:
    return [i.name.decode("utf-8") for i in log_item.header.header_name]


def parse_log_lines(log_item: cstruct) -> list:
    out = []
    lines = log_item.body
    offset = lines.line_offset
    offset_base = offset[0]

    for i in range(len(offset) - 1):
        start_read = offset[i] - offset_base
        end_read = offset[i + 1] - offset[i]
        out.append(lines.body[start_read : start_read + end_read].decode("utf-8"))

    # Add last line
    out.append(
        lines.body[offset[-1] - offset_base : log_item.body.line_len].decode("utf-8")
    )

    return out


def parse_log_item(log_item: cstruct) -> dict:
    headers = get_headers(log_item)
    log_lines = parse_log_lines(log_item)

    return dict(zip(headers, log_lines))


def process_logfile(logfile: Path) -> Generator[dict, None, None]:
    parser = get_parser()

    logger.info(f"Processing {logfile.name}")
    with open(logfile, "rb") as f:
        parsed_log = parser.mac_log(f)

    logger.info(f"Found {parsed_log.item_count} log items")
    for log_item in parsed_log.log_item:
        yield parse_log_item(log_item)


def main() -> None:
    args = get_args()

    for logfile in args.filename:
        logfile_path = Path(logfile)
        for log_item in process_logfile(logfile_path):
            print(json.dumps(log_item, indent=4))


if __name__ == "__main__":
    main()
