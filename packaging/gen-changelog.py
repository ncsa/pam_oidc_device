#!/usr/bin/env python3
"""
Generates RPM-compliant %changelog entries from CHANGELOG.md and include/metadata.h.
"""

import sys
import re
from datetime import datetime

def parse_metadata(metadata_path):
    metadata = {}
    try:
        with open(metadata_path, 'r', encoding='utf-8') as f:
            for line in f:
                m = re.match(r'^\s*#define\s+([A-Z_]+)\s+"([^"]+)"', line)
                if m:
                    metadata[m.group(1)] = m.group(2)
    except Exception:
        pass
    return metadata

def generate_rpm_changelog(changelog_path, metadata):
    maintainer = metadata.get('MODULE_MAINTAINER', 'NCSA Cyberinfrastructure <help@ncsa.illinois.edu>')
    default_ver = metadata.get('MODULE_VERSION', '0.3.3')

    entries = []
    current_ver = None
    current_date = None
    current_items = []

    try:
        with open(changelog_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        today = datetime.now().strftime('%a %b %d %Y')
        return f"* {today} {maintainer} - {default_ver}-1\n- Release {default_ver}\n"

    for line in lines:
        stripped = line.strip()
        # Match markdown headers: ## [0.1.0] - 2026-10-30 or ## 0.1.0 - 2026-10-30
        m = re.match(r'^##\s+\[?v?([0-9.]+)\]?\s*-\s*(\d{4}-\d{2}-\d{2})', stripped)
        if m:
            if current_ver:
                try:
                    dt_obj = datetime.strptime(current_date, '%Y-%m-%d')
                    date_str = dt_obj.strftime('%a %b %d %Y')
                except ValueError:
                    date_str = current_date
                
                header = f"* {date_str} {maintainer} - {current_ver}-1"
                entries.append(header + "\n" + "\n".join(current_items))
            
            current_ver = m.group(1)
            current_date = m.group(2)
            current_items = []
        elif current_ver:
            # Collect bullet lines for the entry body. A bullet is a line
            # starting at column 0 with "- " or "* "; indented lines are
            # wrapped prose continuing the previous bullet and must NOT
            # become %changelog lines. Items are normalized to "- " so no
            # generated line begins with "*": rpmbuild parses ANY
            # "*" -leading %changelog line as a new entry header and
            # demands a valid date there.
            if (not line[:1].isspace()) and (line.startswith('- ') or line.startswith('* ')):
                current_items.append('- ' + line[2:].strip())

    if current_ver:
        try:
            dt_obj = datetime.strptime(current_date, '%Y-%m-%d')
            date_str = dt_obj.strftime('%a %b %d %Y')
        except ValueError:
            date_str = current_date
        
        header = f"* {date_str} {maintainer} - {current_ver}-1"
        entries.append(header + "\n" + "\n".join(current_items))

    if not entries:
        today = datetime.now().strftime('%a %b %d %Y')
        return f"* {today} {maintainer} - {default_ver}-1\n- Release {default_ver}\n"

    return "\n\n".join(entries) + "\n"

if __name__ == '__main__':
    changelog_file = sys.argv[1] if len(sys.argv) > 1 else 'CHANGELOG.md'
    metadata_file = sys.argv[2] if len(sys.argv) > 2 else 'include/metadata.h'
    meta = parse_metadata(metadata_file)
    print(generate_rpm_changelog(changelog_file, meta))
