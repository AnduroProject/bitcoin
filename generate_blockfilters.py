#!/usr/bin/env python3
"""
Generate blockfilters.json.h from custom block data
Usage: python3 generate_blockfilters.py <block_hex> > blockfilters.json.h
"""

import sys
import json

def hex_to_c_array(hex_string):
    """Convert hex string to C-style byte array"""
    # Remove any whitespace or prefixes
    hex_string = hex_string.replace('0x', '').replace(' ', '').replace('\n', '')
    
    # Convert to bytes
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have even length")
    
    bytes_data = bytes.fromhex(hex_string)
    
    # Format as C array
    c_array = []
    for i, byte in enumerate(bytes_data):
        c_array.append(f"'\\x{byte:02x}'")
    
    return c_array

def format_c_array_lines(c_array, indent=4):
    """Format C array into lines of reasonable length"""
    lines = []
    current_line = " " * indent
    
    for i, item in enumerate(c_array):
        if i > 0:
            current_line += ", "
        
        # Start new line if current line is getting too long
        if len(current_line) > 70 and i > 0:
            lines.append(current_line.rstrip(", "))
            current_line = " " * indent
        
        current_line += item
    
    if current_line.strip():
        lines.append(current_line)
    
    return ",\n".join(lines)

def generate_blockfilters_header(block_hex, block_height=0, block_hash=None, 
                                prev_basic_header=None, basic_filter=None, 
                                basic_header=None, notes="Custom block"):
    """Generate the complete blockfilters.json.h file"""
    
    # Default values if not provided
    if block_hash is None:
        block_hash = "0" * 64
    if prev_basic_header is None:
        prev_basic_header = "0" * 64
    if basic_filter is None:
        basic_filter = "0150ac20"
    if basic_header is None:
        basic_header = "cd6ff3436ab73a37671e2232b42c8bce4c5597112d736e88555effd3aabcc526"
    
    # Create block filter test entry matching the exact format
    test_data = [
        [
            "Block Height,Block Hash,Block,[Prev Output Scripts for Block],Previous Basic Header,Basic Filter,Basic Header,Notes"
        ],
        [
            block_height,
            block_hash,
            block_hex,
            [],  # Previous output scripts
            prev_basic_header,
            basic_filter,
            basic_header,
            notes
        ]
    ]
    
    # Convert to JSON with proper formatting
    json_string = json.dumps(test_data, separators=(',', ','))
    
    # Convert JSON string to C array
    c_array = hex_to_c_array(json_string.encode('utf-8').hex())
    
    # Generate header
    header = """// Copyright (c) 2019-2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_DATA_BLOCKFILTERS_JSON_H
#define BITCOIN_TEST_DATA_BLOCKFILTERS_JSON_H

namespace json_tests {
static const char *blockfilters_json = 
"""
    
    footer = """;
} // namespace json_tests

#endif // BITCOIN_TEST_DATA_BLOCKFILTERS_JSON_H
"""
    
    # Format the C array with proper indentation
    formatted_array = format_c_array_lines(c_array)
    
    return header + formatted_array + footer

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_blockfilters.py <block_hex> [height] [hash] [prev_header] [filter] [header] [notes]", file=sys.stderr)
        print("Example: python3 generate_blockfilters.py 0100000000000000... 0 > blockfilters.json.h", file=sys.stderr)
        print("\nAll parameters after block_hex are optional:", file=sys.stderr)
        print("  height: Block height (default: 0)", file=sys.stderr)
        print("  hash: Block hash (default: all zeros)", file=sys.stderr)
        print("  prev_header: Previous basic header (default: all zeros)", file=sys.stderr)
        print("  filter: Basic filter hex (default: 0150ac20)", file=sys.stderr)
        print("  header: Basic header hash (default: genesis hash)", file=sys.stderr)
        print("  notes: Description (default: 'Custom block')", file=sys.stderr)
        sys.exit(1)
    
    block_hex = sys.argv[1]
    
    # Optional parameters
    block_height = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    block_hash = sys.argv[3] if len(sys.argv) > 3 else None
    prev_basic_header = sys.argv[4] if len(sys.argv) > 4 else None
    basic_filter = sys.argv[5] if len(sys.argv) > 5 else None
    basic_header = sys.argv[6] if len(sys.argv) > 6 else None
    notes = sys.argv[7] if len(sys.argv) > 7 else "Custom block"
    
    output = generate_blockfilters_header(
        block_hex, block_height, block_hash, 
        prev_basic_header, basic_filter, basic_header, notes
    )
    print(output)

if __name__ == "__main__":
    main()