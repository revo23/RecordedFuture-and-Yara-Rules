import re # Regular expression operations

def format_yara_hex(raw_hex, group=2, wrap=16):
    """
    Convert raw hex string into YARA-compliant hex string.

    Args:
        raw_hex (str): Continuous hex string, e.g., "83c418c3"
        group (int): Number of characters per byte (default 2)
        wrap (int): Number of bytes per line for readability (default 16)

    Returns:
        str: YARA-formatted hex string, e.g.,
        { 83 C4 18 C3 90 90 90 8B 44 24 08 8B 4C 24 04 }
    """
    # Remove any non-hex characters
    clean_hex = ''.join(c for c in raw_hex if c in '0123456789abcdefABCDEF')

    # Split into bytes
    bytes_list = [clean_hex[i:i+group] for i in range(0, len(clean_hex), group)]

    # Wrap lines for readability
    lines = [' '.join(bytes_list[i:i+wrap]) for i in range(0, len(bytes_list), wrap)]

    return "{\n    " + "\n    ".join(lines) + "\n}"

def process_yara_rule(rule_text):
    """
    Finds all hex strings in a YARA rule and reformats them.

    Args:
        rule_text (str): Raw YARA rule text.

    Returns:
        str: YARA rule text with formatted hex strings.
    """
    # Regex to match hex strings in curly braces
    hex_pattern = re.compile(r'\{([0-9a-fA-F\s]*)\}')

    def replacer(match):
        raw = match.group(1)
        return format_yara_hex(raw)

    # Substitute all hex strings with formatted versions
    return hex_pattern.sub(replacer, rule_text)

# Example usage:
with open("raw_rules.yara", "r") as f:
    raw_rules = f.read()

formatted_rules = process_yara_rule(raw_rules)

# Save to a new file
with open("formatted_rules.yara", "w") as f:
    f.write(formatted_rules)

print("YARA rules have been formatted and saved to formatted_rules.yara")
