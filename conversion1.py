import re

# Input YARA rules file
input_file = "privateloader.yar"
output_file = "privateloader_formatted.yar"

def format_hex_string(hex_str):
    # Remove spaces, braces, and convert to lowercase
    hex_str = hex_str.replace("{", "").replace("}", "").replace(" ", "").lower()
    # Split every 2 characters and join with space
    spaced_hex = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    return f"{{ {spaced_hex} }}"

with open(input_file, "r") as f:
    lines = f.readlines()

formatted_lines = []
hex_pattern = re.compile(r'(\$\w+\s*=\s*)\{([0-9a-fA-F]+)\}')

for line in lines:
    match = hex_pattern.search(line)
    if match:
        var, hex_str = match.groups()
        formatted_line = var + format_hex_string(hex_str) + "\n"
        formatted_lines.append(formatted_line)
    else:
        formatted_lines.append(line)

with open(output_file, "w") as f:
    f.writelines(formatted_lines)

print(f"Formatted YARA rules saved to {output_file}")
