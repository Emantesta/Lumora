def check_braces(file_path):
    brace_count = 0
    line_number = 0
    imbalance_start = 0
    with open(file_path, 'r') as file:
        for line in file:
            line_number += 1
            for char in line:
                if char == '{':
                    brace_count += 1
                    if brace_count == 1 and imbalance_start == 0:
                        imbalance_start = line_number
                elif char == '}':
                    brace_count -= 1
            if brace_count < 0:
                print(f"Extra closing brace at line {line_number}")
                return
    if brace_count > 0:
        print(f"Missing {brace_count} closing brace(s) at end of file. Imbalance may start around line {imbalance_start}")
    elif brace_count == 0:
        print("Braces are balanced")

check_braces('contracts/AMMPool.sol')