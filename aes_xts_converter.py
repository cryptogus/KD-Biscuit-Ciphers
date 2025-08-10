#!/usr/bin/env python3
# filepath: /home/hhlee/make_kat.py

import re
import sys


def hex_to_c_array(hex_string, name):
    """16진수 문자열을 C 배열 형태로 변환"""
    if not hex_string:
        return f"uint8_t {name}[] = {{}};"

    # 16진수를 2자리씩 나누어 0x 형태로 변환
    bytes_list = [hex_string[i : i + 2] for i in range(0, len(hex_string), 2)]
    bytes_formatted = [f"0x{b}" for b in bytes_list]

    # 한 줄에 16개씩 배치
    lines = []
    for i in range(0, len(bytes_formatted), 16):
        line = ", ".join(bytes_formatted[i : i + 16])
        lines.append(f"    {line}")

    array_content = ",\n".join(lines)
    length = len(bytes_list)

    return f"uint8_t {name}[{length}] = {{\n{array_content}\n}};"


def parse_cavs_file(filename):
    """CAVS 파일을 파싱하여 C 배열로 변환"""
    with open(filename, "r") as f:
        content = f.read()

    # 현재 모드 (ENCRYPT/DECRYPT)
    current_mode = ""
    count = 0
    encrypt_count = 0
    decrypt_count = 0

    print("// Generated from CAVS test vectors")
    print("#include <stdint.h>")
    print()

    # 각 블록을 처리
    lines = content.split("\n")
    current_data = {}

    for line in lines:
        line = line.strip()

        if line.startswith("[") and line.endswith("]"):
            # 모드 변경 전에 이전 데이터 처리
            if current_data and current_mode:
                print_test_case(current_data, current_mode, count)
                count += 1
                # 이전 모드로 카운트 증가
                if current_mode == "encrypt":
                    encrypt_count += 1
                elif current_mode == "decrypt":
                    decrypt_count += 1
                current_data = {}

            # 새로운 모드로 변경
            current_mode = line[1:-1].lower()
            count = 0
            print(f"// === {current_mode.upper()} MODE ===")
            continue

        if line.startswith("COUNT ="):
            # 이전 데이터가 있으면 출력
            if current_data and current_mode:
                print_test_case(current_data, current_mode, count)
                count += 1
                # 현재 모드로 카운트 증가
                if current_mode == "encrypt":
                    encrypt_count += 1
                elif current_mode == "decrypt":
                    decrypt_count += 1
            current_data = {}
            continue

        # KEY, I, PT, CT 추출
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip().upper()
            value = value.strip()
            # KEY, I, PT, CT만 저장
            if (current_mode == "encrypt"):
                if key in ["KEY", "I", "PT", "CT"]:
                    current_data[key] = value
            elif (current_mode == "decrypt"):
                if key in ["KEY", "I", "CT", "PT"]:
                    current_data[key] = value

    # 마지막 데이터 처리
    if current_data and current_mode:
        print_test_case(current_data, current_mode, count)
        if current_mode == "encrypt":
            encrypt_count += 1
        elif current_mode == "decrypt":
            decrypt_count += 1

    # 테스트 케이스 개수를 C 변수로 출력
    print("// Test case counts")
    print(f"#define ENCRYPT_TEST_COUNT {encrypt_count}")
    print(f"#define DECRYPT_TEST_COUNT {decrypt_count}")
    print(f"#define TOTAL_TEST_COUNT {encrypt_count + decrypt_count}")
    print()
    print(f"const uint32_t encryptTestCount = {encrypt_count};")
    print(f"const uint32_t decryptTestCount = {decrypt_count};")
    print(f"const uint32_t totalTestCount = {encrypt_count + decrypt_count};")


def print_test_case(data, mode, count):
    """테스트 케이스를 C 배열로 출력"""
    print(f"// Test Case {count}")

    for key in ["KEY", "I", "PT", "CT"]:
        if key in data:
            # 카멜케이스로 변환: encrypt0Key, encrypt0I, encrypt0Pt, encrypt0Ct
            key_camel = key.lower().capitalize()  # Key, I, Pt, Ct
            var_name = f"{mode}{count}{key_camel}"
            print(hex_to_c_array(data[key], var_name))

    print()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <NIST rsp file(cavs_file)>")
        sys.exit(1)

    filename = sys.argv[1]
    try:
        parse_cavs_file(filename)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
