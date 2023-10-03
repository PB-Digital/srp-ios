from models import Config
from config_parser import get_raw_config
from typing import Any
from sys import argv
import json

def parse_version(version_string: str) -> list[int]:
    return [ int(i) for i in version_string.split('.') ]

def get_current_version(config: Config) -> list[int]:
    return parse_version(config.version)

def compare_versions(release: list[int], current: list[int]) -> bool:
    if len(release) != len(current):
        print('\n\033[1;31m' + '❌ Version formats does not match!\n')
        exit(1)

    for r, c in zip(release, current):
        if c > r:
            return True
        elif c < r:
            return False
        
    return False

def main():
    release_version_string: str = argv.pop()
    
    release_version: list[int] = parse_version(release_version_string)
    current_version: list[int] = get_current_version(get_raw_config())

    is_valid: bool = compare_versions(release_version, current_version)

    if is_valid:
        print('\n\033[1;32m' + '✅ Valid\n')
    else:
        print('\n\033[1;31m' + '❌ Not valid\n')
        exit(2)


if __name__ == '__main__':
    main()
