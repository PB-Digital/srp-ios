import json
from typing import Any
from models import Config

def get_raw_config() -> Config:
    with open('Config.json', 'r') as file:
        config = json.load(file)
    return Config(
        version = config['version'], 
        release_notes = config['release_notes']
    )
