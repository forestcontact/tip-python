import json

from dataclasses import dataclass
from typing import List, Dict

import toml

@dataclass
class SignerPair:
	identity: str
	api: str

@dataclass
class TipInfo:
	commitments: List[str]
	signers: List[SignerPair]

@dataclass
class ApiConfig:
    port: int = 0

@dataclass
class StoreConfig:
    dir: int = 0

@dataclass
class MessengerConfig:
    user: str
    session: str
    key: str
    buffer: int
    conversation: str

@dataclass
class NodeConfig:
    key: str
    signers: List[str]
    timeout: int

@dataclass
class TomlConfig:
    api: dict
    store: dict
    messenger: dict
    node: dict

def load_toml(toml_file: str):
    config = toml.load(toml_file)
    return TomlConfig(**config)

class TipConfig(object):

    def __init__(self, toml_file: str):
        self.config = load_toml(toml_file)
        self.node_config = NodeConfig(**self.config.node)
        self.messenger_config = MessengerConfig(**self.config.messenger)
        self.api_config = ApiConfig(**self.config.api)
        self.store_config = StoreConfig(**self.config.store)

    def get_node_config(self):
        return self.node_config
    
    def get_messenger_config(self):
        return self.messenger_config

    def get_api_config(self):
        return self.api_config

    def get_store_config(self):
        return self.store_config

class TipInfo:

    def __init__(self, config_file):
        with open(config_file) as f:
            info = json.load(f)
            signers = []
            for signer in info.signers:
                signers.append(SignerPair(**signer))
            self.tip_info = TipInfo(info['commitments'], signers)
    
    def get_commitments(self) -> List[str]:
        return self.tip_info.commitments
    
    def get_signers(self) -> List[SignerPair]:
        return self.tip_info.signers

