import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT_PATH = Path(__file__).parent.parent
DATASETS_PATH = ROOT_PATH / "datasets"
PROMPTS_PATH = DATASETS_PATH / "prompts"

LOGS_PATH = ROOT_PATH / "logs"
LOGS_PATH.mkdir(exist_ok=True)
LOGS_FILE = LOGS_PATH / "app.log"

load_dotenv()

logger = logging.getLogger("ThreMoLIA")
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOGS_FILE, encoding="utf-8")
formatter = logging.Formatter(
    "%(asctime)s — %(levelname)s — %(message)s",
    datefmt="%d.%m.%Y %H:%M:%S",
)
handler.setFormatter(formatter)
logger.addHandler(handler)

mcp_handler = logging.StreamHandler(sys.stderr)
mcp_handler.setFormatter(formatter)
logger.addHandler(mcp_handler)


def load_text(file_path: str) -> str:
    with open(file_path, encoding="utf-8") as f:
        return f.read()


def load_json(file_path: str) -> dict:
    with open(file_path, encoding="utf-8") as f:
        return json.load(f)


def exclusion_of_models(
    dicts_list: list[dict],
    sm: list[list[str], list[bool] | list],
) -> list[dict]:
    """Excludes specified threat modeling frameworks columns from the list of threats."""
    del_models = [
        name.replace(" ", "_").lower()
        for name, flag in zip(sm[0], sm[1], strict=True)
        if not flag
    ]
    new_dicts = []
    for d in dicts_list:
        new_dict = {
            k: v for k, v in d.items() if not any(sub in k for sub in del_models)
        }
        new_dicts.append(new_dict)

    return new_dicts


class MissingEnvVarError(Exception):
    def __init__(self, value: str) -> None:
        super().__init__(f"{value} is required in the .env file")


def get_required_env(env_var_name: str) -> str:
    value = os.getenv(env_var_name)
    if value:
        return value
    raise MissingEnvVarError(env_var_name)
