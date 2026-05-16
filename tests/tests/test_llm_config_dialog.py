import pytest
from streamlit.testing.v1 import AppTest

from thremolia.llm_interfaces import (
    ChatGPTInterface,
    OllamaInterface,
    OpenAICompatibleInterface,
)
from thremolia.llm_interfaces.llm_utils import UnknownInterfaceError
from thremolia.streamlit_gui.llm_config_dialog import switch_llm_interface


@pytest.mark.parametrize(
    ("selected_llm"),
    [
        "Cat",
    ],
)
def test_switch_llm_interface_wrong(selected_llm):
    at = AppTest.from_file("streamlit_gui.py").run()

    with pytest.raises(UnknownInterfaceError) as excinfo:
        at.session_state.llm_interface = switch_llm_interface(selected_llm)

    assert f"Unknown client type: {selected_llm.lower()}" in str(excinfo.value)
    assert excinfo.type is UnknownInterfaceError


@pytest.mark.parametrize(
    ("selected_llm", "correct_type"),
    [
        ("chatGPT", ChatGPTInterface),
        ("Ollama", OllamaInterface),
        ("openaicompatible", OpenAICompatibleInterface),
    ],
)
def test_switch_llm_interface(selected_llm, correct_type):
    at = AppTest.from_file("streamlit_gui.py").run()

    at.session_state.llm_interface = switch_llm_interface(selected_llm)

    assert isinstance(at.session_state.llm_interface, correct_type)
