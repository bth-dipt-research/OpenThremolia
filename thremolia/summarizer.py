from pypdf import PdfReader
from tokenizers import Tokenizer

from thremolia.llm_interfaces import LLMInterface
from thremolia.utils import logger

MAX_TEXT_LEN = 5000


def split_text_into_chunks(
    text: str,
    chunk_size: int = 3000,  # size in tokens
    overlap: int = 100,
) -> list[str]:
    """Split text into overlapping chunks."""
    tokenizer = Tokenizer.from_pretrained("bert-base-uncased")
    output = tokenizer.encode(text)
    chunks = []
    start_index = 0

    while start_index < len(output.ids):
        end_index = start_index + chunk_size
        current_chunk = output.ids[start_index:end_index]
        chunks.append(tokenizer.decode(current_chunk))
        start_index += chunk_size - overlap  # Move forward with overlap

    logger.info(
        f"Split text into {len(chunks)} chunks, average chunk size: {sum(len(chunk) for chunk in chunks) / len(chunks) if chunks else 0:.2f} characters",
    )
    return chunks


def extract_text_from_pdf(pdf: str) -> str | None:
    pdf_reader = PdfReader(pdf)
    text = ""
    for page in range(len(pdf_reader.pages)):
        text += pdf_reader.pages[page].extract_text()
    return text


def summarize_pdf(pdf: str, client: LLMInterface) -> str:
    """Process a single PDF file and return summary data."""
    text = extract_text_from_pdf(pdf)
    if not text:
        return None

    if len(text) <= MAX_TEXT_LEN:
        return text

    chunks = split_text_into_chunks(text)

    return client.summarize_requirements(chunks)


def summarize_text(text: str, client: LLMInterface) -> str:
    if len(text) <= MAX_TEXT_LEN:
        return text

    chunks = split_text_into_chunks(text)
    return client.summarize_requirements(chunks)
