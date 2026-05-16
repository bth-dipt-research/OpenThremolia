import base64
import json
from datetime import datetime
from os import getenv
from pathlib import Path

import anyio
import pandas as pd
from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, Field

from thremolia.llm_interfaces.llm_interface import LLMInterface
from thremolia.llm_interfaces.llm_utils import create_llm_client
from thremolia.report_validation import ValidationReport
from thremolia.threat import THREAT_MODELS, THREAT_MODELS_DATA, Report
from thremolia.utils import logger

mcp = FastMCP("Thremolia MCP")

SELECTED_THREAT_MODELS = json.loads(
    getenv("DEFAULT_THREAT_MODELS", json.dumps(THREAT_MODELS)),
)


@mcp.tool()
def describe_image(path_to_image: str) -> str:
    """
    Returns a detailed text description of the provided image with a DFD.
    The path should be the absolute one if the MCP is running locally, or relative if running within docker container.
    """
    image_path = Path(path_to_image)
    logger.debug(f"Trying to open: {image_path}")
    try:
        with open(image_path, "rb") as image_file:
            image_base64 = base64.b64encode(image_file.read()).decode("utf-8")
    except FileNotFoundError:
        return f"An error occurred: Image file not found at {image_path}"
    except Exception as e:
        return f"An error occurred while opening the image: {e}"

    llm_client = create_llm_client()
    return llm_client.describe_image(image_base64)


@mcp.tool()
async def generate_report(
    system_description: str,
    save_directory: str,
    ctx: Context,
) -> str:
    """
    Generates a list of possible threats within the described system,
    validates it automatically and saves in a report file.

    Args:
        system_description (str): Textual description of the system, its components,
            dataflows, trust boundaries, etc.
        save_directory (str): Directory where the report should be saved. Can be
            filled with empty string or a single dot if you want to save the report in
            the current directory. Set the path to absolute for local MCP execution;
            set it to relative for Docker execution.

    """
    llm_client = create_llm_client()

    report = llm_client.generate_report(system_description, SELECTED_THREAT_MODELS)
    await ctx.report_progress(
        progress=1,
        total=4,
        message="Report generated. Validating...",
    )
    logger.debug("MCP: report generated")

    validation_report = ValidationReport(
        report,
        system_description,
        llm_client,
        validate_distances=False,
    )
    logger.debug("MCP: report validated")
    await ctx.report_progress(
        progress=2,
        total=4,
        message="Report validation complete. Polishing report...",
    )

    if validation_report.stride_percentage < 100:
        report = llm_client.extend_report(
            report,
            SELECTED_THREAT_MODELS,
            validation_report.missing_threats,
        )
        validation_report = ValidationReport(
            report,
            system_description,
            llm_client,
            validate_distances=False,
        )
        logger.debug("MCP: report extended and revalidated")

    if validation_report.mistakes_list:
        report = llm_client.fix_report(
            report,
            SELECTED_THREAT_MODELS,
            pd.DataFrame(
                [mistake.model_dump() for mistake in validation_report.mistakes_list],
            ),
        )
        logger.debug("MCP: report fixed")

    await ctx.report_progress(
        progress=3,
        total=4,
        message="Polishing finished. Generating output file...",
    )

    return await save_report(
        save_directory,
        system_description,
        report,
        validation_report,
        llm_client,
        ctx,
    )


# TODO: come up with a merged method for both this one and the save_load.py counterpart
# and locate it in a place with minimal dependencies (no streamlit, etc.)
def construct_save_file(
    system_description: str,
    report: Report,
    validation_report: ValidationReport,
    llm_client: LLMInterface,
) -> dict:
    return {
        "metadata": {
            "date": datetime.now().strftime("%d-%m-%Y %H-%M-%S"),
            "author": "mcp_server",
            "save_version": "1.1",
            "used_models": {
                "main_model": llm_client.model,
                "img_to_text_model": llm_client.img_to_text_model,
                "validation_model": llm_client.validation_model,
            },
        },
        "text": system_description,
        "report": report.model_dump(),
        "validation_report": validation_report.model_dump(),
        "valid_threats": [
            threat.model_dump() for threat in report.threats if threat.validation
        ],
        "valid_mistakes": [
            mistake.model_dump()
            for mistake in validation_report.mistakes_list
            if mistake.valid
        ],
        "message_history": llm_client.message_history,
        "chat_history": [
            {
                "role": "assistant",
                "content": report.message,
            },
            {
                "role": "assistant",
                "content": validation_report.justification,
            },
        ],
    }


class SavingPreferences(BaseModel):
    """Schema for collecting user preferences."""

    try_alternative: bool = Field(
        description="Would you like to try to save the report with another path?",
    )
    alternative_path: str = Field(default=".", description="Alternative saving path")


async def save_report_file(
    save_directory: Path,
    save_name: str,
    content: dict,
    ctx: Context,
) -> str:
    save_path = Path(save_directory) / save_name

    if Path(save_directory).exists():
        logger.debug(f"MCP: trying to save file at {save_path}")
        json_dump = json.dumps(content, indent=4)
        async with await anyio.open_file(save_path, mode="w") as f:
            await f.write(json_dump)
        logger.debug(f"MCP: file saved at {save_path}")
        return f"File saved at: {save_path}"

    result = await ctx.elicit(
        message=(
            "Could not access the saving directory. Would you like to try another save path?"
        ),
        schema=SavingPreferences,
    )
    if result.action == "accept" and result.data.try_alternative:
        return await save_report_file(
            result.data.alternative_path,
            save_name,
            content,
            ctx,
        )
    return "File was not saved"


async def save_report(
    save_directory: Path,
    system_description: str,
    report: Report,
    validation_report: ValidationReport,
    llm_client: LLMInterface,
    ctx: Context,
) -> str:
    logger.debug("MCP: constructing save")
    save_content = construct_save_file(
        system_description,
        report,
        validation_report,
        llm_client,
    )
    logger.debug("MCP: save constructed")
    save_name = f"mcp_report_{save_content['metadata']['date']}.thremolia"

    if not save_directory:
        save_directory = Path(__file__).parent
    else:
        save_directory = Path(save_directory)

    save_result = await save_report_file(save_directory, save_name, save_content, ctx)

    if save_result == "File was not saved":
        return f"""File was not saved. You can manually save the report by putting the content below as a json into a file named {save_name}.
Here is the report content:
{save_content}
"""
    return f"{save_result}\n\n{display_report(report, validation_report)}"


def display_report(report: Report, validation_report: ValidationReport) -> str:
    threat_list = "\n".join(map(str, report.threats))
    tm_coverages = ""
    for tm in THREAT_MODELS_DATA:
        percentage = getattr(validation_report, f"{tm.threat_field}_percentage")
        tm_coverages += f"{tm.name} Percentage: {percentage} \n"

    return f"""# Report summary:
{report.message}

# Threats:
{threat_list}

# Report Validation:
Health Score: {validation_report.health_score}
Aggregated CVSS score: {validation_report.aggregated_cvss}
STRIDE Coverage: {validation_report.stride_coverage}
STRIDE Percentage: {validation_report.stride_percentage}
{tm_coverages}
Threats not generated according to STRIDE Coverage: {validation_report.non_generated_threats}
"""


# TODO: come up with a merged method for both this one and the save_load.py counterpart
# and locate it in a place with minimal dependencies (no streamlit, etc.)
async def read_report_file(filepath: str, ctx: Context) -> dict | str:
    filepath = Path(filepath)
    if filepath.is_file():
        logger.debug(f"MCP: trying to open file at {filepath}")
        async with await anyio.open_file(filepath) as f:
            contents = await f.read()
            return json.loads(contents)

    result = await ctx.elicit(
        message=("Could not find the file. Would you like to try another save path?"),
        schema=SavingPreferences,
    )
    if result.action == "accept" and result.data.try_alternative:
        return await read_report_file(result.data.alternative_path, ctx)

    return f"Could not find the file at {filepath}"


@mcp.tool()
async def display_report_from_file(filepath: str, ctx: Context) -> str:
    """
    Returns an easy to use representation of the report.
    The path should be the absolute one if the MCP is running locally, or relative if running within docker container.
    """
    report_file = await read_report_file(filepath, ctx)
    if isinstance(report_file, str):
        return report_file

    report = Report.from_dict(report_file["report"])
    validation_report = ValidationReport.from_dict(report_file["validation_report"])

    return display_report(report, validation_report)


@mcp.tool()
async def extend_report(filepath: str, ctx: Context) -> str:
    """
    Extends the report with a list of threats that are missing according to STRIDE coverage.
    The path should be the absolute one if the MCP is running locally, or relative if running within docker container.
    """
    report_file = read_report_file(filepath, ctx)
    if isinstance(report_file, str):
        return report_file
    report = Report.from_dict(report_file["report"])
    validation_report = ValidationReport.from_dict(report_file["validation_report"])

    llm_client = create_llm_client()
    llm_client.message_history = report_file["message_history"]
    llm_client.extend_report(
        report,
        selected_models=SELECTED_THREAT_MODELS,
        missing_threats=validation_report.missing_threats,
    )

    await ctx.report_progress(
        progress=1,
        total=4,
        message="Report extended. Validating...",
    )
    logger.debug("MCP: report extended. Revalidating report...")

    validation_report = ValidationReport(
        report,
        report_file["text"],
        llm_client,
        validate_distances=False,
    )
    logger.debug("MCP: report validated")
    await ctx.report_progress(
        progress=2,
        total=4,
        message="Report validation complete. Generating output file...",
    )

    return save_report(
        Path(filepath).parent[0],  # directory where original report is located
        report_file["text"],
        report,
        validation_report,
        llm_client,
    )


@mcp.tool()
async def fix_report(filepath: str, ctx: Context) -> str:
    """
    Fixes the report with a list of mistakes within the report file.
    The path should be the absolute one if the MCP is running locally, or relative if running within docker container.
    """
    report_file = read_report_file(filepath, ctx)
    if isinstance(report_file, str):
        return report_file
    report = Report.from_dict(report_file["report"])
    validation_report = ValidationReport.from_dict(report_file["validation_report"])

    llm_client = create_llm_client()
    llm_client.message_history = report_file["message_history"]
    llm_client.fix_report(
        report,
        selected_models=SELECTED_THREAT_MODELS,
        mistakes=pd.DataFrame(
            [mistake.model_dump() for mistake in validation_report.mistakes_list],
        ),
    )
    await ctx.report_progress(
        progress=1,
        total=4,
        message="Report extended. Validating...",
    )
    logger.debug("MCP: report mistakes fixed. Revalidating report...")

    validation_report = ValidationReport(
        report,
        report_file["text"],
        llm_client,
        validate_distances=False,
    )
    logger.debug("MCP: report validated")
    await ctx.report_progress(
        progress=2,
        total=4,
        message="Report validation complete. Generating output file...",
    )

    return save_report(
        Path(filepath).parent[0],  # directory where original report is located
        report_file["text"],
        report,
        validation_report,
        llm_client,
    )


@mcp.tool()
def ask_thremolia(prompt: str) -> str:
    """
    Forwards the prompt to a connected LLM and returns response from it.
    """
    llm_client = create_llm_client()
    llm_client.generate_system_prompt(SELECTED_THREAT_MODELS)

    return llm_client.send_chat_message(prompt)


@mcp.tool()
async def ask_thremolia_about_report(
    prompt: str,
    filepath: str,
    ctx: Context,
) -> str:
    """
    Forwards the prompt to a connected LLM and returns response from it.
    Uses context from the existing report.
    """
    llm_client = create_llm_client()
    llm_client.generate_system_prompt(SELECTED_THREAT_MODELS)

    report_file = await read_report_file(filepath, ctx)
    if isinstance(report_file, str):
        return report_file

    llm_client.message_history = report_file["message_history"]
    return llm_client.send_chat_message(prompt)


if __name__ == "__main__":
    mcp.run()
