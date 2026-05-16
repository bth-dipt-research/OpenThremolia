# Basic principles

This document describes some of the approaches used in the implementation of the application functionality.

## DFD Description

We use LLM capabilities to analyze the provided by the user app DFD and convert it to text description. The results of this img-to-text conversion are heavily dependant on LLM vision capabilities.

The resulting system description heavily affects the final quality of the report. This is why in the system prompt we not only ask LLM to describe what it sees on the DFD, but also categorize elements with STRIDE-per-element types (External Entity, Process, Data Flow, Data Store), individually list trust boundaries, etc.

It is recommended using models of at least GPT 4o-mini performance level for this process in order to achieve better results. The `image_recognition.md` system prompt can be also adjusted for better results on different LLMs.


## Report Generation

### System prompt
For the report generation we provide LLM with all the required information:
1. Basic report generation instructions (default one is located in the `system_prompt.md`)
2. System description (provided by user)
3. Context information about selected Threat Models
    - shortened threat descriptions of OWASP and ATLAS threats: `MITRE_ATLAS_threat_list.md` `OWASP_TOP_10_for_LLMs_2025_threat_list.md`
    - detailed description of STRIDE-per-element approach: `STRIDE_matrix.md`
4. Response format: Pydantic BaseModel class `Report`, located in `threat.py`

Due to context window size limitations of most LLMs we provide shortened versions of threat descriptions by default. In cases when LLM has big enough context window size (i.e. 1M+ tokens), the context information can be easily expanded for better report generation results.

> **Important!** When customizing system prompt, please include **`<threats_context>`** tag somewhere in it. It will be automatically replaced with the selected Threat Models context during the generation process.


### Generation process

During the generation process the LLM will be providing portions of the report (due to the response size limitations) and will be automatically asked by the app to continue generation until the LLM itself thinks the process if finished.

> **Note!** On smaller LLMs, like llama3.2 3B due to small context window size this can sadly result in an endless report generation.

This happens when the model forgets either previously generated threats or ways of signalling that the report is complete. Currently the workaround is a constant limitation of maximum sequential generations per request (can be changed in the `.env` file with `LLM_GENERATION_LIMITER` config).

From a user perspective this can be avoided by:
- splitting system description onto smaller sections and generating reports for them individually;
- trying to shrink size of the system and context prompts to reduce their overall token size;
- choosing an LLM with a higher context window size.

## Validation

The validation process is used to evaluate the quality of the report by performing a set of logical checks, LLM requests, etc. It can be used to help answer questions like:

- Is the report complete?
- Were selected threat models covered completely with the report?
- What is the accuracy of the report?
- Did LLM make any mistakes in it? How many? Which ones?

By having these answers user can determine if the overall report quality is satisfying or if it should be re-generated.

In order to answer those questions the validation process consists of following steps:

- Categorization validation. Checks if every threat is categorized with an existing threat type from the selected threat models.
- Validation of CVSS vectors for mistakes in them.
- Construction of coverage matrixes for each of the selected threat model and determines coverage of those matrixes with the report.
- Analysis of relativeness of the provided threat model categories with threat descriptions. The process is:
    - convert the threat description to RAG vector;
    - use RAG search to find threat model categories descriptions similar to this one;
    - select first `threshold_value` results and check if the selected threat is classified with one of them.
- LLM based validations:
    - LLM is provided with full system description and the report and is asked to analyze the quality of the report and give its total *health score*. The `health_check.md` system prompt is used for this process and can be customized according to user's needs.
    - The same process repeats but with a set of custom prompts provided by the user directly or selected from predefined ones in the `custom_metrics.json`. They are selected through the UI before the Report Generation process.
- Metric calculations:
    - *Aggregated CVSS score* is calculated, which is a sum of all threat's CVSS scores.
    - By using the STRIDE coverage matrix and STRIDE-per-element approach the amount of *non-generated threats* is determined.
    - After the user selects which threats are valid and/or mitigated the system calculates amounts and percentages of *invalid threats*, *mitigated threats* as well as *aggregated residual CVSS score* ,which is a sum of CVSS scores of non-mitigated threats.
    - The overall report *Accuracy* is determined using all the previous calculations, where:
        - **valid threats** are `true positive`;
        - **invalid threats** are `false positive`;
        - **manually added threats** are `true negative`;
        - **non-generated threats** are `false negative`.

## Question answering

The user can freely communicate with the LLM to talk about the report, specific threats, threat models, etc. To improve LLM's knowledge of the topic we use RAG process to insert required context in the user's messages.

Currently the context is based on the **OWASP Top 10 for LLMs** and **MITRE ATLAS** threat models: their attack techniques, tactics and mitigations information.

The data loaded into these RAG collections can be seen in the `OWASP_2025.csv` and `MITRE_ATLAS.csv` files respectively.

## Automated Report extension process

To minimize actions required from the user, the report can be automatically extended to cover all of the STRIDE-per-element coverage matrix. In this process the app sends an additional prompt to the LLM with a list of non-generated threats for each element found in the system description.

Please note, that in system descriptions with high amount of elements and connections the complete coverage may be difficult to achieve. This is dependant on the LLM used, as each individual threat requires approximately 250-350 LLM tokens, and with a requirement of up to 5 threats per element it can easily exceed the context window size of the smaller LLMs.

## Automated Report fixing process

In order to fix mistakes the user can select which ones to fix from the mistakes list and press the `Fix Report` button to send the resulting list to the LLM. The LLM then analyzes the mistakes and attempts to re-generate these threats whilst fixing the errors.

Unfortunately, this process is highly dependent on the capabilities of the selected LLM, and not all types of mistakes are easily corrected by every LLM.