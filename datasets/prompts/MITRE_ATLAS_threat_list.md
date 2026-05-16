## MITRE ATLAS:
AML.T0000: Search for Victim's Publicly Available Research Materials - Adversaries may search publicly available research to learn how and where machine learning is used within a victim organization.
AML.T0001: Search for Publicly Available Adversarial Vulnerability Analysis - An adversary will likely try to identify any pre-existing researches available on the vulnerabilities that has been done for this class of models.
AML.T0002: Acquire Public ML Artifacts - Adversaries may search public sources for machine learning artifacts, including software stacks, datasets, and model configurations.
AML.T0003: Search Victim-Owned Websites - Adversaries may search victim-owned websites for technical details, organizational information, key employee data, and business operations to aid in targeting.
AML.T0004: Search Application Repositories - Adversaries may search open application repositories, such as Google Play and the App Store, for targeting information.
AML.T0005: Create Proxy ML Model - Adversaries may obtain proxy models to simulate full offline access to the victim's target model.
AML.T0006: Active Scanning - Adversaries may probe or scan victim systems for targeting, involving direct interaction unlike other reconnaissance methods.
AML.T0007: Discover ML Artifacts - Adversaries may search private sources for machine learning artifacts, such as software stacks and data repositories, to refine attacks and identify targets for exfiltration or disruption.
AML.T0008: Acquire Infrastructure - Adversaries may acquire or rent various infrastructure, including servers, domains, and web services, to support their operations.
AML.T0010: ML Supply Chain Compromise - Adversaries may gain initial access by compromising the ML supply chain, sometimes requiring secondary access to complete their attack.
AML.T0011: User Execution - An adversary may rely upon specific actions by a user in order to gain execution.
AML.T0012: Valid Accounts - Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.
AML.T0013: Discover ML Model Ontology - Adversaries may discover the ontology of a machine learning model's output space, for example, the types of objects a model can detect.
AML.T0014: Discover ML Model Family - Adversaries may discover the general family of model.
AML.T0015: Evade ML Model - Adversaries can craft adversarial data that prevent a machine learning model from correctly identifying the contents of the data.
AML.T0016: Obtain Capabilities - Adversaries may search for and obtain software capabilities for use in their operations.
AML.T0017: Develop Capabilities - Adversaries may develop their own capabilities to support operations. This process encompasses identifying requirements, building solutions, and deploying capabilities.
AML.T0018: Backdoor ML Model - Adversaries may implant backdoors in ML models, causing them to behave normally but produce adversary-controlled outputs when triggered.
AML.T0019: Publish Poisoned Datasets - Adversaries may poison training data and publish it to a public location.
AML.T0020: Poison Training Data - Adversaries may attempt to poison datasets used by a ML model by modifying the underlying data or its labels.
AML.T0021: Establish Accounts - Adversaries may create accounts with various services for use in targeting, to gain access to resources needed in ML Attack Staging, or for victim impersonation.
AML.T0024: Exfiltration via ML Inference API - Adversaries may exfiltrate private information via ML Model Inference API Access.
AML.T0025: Exfiltration via Cyber Means - Adversaries may exfiltrate ML artifacts or other information relevant to their goals via traditional cyber means.
AML.T0029: Denial of ML Service - Adversaries may target machine learning systems with a flood of requests for the purpose of degrading or shutting down the service.
AML.T0031: Erode ML Model Integrity - Adversaries may degrade the target model's performance with adversarial data inputs to erode confidence in the system over time.
AML.T0034: Cost Harvesting - Adversaries may target different machine learning services to send useless queries or computationally expensive inputs to increase the cost of running services at the victim organization.
AML.T0035: ML Artifact Collection - Adversaries may collect ML artifacts, such as models, datasets, and telemetry data, for Exfiltration or for use in ML Attack Staging.
AML.T0036: Data from Information Repositories - Adversaries may leverage information repositories to mine valuable information.
AML.T0037: Data from Local System - Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.
AML.T0040: ML Model Inference API Access - Adversaries may gain access to a model via legitimate access to the inference API to Discover ML Model Ontology, Model Family, to Verify Attack, Craft Adversarial Data, Evade ML Model, Erode ML Model Integrity.
AML.T0041: Physical Environment Access - If the model is interacting with data collected from the real world in some way, the adversary can influence the model through access to wherever the data is being collected.
AML.T0042: Verify Attack - Adversaries can verify the efficacy of their attack via an inference API or access to an offline copy of the target model.
AML.T0043: Craft Adversarial Data - Adversarial data are inputs to a machine learning model that have been modified such that they cause the adversary's desired effect in the target model.
AML.T0044: Full ML Model Access - Adversaries may gain full "white-box" access to a machine learning model, including its architecture, parameters, and class ontology.
AML.T0046: Spamming ML System with Chaff Data - Adversaries may flood the ML system with chaff data, increasing detections and causing analysts to waste time on incorrect inferences.
AML.T0047: ML-Enabled Product or Service - Adversaries may use a product or service that uses machine learning under the hood to gain access to the underlying machine learning model.
AML.T0048: External Harms - Adversaries may abuse their access to a victim system and use its resources or capabilities to further their goals by causing harms external to that system.
AML.T0049: Exploit Public-Facing Application - Adversaries may exploit weaknesses in internet-facing systems, such as bugs or design flaws, to induce unintended behavior.
AML.T0050: Command and Scripting Interpreter - Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.
AML.T0051: LLM Prompt Injection - An adversary may craft malicious prompts as inputs to an LLM that cause the LLM to act in unintended ways.
AML.T0052: Phishing - Adversaries may send phishing messages to gain access to victim systems.
AML.T0053: LLM Plugin Compromise - Adversaries may use their access to an LLM that is part of a larger system to compromise connected plugins.
AML.T0054: LLM Jailbreak - An adversary may use a carefully crafted LLM Prompt Injection designed to place LLM in a state in which it will freely respond to any user input, bypassing any controls, restrictions, or guardrails placed on the LLM.
AML.T0055: Unsecured Credentials - Adversaries may search compromised systems to find and obtain insecurely stored credentials.
AML.T0056: LLM Meta Prompt Extraction - An adversary may induce an LLM to reveal its initial instructions, or "meta prompt" and get sensitive information about the internal workings of the system.
AML.T0057: LLM Data Leakage - Adversaries may craft prompts that induce the LLM to leak sensitive information. This can include private user data or proprietary information.
