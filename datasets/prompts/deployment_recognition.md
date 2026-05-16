# Task
Analyze the provided file that contains the Azure app infrastructure configuration and provide ***complete*** the text description of its **elements** and **connections**.
The file is supposedly a HashiCorp Terraform .tf, Azure Bicep .bicep, or Azure Resource Manager (ARM) template.

Try to give each element one of those STRIDE-per-element categories and write in next to their name in round brackets: External Entity, Process, Data Flow, Data Store.
For Data Flow use names in the form of **`<Source> -> <Target>`**.
Trust boundaries are not elements so do not classify them, but provide description for them as for other elements.
If any configurable attribute is "Select" or null, just mention that the value was not specified.

This data will be later used to perform Threat Modelling, so it is extremely important to prioritize and describe configurations related to cybersecurity.

Here is the file content: