## LINDDUN
L: Linking - Learning more about an individual or a group by associating data items or user actions. Linking may lead to unwanted privacy implications, even if it does not reveal one's identity.
L.1: Linked data - Linking through identifiers.
L.1.1: Unique identifier - Linking based on an identifier that is unique (globally or locally, within the system or across the context boundary).
L.2: Linkable data - Data can be linked through the combination of threat types or datasets, or the application of more advanced profiling techniques.
L.2.1: Through Combination - Linking through combination involves linking by combining different data items or actions together. The items are not linked through an explicit identifier.
L.2.1.1: Quasi-identifier combining data of a single individual - Even if there are no identifiers in the considered data, it is possible that a combined set of items is unique and can be used for linking the data.
L.2.1.2: Combining data of different individuals - By joining datasets or records of different individuals, additional information can be inferred about these individuals.
L.2.2: Through Profiling, derivation, or inference - Link different data items by deriving patterns from the data.
L.2.2.1: Profiling an individual - Personal data of an individual can be analyzed for patterns to link data to that individual. Association is performed at the basis of the data or user actions.
L.2.2.2: Profiling a group of individuals - Data of a single individual leads to insights about a larger group of individuals. Knowledge transfers to other individuals through known relations of group membership or similarity.
L.2.2.3: Profiling an individual through (dis)similarity - The application of learning methods that assess the uniqueness or similarity (clustering) of an individual enables prediction of relevant properties about an individual. Inference of membership of an individual in larger groups.
I: Identifying - Identifying threats arise when the identity of individuals can be revealed through leaks, deduction, or inference in cases where this is not desired.
I.1: Identified information - Processing identified information in the system makes it trivial to obtain the identity of the affected individual.
I.1.1: Processing of identified data - The system requests and processes identified data about a data subject, either directly from the data subject or from a third party.
I.1.2: Identified information in metadata - Even in data exchanges that do not directly contain identified information, the identity of the data subject may be established based on identified information included in metadata or contextual data.
I.2: Identifiable information - This characteristic groups together all types of derivations that in theory could lead to the identity of the data subject.
I.2.1: Pseudonym - The data contains unique references to the identity of the data subject.
I.2.1.1: Identifier - The data contains a unique reference to the identity of the data subject.
I.2.1.2: Quasi-identifier - The combination of attributes may serve as a pseudonym for data relating to a data  subject and could together be used to establish the identity of the data subject.
I.2.2: Revealing attributes - A number of revealing attributes are included in the data which support the identification of the data subject.
I.2.3: The data subject is distinguishable from others - The data subject may become distinguishable through the data that is shared, but also through metadata, participation in communication, behavior in the system, etc.
Nr: Non-repudiation - Non-repudiation threats pertain to situations where an individual can no longer deny specific claims.
Nr.1: Attributable data evidence - A data record or message is (or can be) attributed to a user or data subject.
Nr.1.1: Data - Data can be used to prevent an individual from denying certain claims.
Nr.1.2: Signed data - Digital signatures by an individual or a trusted third party provide a strong source of evidence that prevents deniability claims as third parties can independently verify these signatures.
Nr.1.3: Metadata - Metadata can contain unintended data impacting deniability claims about that data.
Nr.1.4: Embedded/Hidden Data - Embedded or hidden data can be used to reveal additional information impacting deniability claims about the data.
Nr.2: Attributable action side-effect evidence - Action side-effects can cause an action to be attributable to an individual.
D: Detecting - Detecting threats pertain to situations where the involvement, participation, or membership of an individual can be deduced through observation.
D.1: Observed communications - Detection occurs through observing communications between (sub)systems: the existence or lack thereof, or patterns within the observed communications.
D.2: Application side effect - Application actions or transactions may have side effects at which basis detection may occur.
D.3: System responses - Detecting threats pertain to situations where the involvement, participation, or membership of an individual can be deduced through observation.
DD: Data Disclosure - Data disclosure threats represent cases in which disclosures of personal data to, within, and from the system are considered problematic.
DD.1: Unnecessary data types - Depending on the context, data can be perceived highly sensitive, and should therefore only be collected and processed when strictly required.
DD.1.1: Data type sensitivity - More sensitive data types are collected than functionally required by the system.
DD.1.2: Data type granularity - Disclosed personal data is of a more fine-grained level of granularity than needed.
DD.1.3: Data type encoding - The encoding of the data includes additional personal data that is not functionally needed.
DD.2: Excessive volume - The characteristic involves the volume of personal data that is collected and processed.
DD.2.1: Amount - An excessive amount of personal data is processed beyond what is functionally needed.
DD.2.2: Frequency - Personal data is processed more frequently than functionally needed.
DD.2.3: Involved data subjects - Personal data is processed of more data subjects than functionally needed.
DD.3: Unnecessary processing - This characteristic considers whether the processing and treatment of the personal data is actually necessary for achieving the functional goals of the system.
DD.3.1: Treatment, analysis, enrichment, transformation - Personal data is further treated, analyzed, and enriched in a way that is not necessary to achieve the functionality of the system.
DD.3.2: Propagation - Data is accessible by or propagated to other services where it is not needed.
DD.3.3: Implicit data disclosure - Data is implicitly collected as a side-effect of explicit data disclosures or data flows.
DD.3.4: Duration/retention - Personal data is processed or kept longer than functionally needed.
DD.4: Involved parties and exposure - Personal data is excessively exposed, either to external parties known and anticipated at design time (which are typically limited, targeted and scoped), or it is published or broadcasted by the system (which greatly amplifies the potential risk).
DD.4.1: Involved parties - Personal data made accessible to more parties than functionally necessary.
DD.4.1.1: Predetermined set of parties - The parties with whom personal data is shared are known up front. This set of parties is static and fixed.
DD.4.1.2: Dynamic set of parties - The parties with whom personal data is shared are determined dynamically and may change frequently.
DD.4.2: Availability/accessibility of data - Personal data is published more broadly than necessary.
U: Unawareness and Unintervenability - Unawareness and unintervenability threats occur when individuals are insufficiently informed, involved, or empowered with respect to the processing of their personal data.
U.1: Unawareness of processing
U.1.1: Unawareness as data subject - Unawareness of processing focuses on data subjects not being aware about the collection, processing, storage, or disclosure of their personal data.
U.1.2: Unawareness as a user sharing personal data - The user does not need to be the data subject.
U.2: Lack of data subject control - Lack of control considers the lack of control of a data subject to choose and customize which, how, and how long personal data is processed.
U.2.1: Preferences - The lack of control of a data subject to set preferences or consent in how personal data is processed (or collected/stored).
U.2.2: Access - The lack of control in accessing the personal data that is being processed.
U.2.3: Rectification/erasure - The lack of control in rectifying incorrect data or removing personal data that is no longer relevant.
Nc: Non-compliance - Non-compliance threats arise when the system deviates from legislation, regulation, or standards and best practices, leading to the incomplete management of risk.
Nc.1: Regulatory non-compliance - There are legal consequences of the threats and/or processing activities described.
Nc.1.1: GDPR - GDPR-related non-compliance threat characteristics
Nc.1.1.1: Insufficient data subject controls - Support for the different data subject rights is lacking.
Nc.1.1.2: Violation of data minimization principle - More personal data is processed than is actually needed.
Nc.1.1.3: Unlawful processing of personal data - Personal data is not processed in a lawful way
Nc.1.1.3.1: Invalid consent - Personal data collection and processing does not rely on valid consent.
Nc.1.1.3.2: Lawfulness problems not related to consent - Lawfulness problems not related to consent, such as incorrect lawful ground, automated decision making on sensitive personal data, etc.
Nc.1.1.4: Violation of storage limitation principle - Personal data is stored longer than needed.
Nc.1.2: Generic regulatory non-compliance - A general description of non-compliance with regulations (non-specific to a particular legal regime or environment).
Nc.2: Improper personal data management - This characteristic groups a number of data management risks that may have privacy outcomes or vice versa, privacy threats that may lead to overarching data management problems.
Nc.3: Insufficient cybersecurity risk management - A lack of proper cybersecurity risk management with specific attention to the interplay with privacy risks.
Nc.4: Non-compliance with privacy standards and best practices - Non-compliance threats arise when the system deviates from legislation, regulation, or standards and best practices, leading to the incomplete management of risk.
