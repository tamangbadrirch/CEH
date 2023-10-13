# CEH: Certified Ethical Hacker Course 
Table of Contents
[Day 1: Introduction to CEH V12 and Information Security](#day-1-introduction-to-ceh-v12-and-information-security)
[Day 2: Cybersecurity Attack Fundamentals and Hacking Methodology](#day-2-cybersecurity-attack-fundamentals-and-hacking-methodology)
[Day 3: Ethical Hacking](#day-3-ethical-hacking)
[Day 4: Risk, Threat, and Vulnerability](#day-4-risk-threat-and-vulnerability)



## Day 1: Introduction to CEH V12 and Information Security

# Introduction to CEH and EC-Council
  CEH (Certified Ethical Hacker) was established by the EC-Council in 2001.
  
  The EC-Council offers a range of other cybersecurity certifications, including:
    CSCU (Certified Secure Computer User): 
    Intended for individuals who want to gain a fundamental understanding of computer and network security. 
    Suitable for non-technical users, employees, and anyone interested in basic cybersecurity awareness.

  CND (Certified Network Defender):
    Designed for network administrators and professionals responsible for network defense.
    Focuses on protecting, detecting, and responding to network threats and vulnerabilities.
    
  CPENT (Certified Penetration Tester):
    Targeted at experienced security professionals and ethical hackers.
    It's a more advanced certification for those who want to specialize in penetration testing.

  CHFI (Certified Hacking Forensic Investigator):
    Aimed at professionals in law enforcement, IT security, and those involved in computer forensics and investigations.
    Focuses on the skills needed to investigate and analyze computer-related crimes.
    
  ECIH (EC-Council Certified Incident Handler):
    Designed for incident responders, IT managers, and security professionals responsible for handling cybersecurity incidents.
    Teaches how to effectively manage and respond to security incidents.

  ECISO (EC-Council Certified Information Security Officer):
    Specifically required for information security officers in the banking sector as per NRB (Nepal Rastra Bank) regulations.
    Focuses on the responsibilities and skills needed for information security officers in financial institutions.

  CASE .Net & Java (Certified Application Security Engineer for programmers):
    Geared towards software developers and programmers.
    Teaches secure coding practices and how to develop secure software applications.

  CSA (Certified SOC Analyst):
    Targeted at Security Operations Center (SOC) analysts and professionals responsible for monitoring and responding to security incidents.
    Focuses on enhancing the skills needed for effective threat detection and response.

  CTIA (Certified Threat Intelligence Analyst):
    Intended for individuals working in threat intelligence and those responsible for collecting and analyzing cyber threat data.
    Focuses on understanding and countering cyber threats.

  CCT (Certified Technician):
    Designed for IT technicians and support professionals.
    Focuses on practical skills and knowledge needed for technical roles in cybersecurity.

  CCSE (Certified Cloud Security Engineer):
    Aimed at professionals working with cloud technologies and responsible for ensuring the security of cloud environments.
    Focuses on securing cloud-based infrastructure and applications.

# CEH Program Overview
  CEH combines ethical hacking with IS (Information Security) Audit.
  IS Audit involves assessing the current security status.
  CEH covers a wide range of hacking techniques.
  The course duration is 40 hours and is developed by the EC-Council.
  It comprises 20 modules, each focusing on different aspects of ethical hacking.

**Target Machines for Labs**
The following machines are used for lab exercises:
* Windows 11 (IP: 10.10.1.11)
* Windows Server 2022 (for Active Directory hacking, IP: 10.10.1.22)
* Windows Server 2019 (for web application hacking, IP: 10.10.1.19)
* Parrot Security Linux (or Kali, IP: 10.10.1.13)
* Ubuntu Linux (for IOT, IP: 10.10.1.9)
* Android (for mobile hacking, IP: 10.10.1.14)

Attacking Machines
Windows 11 and Parrot Security Linux (or Kali) serve as attacking machines, while others are servers.

**Use the following credentials for authentication:**
Windows Server:
User: Administrator
Password: Pa$$w0rd

Windows 11:
User: admin
Password: Pa$$w0rd

Linux Machines:
User: kali
Password: kali

User: Ubuntu
Password: toor

**Live Hacking Website for Testing**
For practical testing, you can use the website www.certifiedhacker.com.

# Exam Information (v12)
CEH ANSI + Practical = CEH Master
Exam Code: 312-50 (ECC Portal) / 312-50 (VUE)
The total number of questions: 125, with a duration of 4 hours for ANSI.
After the lockdown, you can take the exam from home.
There are 20 scenario-based questions in the Practical exam(CEH Practical), which is open-book style and has a duration of 6 hours.
There is a 15-minute break during the Practical exam.

# Elements of Information Security
CIA Triad:
* Confidentiality: Ensures unauthorized access is prevented, typically through security controls like Multi-Factor Authentication (MFA).
* Integrity: Guarantees the trustworthiness of data or resources, ensuring they remain unaltered. Techniques include encryption, hashing etc.
* Availability: Ensures that authorized users can access data in the same form anytime when it's needed.

* Authenticity: Validates the genuineness of users are they the intended or real one who are supposed to be.
* Non-Repudiation: Ensures that the sender/receiver cannot deny after sending/receiving a message signed by their digital signatures.

# Data Security
Data has three states:
1. Data at rest (stored): Sensitive data should be stored in encrypted form to protect it.
2. Data in transit (motion): Secure channels such as end-to-end encryption -like trussted & paid (VPN tunnels) should be used while transferring data.
3. In process (open & edit): Decryption should occur in a secure location to prevent unauthorized access.
   
# AAA (Authentication, Authorization, Accounting)**
AAA is a critical concept in security:
Authentication: Verifying the identity of users or systems.
Authorization: Granting appropriate access rights to authenticated users.
Accounting: Keeping records of user actions for security auditing and analysis.

## Day 2: Cybersecurity Attack Fundamentals and Hacking Methodology
# Attacking Motives and Methods
  Attacks consist of three components: Motive (Goal), Method (Technique), and Vulnerability (Weakness).
  * Motive pertains to what the attacker aims to achieve in targeting a system.
  * Method involves the processes or techniques followed during an attack. Threat intelligence is used to guess the attacker's method.
  * Vulnerability refers to the weaknesses in the target system.

# Motives behind Information Security Attacks
  Various motives behind information security attacks include:
  * Disrupting business continuity
  * Stealing information and manipulating data
  * Creating fear and chaos by disrupting critical infrastructures
  * Causing financial loss to the target
  * Propagating religious or political beliefs
  * Achieving a state's military objectives
  * Damaging the reputation of the target
  * Taking revenge
  * Demanding ransom

** Exploitation vs. Attack**
  * Exploitation involves gaining access through actions such as system hacking, password cracking, and data manipulation.
  * Attack refers to disrupting the system, which may not necessarily lead to exploitation. Examples include DoS attacks and SQL injection.

# Classification of Attacks
  Attacks can be classified into five types:
  * Passive attacks: Collect information without causing harm (e.g., sniffing, eavesdropping).
  * Active attacks: Take action, disrupting systems (e.g., DoS, MITM, session hijacking, SQL injection).
  * Close-In attacks: Proximity-based attacks (e.g., social engineering, eavesdropping, shoulder surfing).
  * Insider Attacks: Perpetrated by employees or ex-employees, often violating rules (e.g., keyloggers, backdoors, malware).
  * Distribution Attacks: Tampering with hardware or software (e.g., vendor-based attacks, security testing software).

**CEO and Administrative Access**
  Limiting full administrative access for high-level personnel is recommended.

* Wiretapper devices can compromise security.

# Information Warfare
  Information Warfare (InfoWar) is a strategic approach where attackers attack, and defenders defend, akin to a game.

# Defensive Warfare vs. Offensive Warfare
  * Defensive Warfare involves prevention, deterrence, alerts, detection, emergency preparedness, and response.
  * Offensive Warfare includes web app attacks, web server attacks, malware attacks, MITM attacks, and system hacking.

# Hacking Methodology & Framework
Hacking methodologies provide guidelines for structured processes.
# CEH Hacking Methodology (CHM)
* Footprinting: Gather information from outside sources.
* Scanning: Check target's IT infrastructure, location, and interact directly.
* Enumeration: Collect detailed and in-depth system information.
* Vulnerability Analysis: Use VA tools after gathering all available info.
* System Hacking:
  * Gaining Access: Crack passwords, exploit vulnerabilities.
  * Escalating Privileges
  * Maintaining Access: Execute applications, hide files, clear logs.

# Cyber Kill Chain
The Cyber Kill Chain is a concept and framework developed by Lockheed Martin, a global aerospace and defense company, to describe the stages of a cyberattack. 
It is used to understand, identify, and prevent cyber threats effectively. The term "kill chain" is borrowed from military strategy and refers to the sequence of steps that an attacker goes through to achieve their objectives. 
In the context of cybersecurity, the Cyber Kill Chain outlines the stages of a cyberattack, from the initial reconnaissance to the final objective.
It consists of the following phases:
* Reconnaissance:
  Attackers gather information about the target.
  Example: Scanning the target's network to find open ports and services.
  Tools: Nmap, Shodan, Recon-ng

* Weaponization:
  Attackers prepare or acquire malicious tools.
  Example: Creating malware with a payload to exploit a vulnerability.
  Tools: Metasploit, SET (Social-Engineer Toolkit), custom malware

* Delivery:
  Attackers deliver the malicious payload to the target.
  Example: Sending a phishing email containing malware attachment.
  Tools: Phishing kits, malicious email attachments, exploit kits

* Exploitation:
  Attackers execute the payload to exploit a vulnerability.
  Example: Running code in a malicious attachment to gain control over a system.
  Tools: Exploit frameworks (e.g., Metasploit), custom exploits

* Installation:
  Attackers establish a persistent presence on the compromised system.
  Example: Installing backdoors or rootkits to maintain access.
  Tools: Remote administration tools (RATs), Trojans, custom scripts

* Command and Control (C2):
  Attackers set up a communication channel for remote control.
  Example: Malware connecting to a remote server controlled by the attacker.
  Tools: RATs with C2 functionality, reverse shells

* Actions on Objectives:
  Definition: Attackers achieve their ultimate goal, such as data theft or disruption.
  Example: Exfiltrating sensitive data or carrying out a destructive attack.
  Tools: Data exfiltration tools, ransomware, destructive malware

Day 3 - Ethical Hacking and Cybersecurity Fundamentals:

# Day 3: Ethical Hacking

## Introduction
* Ethical hacking involves identifying vulnerabilities and verifying the existence of exploitable vulnerabilities. It plays a vital role in enhancing an organization's cybersecurity posture.

### Think Like a Hacker
To effectively safeguard against cyber threats, one must think like a hacker. By understanding how cybercriminals operate, ethical hackers can better protect an organization's digital assets.

## Why Ethical Hackers?
Ethical hackers are essential for multiple reasons:

* **Preventing Hackers:** Ethical hackers can proactively prevent malicious hackers from exploiting vulnerabilities.

* **Uncovering Vulnerabilities:** Identifying security weaknesses and vulnerabilities before they are exploited by malicious actors.

* **Avoiding Security Breaches:** Preventing security breaches that could lead to data loss, financial damage, and reputational harm.

* **Safeguarding Customer Data:** Ensuring the security and privacy of customer data.

* **Strengthening Security Posture:** Enhancing an organization's overall security posture by identifying and addressing vulnerabilities.

* **Enhancing Security Awareness:** Raising security awareness within an organization, making cybersecurity a shared responsibility.

## Scope
The authorized range of activities, targets, and objectives for an ethical hacker's assessment. Determining the scope of ethical hacking involves various elements, including:

### Risk Assessment
* **Risk Assessment:** Evaluating potential threats and vulnerabilities to understand the risk landscape.

* **Auditing:** Conducting comprehensive audits to assess security measures and compliance.

### Counter Fraud

* **Counter Fraud Measures:** Implementing strategies to detect and prevent fraudulent activities.

### Best Practices

* **Highlighting Best Practices:** Identifying and promoting best practices for security measures and policies.

### Identifying Risk

* **Identifying Risk:** Recognizing potential risks and understanding their implications.

### Highlighting Remedial Action

* **Remedial Action:** Proposing and highlighting corrective actions to mitigate identified risks.

### Limitations
The boundaries and restrictions that an ethical hacker must adhere to, including prohibited activities and actions. Defining limitations is crucial to ensure ethical and legal compliance in ethical hacking:

* **Setting Boundaries:** Establishing the boundaries of ethical hacking to specify what actions are permissible.

* **Hiring Outside Vendors:** In some cases, hiring external vendors to conduct penetration tests can help define what is within the scope of ethical hacking.

* **Agreements and Testing:** Legal agreements should be in place before conducting any testing, and all testing should align with these agreements.

## Vulnerability vs. Risk
Understanding the distinction between vulnerability and risk is essential:

* **Vulnerability:** A vulnerability represents a weakness in a system. For example, not updating antivirus software is a vulnerability.

* **Risk:** Risk refers to the decision to not install protective systems, exposing the organization to potential threats. For instance, not installing antivirus software poses a risk of virus infection.

### Best Practices for VAPT (Vulnerability Assessment and Penetration Testing)

* **Backups:** Always back up data before performing VAPT to avoid data loss during testing.

* **Staging Environment:** Test in a replicated staging environment that mirrors the production system. Avoid testing in the real production environment to prevent lingering SQL queries that could compromise security.

## Skills of Ethical Hackers

### Technical Skills
Ethical hackers should have a strong foundation in various technical areas:

* **Knowledge of OS Environments:** Understanding major operating system environments is crucial for identifying vulnerabilities specific to each.

* **Networking Proficiency:** Having in-depth knowledge of networking principles and protocols.

* **Computer Expertise:** Being a computer expert, with a deep understanding of hardware and software components.

* **Security Expertise:** Expertise in the field of cybersecurity, including knowledge of common security threats.

* **Domain-Specific Technical Knowledge:** High-level technical knowledge in their specialized domain, such as web application security or network security.

### Non-Technical Skills
Ethical hackers should also possess various non-technical skills:

* **Ability to Learn:** The capacity to continuously learn and adapt to new technologies and threats.

* **Strong Work Ethics:** Adhering to ethical and professional standards in all aspects of their work.

* **Knowledge of Security Policies:** Familiarity with the organization's security policies and adherence to them.

* **Understanding of Local Laws:** Knowledge of local and international laws and standards related to cybersecurity.

* **Professionalism and Politeness:** Professional and courteous behavior in all interactions, including reporting vulnerabilities to organizations.

* **Sector-Specific Knowledge:** In-depth knowledge of the sector or organization in which they are performing ethical hacking.

## Information Assurance (IA)

* **Information Assurance (IA):** IA is the process of ensuring information security, which includes protecting the confidentiality, integrity, and availability of information.

### CIA: Confidentiality, Integrity, Availability

* **CIA:** CIA stands for Confidentiality, Integrity, and Availability, representing the core principles of information assurance.

  * **Confidentiality:** Ensuring that information is kept private and only accessible to authorized individuals.

  * **Integrity:** Maintaining the accuracy and reliability of data to prevent unauthorized modifications.

  * **Availability:** Ensuring that information is accessible when needed and not subject to downtime.

## Tailored Policies and Guidance

* **Tailored Policies:** IA policies and processes should be customized based on the organization's objectives and the nature of the data they handle.

* **Data Sensitivity:** Different data types require specific security measures. For example, patient data in the healthcare sector should be treated with utmost sensitivity, while financial institutions focus on safeguarding financial information.

## Designing Network and User Authentication Strength

* **Network Design:** Identifying vulnerabilities and threats within the network infrastructure.

* **Problem Identification:** Recognizing problem areas and defining resource requirements.

* **Resource Planning:** Creating plans for the resources needed to implement security measures.

* **Information Assurance Controls:** Applying appropriate information assurance controls to secure systems and data.

* **Certification and Accreditation:** Conducting certification and accreditation processes to ensure that security measures meet industry standards. Some certification includes PCI-DSS, HIPPA, ISO 27001, 27002, GDPR etc

* **Training:** Providing information assurance training to enhance the skills and knowledge of individuals involved in information security as well as users for organization.

## Defense in Depth
Protecting the organization's assets requires multiple layers of security: Each layer should be protected.

* **Hardware Layer:** Implement physical security measures to protect the infrastructure.

* **System Software (OS) Layer:** Ensure that operating systems are updated and hardened against attacks. Enable realtime protection with antivirus and windows firewalls

* **Application Software Layer:** Secure applications by following best practices and implementing code reviews. Deploy digital certificates, ssl, tls, encryption in diffrents stages of data

* **Data Layer:** Protect data through encryption, both in transit and at rest. We can use encryption and use secure channels. 


# Day 4: Risk, Threat, and Vulnerability
## Recap
**Tactics, Techniques, and Procedures (TTP's)**

- **Tactics:** These encompass the full strategic plans in the world of cyber operations. They answer the question: "What is the plan to achieve the objective?"

- **Techniques:** Techniques are more focused on the execution part. They address the question: "How should the plan be executed effectively?"

- **Procedures:** Procedures break down the techniques into detailed steps, providing a clear process for achieving each plan. They answer: "What specific steps need to be taken?"

**MITRE ATT&CK Framework**
The MITRE ATT&CK framework is a valuable tool for understanding the tactics and techniques that adversaries use to compromise systems and the measures to defend against these tactics.
It's critical to comprehend how attacks are carried out and how to safeguard against them effectively.

**Recon to Maintain**
This phase in cyber operations is where adversaries maintain their presence within a system. They do this by leveraging the infrastructure they have already established.
It involves keeping access and control over a compromised system or network, allowing adversaries to achieve their objectives without being detected.

## Risk, Threat & Vulnerability

**Risk**
Risk in cybersecurity refers to the degree of uncertainty that an adverse event may cause damage to a system. It is the essence of risk management within the field.
Understanding and managing risk is a fundamental aspect of cybersecurity. By identifying risks and their potential impacts, organizations can develop strategies to mitigate these risks effectively.

**Threat**
Threats are the risk-creating factors. For example, if a few drops of water fall on a laptop, the risk is that the laptop might be damaged, and the threat is the water itself.
Threats are essential drivers of risk in the cybersecurity context. Recognizing and mitigating threats is vital for maintaining a secure environment.

**Risk Levels and Risk Matrix**
Risk is often categorized into levels, typically defined as High, Medium, and Low. These levels help prioritize actions for risk mitigation.
Risk matrix provides a structured approach to defining risk levels based on factors such as the potential consequences and the likelihood of an event occurring.

**Consequences**
Examining the consequences of negative effects is crucial to risk management. These consequences are often quantified based on their frequency of occurrence and the impact they may have on the organization.
By assessing the consequences and their likelihood, organizations can better understand the potential impact of different risks.

**Risk Management**
Risk management is a broad and critical topic in cybersecurity. The main objective is to reduce and maintain risk at an acceptable level, defined by the organization's tolerance level.
Risk management involves several key components, including:

- **Risk Identification:** Identifying the causes and sources of risk.
- **Risk Assessment:** Evaluating the potential impact of risks.
- **Risk Treatment:** Developing strategies to mitigate and respond to risks.
- **Risk Tracking:** Monitoring the effectiveness of risk treatments.
- **Risk Review:** Continuously reviewing and updating the risk management process.

It's an ongoing and iterative process aimed at maintaining a secure environment.

**Threat**
In the analogy of "Threat is like police, Risk is like a doctor," threats are the law enforcement officers actively protecting the system from malicious activities.
Just as police safeguard a community, threats help maintain the security and integrity of the digital environment.

**Cyber Threat Intelligence**
Cyber Threat Intelligence involves the collection and analysis of information regarding threats, adversaries, and the patterns that provide insights to make informed decisions.

It can be categorized into various types, including:
- **Strategic:** High-level intelligence focused on long-term visions and plans. It informs top-level management decisions.
- **Tactical:** Based on strategic plans, tactical intelligence defines how to mitigate risks. It involves the creation of processes and actions.
- **Operational:** This level involves technical details. It specifies how to execute tactical plans, such as the use of specific servers, firewalls, or in-house cloud services.
- **Technical:** Highly technical and specialized intelligence concerning hardware and software.

**Threat Intelligence Lifecycle**
The Threat Intelligence Lifecycle consists of the following stages:
1. **Planning & Direction:** Determining the goals of intelligence gathering and analysis.
2. **Collection:** Gathering relevant data and information from various sources.
3. **Processing & Exploitation:** Analyzing and using collected data to identify and address threats effectively.
This lifecycle ensures that intelligence is efficiently obtained, processed, and applied to enhance cybersecurity measures.

**Threat Modeling**
Threat modeling involves studying threats to categorize and understand them. It's an essential approach for analyzing the security of an application or system.

The threat modeling process includes:
- **Identifying Security Objectives:** Defining the goals that need to be achieved.
- **Application Overview:** Understanding the components, data flows, and trust boundaries within the application.
- **Decomposing the App:** Detailed threat analysis to uncover vulnerabilities.
- **Identifying Threat-Control Scenarios:** Developing strategies to mitigate threats.
- **Identifying Vulnerabilities:** Identifying weaknesses related to the threats found.
Tools like Virustotal can be useful in this context.

# Incident Management
**Incident management** focuses on handling incidents that occur, especially in the context of security breaches and cyberattacks. It involves various aspects:

- **Vulnerability Handling:** Addressing vulnerabilities to prevent incidents.
- **Artifact Handling:** Managing evidence and artifacts related to incidents.
- **Announcements:** Communicating information about incidents to relevant stakeholders.
- **Alerts:** Setting up alert systems to detect and respond to incidents.
- 
Incident management often necessitates documentation and the formation of an incident management committee.

**Incident Handling & Response**
Incident handling involves a structured approach to dealing with security incidents. It comprises several key phases:
- **Triage:** Prioritizing incidents based on their severity.
- **Reporting and Detection:** Reporting and detecting security incidents.
- **Incident Response:** Responding to and mitigating the impact of incidents.
- **Analysis:** Analyzing incidents to understand their nature and origin.

# Role of AI and ML in Cyber Security
**Artificial Intelligence (AI) and Machine Learning (ML)** play a significant role in cybersecurity. Their contributions include:
- Identifying New Exploits and Weaknesses: AI and ML are capable of detecting new and previously unknown vulnerabilities.
- Reporting Deviations and Anomalies: They can identify unusual patterns or behaviors that may signal an attack.
- Unsupervised Self-Learning Systems: AI and ML systems can adapt and improve their threat detection capabilities over time.
- Increase in Computing Power and Data Handling: Advancements in AI and ML are driven by enhanced computing power and the collection and storage of vast amounts of data.

AI and ML are employed to prevent cyberattacks through various means, including password protection, threat detection, behavioral analysis, network security, AI-based antivirus, and fraud detection.

# PCI-DSS (Payment Card Industry Data Security Standard)
The **PCI-DSS** is a framework that sets the standards for securing payment card data, such as debit, credit, prepaid, and ATM cards. It applies to all entities involved in payment card processing and ensures that cardholder data is handled securely.

The PCI-DSS framework comprises three components: architecture, structure, standards (compulsory), and guidelines (recommendations).

# ISO/IEC 27001
**ISO/IEC 27001** pertains to quality standards for IT systems, focusing on the establishment, implementation, and maintenance of an Information Security Management System (ISMS). The ISMS ensures that an organization's security requirements and objectives are cost-effectively managed while maintaining compliance with laws and regulations. It consists of 93 controls, and the 2022 version is the latest. ISO 27001 certification provides assurance of a company's commitment to information security management.

Compliance with ISO 27001 involves establishing, implementing, and maintaining a security management system that:
- Addresses security requirements and objectives.
- Is cost-effective.
- Ensures compliance with laws and regulations.
- Manages information security processes effectively.
IT system disposal, such as the secure destruction of hard drives, is a crucial aspect of maintaining information security.

# HIPAA (Health Insurance Portability and Accountability Act)
**HIPAA** primarily relates to health-related data, covering privacy, security, enforcement rules, national identifier requirements, and electronic transaction and code set standards. It is essential for maintaining the privacy and security of patient health information.

# GDPR (General Data Protection Regulation)
**GDPR** sets stringent privacy and security regulations concerning the processing of personal data. It prohibits the sharing of personal data without the consent of the individuals concerned. GDPR is considered one of the strictest privacy and security laws globally, requiring organizations to maintain high standards for data protection.

# ISO/IEC 27002
**Overview:** ISO/IEC 27002 is a code of practice for information security management. It provides a framework of security controls and guidelines for establishing, implementing, and maintaining an information security management system (ISMS).

**Purpose:** ISO 27002 helps organizations protect their information assets, reduce risks, and ensure compliance with legal and regulatory requirements. It offers a customizable set of controls to enhance information security.

**Alignment:** It closely aligns with ISO 27001, which outlines ISMS requirements. ISO 27002 provides detailed guidance on implementing security controls.

# SOC 2 (Service Organization Control 2)
**Overview:** SOC 2 is a framework developed by AICPA for assessing the security, availability, processing integrity, confidentiality, and privacy of customer data by service organizations.

**Trust Service Principles:** SOC 2 is based on five trust service principles: security, availability, processing integrity, confidentiality, and privacy.

**Audience:** SOC 2 reports are intended for customers, regulators, and stakeholders to provide assurance regarding a service organization's data security and privacy controls.

**Use Cases:** Ideal for cloud service providers, data centers, and organizations handling customer data to demonstrate a commitment to data security and privacy.

Both ISO/IEC 27002 and SOC 2 are significant in enhancing information security practices and trust in organizations. ISO 27002 is a code of practice that provides guidance for implementing an information security management system. SOC 2, on the other hand, assesses data security and privacy controls within service organizations, making it relevant for cloud providers and data centers.
