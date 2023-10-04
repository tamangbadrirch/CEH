# CEH: Certified Ethical Hacker Course 
Table of Contents
[Day 1: Introduction to CEH V12 and Information Security](#day-1-introduction-to-ceh-v12-and-information-security)
[Day 2: Cybersecurity Attack Fundamentals and Hacking Methodology](#day-2-cybersecurity-attack-fundamentals-and-hacking-methodology)



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

