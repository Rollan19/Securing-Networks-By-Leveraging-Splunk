# Securing-Networks-By-Leveraging-Splunk

## Objective

Enhance CentOS cybersecurity by implementing Splunk SIEM to detect, alert, and report on security incidents, focusing on brute force attacks and unauthorized file access. This project aims to develop a real-time monitoring solution for proactive threat detection and response.

### Skills Learned

### Skills Learned from This Thesis

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in configuring and utilizing Splunk for real-time monitoring and alerting.
- Ability to analyze and correlate system logs for detecting security incidents.
- Enhanced knowledge of cybersecurity measures for CentOS systems.
- Expertise in developing and implementing threat detection and response strategies.
- Practical experience with cybersecurity tools such as VMware, CentOS, Kali Linux, and Putty.
- Skills in identifying and mitigating brute force attacks and unauthorized access attempts.
- Development of critical thinking and problem-solving skills in cybersecurity contexts.

### Tools Used

- Security Information and Event Management (SIEM) system for log ingestion and analysis (e.g., Splunk).
- Brute force attack tools (such as Hydra) for simulating attacks and testing defenses.
- Network analysis tools (such as Nmap) for port scanning and vulnerability assessment.

## Steps
### System Desgin

 <img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/53d2ee3d-27d5-4965-adcf-00713ccdd18c" />
 
Fig 1: Proposed System Design
In a figure, the system architecture is centered around a comprehensive network setup involving various interconnected components, specifically designed for security monitoring and log management through a Splunk deployment. This setup features two primary elements: the attacker machine (192.168.80.152) and the CentOS server (192.168.80.161). The attacker machine is tasked with launching brute force attacks against the CentOS server, which hosts the Splunk SIEM solution. The objective of the attacker is to gain unauthorized access to user accounts on the CentOS machine by systematically guessing passwords using repetitive or iterative methods. Upon successful intrusion, the attacker intends to steal and exfiltrate sensitive data stored on the CentOS server, which could include confidential documents, passwords, and other critical information.
The CentOS server, serving as both the target of the attack and the host for the Splunk SIEM system, plays a crucial role in this architecture. The Splunk SIEM is deployed to monitor and analyze system logs, network traffic, and other relevant data sources in real-time. It is configured to detect and alert on suspicious activities, such as brute force attempts and unauthorized access to user accounts. This configuration includes monitoring for abnormal login attempts and unauthorized access to sensitive files, generating alerts when such activities are detected. Splunk utilizes both threshold-based and pattern-based detection methods to identify brute force attacks. Threshold-based detection monitors for a high volume of failed login attempts from the same source within a specific time frame, while pattern-based detection involves creating search queries to identify specific attack patterns in authentication logs.
The network setup illustrated in the diagram involves the PC (Victim), which sends log data to the Indexer on port 9997, facilitating the collection and analysis of security-related data by the Splunk system. The Indexer processes and indexes these logs, which are then available for further analysis by the Search Head, connected on port 9997. The Web Interface, interacting with the PC (Victim) on ports 8000 and 8089, provides an access point for authorized users, who connect to it using role-based access control (RBAC) on port 8000.
The attacker machine's SSH access to the PC (Victim) on port 22 poses a significant securitthe y threat, highlighting the need for robust security measures. When Splunk detects a potential brute force attack, it triggers an alert to notify security personnel, providing details such as the source IP address (192.168.80.152), targeted user accounts, and the number of failed login attempts. This enables security analysts to respond promptly and effectively, taking appropriate actions such as blocking the source IP address or implementing additional security measures to mitigate potential threats. This architecture underscores the critical importance of continuous monitoring and proactive security measures to protect against unauthorized access and data theft. The integration of Splunk SIEM with real-time monitoring and alerting capabilities provides visibility into security incidents, allowing for rapid response and mitigation of threats, thereby enhancing the overall security posture of the network.
4.3 Implementation
4.3.1 Security Side: Using Splunk Enterprise for Monitoring and Alerts
Initially, CentOS Linux 7 is set up on VMware Workstation, acquiring the IP address 192.168.80.161 through NAT configuration. The virtual machine is provisioned with 1 GB of memory, 1 processor, and a 50 GB hard disk to ensure sufficient space for storing Splunk logs. This configuration establishes a stable environment for deploying and testing the Splunk SIEM solution, enabling effective monitoring and analysis of security events within the CentOS environment.





To activate the network interface and obtain an IP address in CentOS 7, the command "ifup ens33" is used. This command brings up the network interface named "ens33" and initiates the process of obtaining an IP address through DHCP or static configuration.
Once the network interface is activated and an IP address is obtained, Putty is opened and logged in to the CentOS virtual machine using the assigned IP address. Once the IP address obtained is 192.168.80.161, this IP address is entered in the hostname field of Putty and click "Open" to establish an SSH connection to the CentOS VM.

In Figure 5, the user named "lunar" with root account type is created with the password "LNar19@" and added to the wheel group. This group is designated for users who require elevated privileges for certain administrative tasks without needing to log in as the root user. Being a member of the wheel group allows the user "lunar" to execute commands with elevated privileges using the "sudo" command, enhancing security by limiting direct access to the root account and promoting the principle of least privilege.

In Figure 6, the "lunar" account is checked under the "home" directory to verify its presence and ensure that the account was successfully created and configured.

In Figure 7, exploitable files under the "lunar" account are examined. Two directories, namely "Personal_Doc" and "Client_Projects," are created within the user's home directory. Under "Personal_Doc," sensitive files such as "medical_history," "monthly_financial," and "private_diary" are stored, containing personal and confidential information. Similarly, "Client_Projects" houses critical documents like "meeting_2024_04_10," "presentation_client_meeting_notes," and "project_proposal_template," which contain proprietary and confidential data related to client projects. The confidentiality and integrity of these files are paramount as they may contain sensitive information such as medical records, financial statements, and proprietary project details. Any unauthorized access or modification to these files could result in severe consequences, including privacy breaches, financial loss, or damage to professional relationships. 
In Figure 8, the process involves copying the download link for "Splunk Enterprise" from the Splunk website. This link will be used to install Splunk Enterprise onto the CentOS 7 Linux system.


The above screenshot shows a CentOS terminal where the user is downloading the Splunk Enterprise installation package using the `wget` command. The command fetches the file from the Splunk website and saves it as `splunk-9.2.1-78803f08aabb-Linux-x86_64.tgz`. 


The Figure 11 depicts a terminal window with the root user prompt '/opt'. The output of the command 'ls' shows a directory named 'splunk' and a tarball file named 'splunk-9.2.1-780830faabb-Linux-x86_64.tgz'. This indicates that the tar zip file 'splunk-9.2.1-780830faabb-Linux-x86_64.tgz' has been unzipped in the '/opt' directory. It appears that the user is working with Splunk, a software for analyzing machine-generated big data.

In Figure 12, the command 'splunk start --accept-license' is typed in the path '/opt/splunk/bin/'. The command suggests that Splunk is being initiated with the acceptance of the license agreement. The username, ‘admin’ and password ‘KSThu19@’ is entered.

In Figure 13, Splunk Enterprise is configured to operate on the web interface accessible through port 8000, with the server's IP address set to 192.168.80.161.

In Figure 14, the Splunk Enterprise website interface login form is accessed through the IP address 192.168.80.161:8000. The username 'admin' and the password 'KSThu19@', which were created as shown in Figure 12, have been entered into the login form.




In Figure 16, The command '/opt/splunk/bin/splunk add monitor /var/log' is used to add the '/var/log' directory to the Splunk real-time monitoring system.
The 'add monitor' command in Splunk is used to configure the system to monitor and index specific files or directories in real-time. When you run this command, Splunk will start monitoring the specified location and automatically ingest and index any new log data that is generated, allowing you to search and analyze the log data in the Splunk interface.
By adding the '/var/log' directory to the Splunk real-time monitoring system, Splunk will now be able to collect and index all the log files located in the '/var/log' directory, making them available for searching, analysis, and reporting within the Splunk Enterprise platform.
The Figure 17 shows the data input that was added to the Splunk system using the previous command 'splunk add monitor /var/log'. You can see this data input by navigating to the 'Data Summary' section, which is circled in red in the figure. Within the 'Data Summary' view, there is a yellow-circled area that displays the last update timestamp of the data that has been ingested from the '/var/log' directory. Additionally, the data sources can be checked by clicking on the 'Sources' bar, or by referring to the following figure.








The Splunk dashboard shown in the image provides a detailed view of various logs and their sources, which can be used to configure alerts for different security events. Based on the provided information, four specific alerts have been configured, likely using the signatures of the logs shown in the dashboard:
1.	Brute Force Attack
2.	External Login Attempt
3.	File Transfer via SSH
4.	Root Password Unauthorized Access

1. Brute Force Attack


















The configuration of the Brute Force Attack alert in Splunk, as illustrated in Figures 20, 21 and 22, provides a robust mechanism for detecting potential security threats. The search query (Figure 20) monitors failed login attempts by filtering logs from the host "localhost.localdomain" within the "/var/log/audit/audit.log" file where the result is marked as "failed." Building on this, the alert configuration (Figure 21 and 22) specifies the alert name "Brute Force Attack" and includes a description highlighting the significance of multiple failed password attempts. The alert is set to trigger in real-time and will remain active for 24 hours. It will activate when more than five failed login attempts occur within a one-minute window, triggering the alert once the condition is met. Additionally, a throttle is configured with a 60-second interval to prevent the alert from firing too frequently, ensuring manageable notifications. The alert type is set to 'triggered alert' with a critical severity level, emphasizing the importance of immediate attention and response. This setup ensures timely detection and response to brute force attacks, enhancing the security posture of the monitored system.
2. External Login Attempt























The configuration of the External Login Attempt alert in Splunk, as illustrated in Figures 23, 24, and 25, provides a robust mechanism for detecting potential security threats. The search query (Figure 23) monitors external login attempts by filtering logs from the host "localhost.localdomain" within the "/var/log/secure" file, specifically for SSH protocol events where the user access is accepted from the IP address "192.168.88.152." Building on this, the alert configuration (Figures 24 and 25) specifies the alert name "External Login Attempt" and includes a description highlighting the significance of detecting external logins to user accounts. The alert is set to trigger in real-time and will remain active for 24 hours. It will activate for each individual event that matches the search query (Per-Result). The alert type is set to 'triggered alert' with a critical severity level, emphasizing the importance of immediate attention and response. This setup ensures timely detection and response to unauthorized external login attempts, enhancing the security posture of the monitored system.



3.  File Tranfer via SSH





















The configuration of the File Transfer via SSH alert in Splunk, as illustrated in Figures 26, 27, and 28, provides a robust mechanism for detecting potential security threats related to unauthorized file transfers. The search query (Figure 26) monitors for file access events involving the SFTP server by filtering logs from the host "localhost.localdomain" within the "/var/log/audit/audit.log" file, specifically looking for the execution of "/usr/libexec/openssh/sftp-server." Building on this, the alert configuration (Figures 27 and 28) specifies the alert name "File Transfer via SSH" and includes a description highlighting the significance of file transfers occurring, especially following a brute force attack, which may indicate an ongoing security breach. The alert is set to trigger in real-time and will remain active for 24 hours. It will activate for each individual event that matches the search query (Per-Result). The alert type is set to 'triggered alert' with a medium severity level, ensuring timely detection and response to potential unauthorized file transfers, thus enhancing the security posture of the monitored system.



4. Root Password Unauthorized Access













 







The configuration of the "Root Password Unauthorized Access" alert in Splunk, as illustrated in Figures 29, 30, and 31, ensures robust detection of unauthorized root access attempts. The search query (Figure 29) monitors successful root logins from any IP address other than 192.168.80.161 by filtering logs from the host "localhost.localdomain" within the "/var/log/audit/audit.log" file. The alert configuration (Figures 30 and 31), named "Root Password Unauthorized Access," is set to trigger in real-time and will remain active for 24 hours. It is configured to activate when more than three successful root login attempts occur within a 10-minute window, ensuring timely detection of suspicious activity. Additionally, a throttle is configured to suppress triggering for 60 seconds to prevent alert flooding. When triggered, the alert adds the event to Triggered Alerts with a critical severity level, emphasizing the need for immediate investigation and response to potential unauthorized access. This setup significantly enhances the security posture of the monitored system by ensuring timely detection and management of unauthorized root access attempts.



4.3.2 Attacker Side: Performing Brute Force Attacks with Hydra
In Figure 33, Kali Linux is set up on VMware Workstation, acquiring the IP address 192.168.80.152 through NAT configuration. The virtual machine is provisioned with 1 GB of memory, 2 processor, and a 30 GB hard disk. This Kali Linux machine is configured to perform a targeted attack on a CentOS virtual machine through SSH port 22 to gain unauthorized access to a user account and subsequently perform data theft.
As shown in Figure 32, the successful ping connection can be seen. It indicates successful transmission and receipt of 8 packets with no packet loss, along with round-trip time statistics.







In Figure 34, the output of the nmap command used to perform network scanning on the IP address 192.168.80.161 is displayed. The scan reveals information about open and closed ports on the target system. The host at IP address 192.168.80.161 is up with a latency of 0.66 seconds. This section only focuses on port 22/tcp which is open, running the SSH service with openSSH version 7.4.







Figure 35 shows the username list to comprise potential usernames that could be used in a brute force attack on a CentOS system. Each entry represents a common or plausible username that might be configured on the target system. The list is exhaustive and includes variations to increase the likelihood of a successful breach.







Figure 36 shows the password list that contains potential passwords that could be used in a brute force attack on a CentOS system. Each entry represents a common or plausible password that might be set on the target system. To increase the chances of a successful breach, the list is comprehensive and includes variations.






The command utilized (hydra -L username.txt -P password.txt -f ssh://192.168.80.161) specifies files containing lists of usernames and passwords to try against the target IP address 192.168.80.161. Hydra attempts multiple login combinations, indicating that the attack started on April 13, 2024, at 21:40:22, and found a valid set of credentials within approximately one minute. The successful login credentials discovered were username "lunar" and password "LNar19@". This result is displayed in the terminal output, confirming that the tool effectively identified a valid SSH login pair, illustrating the efficacy of Hydra in penetration testing for identifying weak security configurations.
The "External Login Attempt" alert was triggered immediately after the successful brute force attack, indicating that Splunk detected the login attempt from an external source. The "Brute Force Attack" alert triggered slightly earlier, showing that Splunk identified the repeated login attempts as a potential brute force attack. Both alerts are marked as critical, emphasizing the severity of the events. The synchronization of these alerts with the timing of the Hydra attack highlights Splunk's effectiveness in real-time monitoring and alerting on suspicious activities, enabling quick detection and response to security incidents.





After successfully compromising the SSH credentials for the target machine at IP address 192.168.80.161, obtaining the username "lunar" and password "LNar19a", the attacker then logged into the victim's account. At the same time, that move is detected by Splunk Enterprise as an "External Login Attempt" shortly as shown in Figure 40.









After successfully logging into the victim's account using the compromised credentials, the attacker discovered sensitive files named "Client_project" and "Personal_Doc" as shown in Figure 41. This access allows the attacker to potentially exploit the information contained within these files. The "Client_project" file contains confidential business information, project details, or client data, which could be valuable for corporate espionage or financial gain. The "Personal_Doc" file includes private or sensitive personal information, leading to privacy breaches or identity theft. The unauthorized access and retrieval of these files represent a significant security and privacy risk, underscoring the critical need for robust security measures and rapid incident response to prevent and mitigate the impact of such breaches.


After gaining unauthorized access to the victim's account using compromised credentials, the attacker used the `scp` command to download two directories, "Client_Projects" and "Personal_Doc," from the compromised machine to their local system. The "Client_Projects" directory contained sensitive business documents such as meeting notes and project proposals, while the "Personal_Doc" directory included personal files like medical history, financial records, and a private diary. This exfiltration of sensitive information demonstrates a significant breach of both corporate and personal data security, underscoring the critical need for robust security measures, continuous monitoring, and swift incident response to protect against such unauthorized data transfers.
After the attacker used the `scp` command to exfiltrate data from the compromised machine, a series of alerts were triggered in Splunk Enterprise, highlighting the ongoing security breach. Critical "External Login Attempt" alerts were generated at 21:41:24 +07, 21:44:37 +07, and 21:45:26 +07, indicating repeated unauthorized access to the victim's account using the compromised credentials. Subsequently, medium-severity "File Transfer via SSH" alerts were triggered at 21:44:32 +07, 21:44:35 +07, and 21:45:28 +07, corresponding to the transfer of sensitive directories and files, including "Client_Projects" and "Personal_Doc." These alerts provided a clear timeline of the attack, from initial unauthorized access to data exfiltration, enabling the security team to quickly recognize, respond to, and investigate the breach, as well as to implement measures to prevent future incidents.
4.3.2 Sequence of the Entire Event
1.	Brute Force Attack Initiation:
	Time: Around 21:40 +07
	Action: The attacker begins a brute force attack using THC Hydra against the SSH service of the target machine at IP address 192.168.80.161.
	Outcome: Hydra attempts multiple username and password combinations.
2.	Successful Credential Compromise:
	Time: 21:41 +07
	Action: Hydra finds valid credentials, username "lunar" and password "LNar19a."
	Outcome: A valid login pair is discovered, allowing the attacker to proceed with unauthorized access.
3.	Unauthorized Access:
	Time: 21:41:24 +07
	Action: The attacker logs into the victim's account using SSH with the compromised credentials.
	Alert: "External Login Attempt" alert is triggered in Splunk (critical severity).
4.	Initial Data Discovery:
	Time: Shortly after 21:41 +07
	Action: The attacker finds directories named "Client_Projects" and "Personal_Doc" in the victim's account.
5.	Data Exfiltration – First Transfer:
	Time: 21:44:32 +07
	Action: The attacker uses the scp command to download the "Client_Projects" directory.
	Alert: "File Transfer via SSH" alert is triggered in Splunk (medium severity).
6.	Continued Unauthorized Access:
	Time: 21:44:37 +07
	Action: Further unauthorized login attempts detected.
	Alert: Another "External Login Attempt" alert is triggered in Splunk (critical severity).
7.	Data Exfiltration – Second Transfer:
	Time: 21:44:35 +07 and 21:45:28 +07
	Action: The attacker uses the scp command to download the "Personal_Doc" directory.
	Alert: Additional "File Transfer via SSH" alerts are triggered in Splunk (medium severity).
8.	Subsequent Unauthorized Access:
	Time: 21:45:26 +07
	Action: Another unauthorized login attempt is detected.
	Alert: Another "External Login Attempt" alert is triggered in Splunk (critical severity).








4.4 Evaluation
Evaluation of this project is based on Splunk's effectiveness in detecting and alerting security incidents in real-time. The provided attack and alert timelines demonstrate Splunk's capability to promptly identify and respond to brute force attacks, unauthorized access, and data exfiltration attempts on a CentOS system. This real-time detection and alerting confirm that the solution meets its objective of enhancing cybersecurity posture through proactive threat detection and response.
[1]	Brute Force Attack Detection






Attack Time: 21:41:23 +07 (Hydra command initiated)
Triggered Alert: "Brute Force Attack" alert at 21:41:24 +07
Evaluation: Splunk successfully detected the brute force attack in real-time, immediately triggering an alert right after the Hydra command was initiated. This demonstrates Splunk's capability to monitor and identify suspicious login attempts as they occur.



[2]	Unauthorized Access Detection






Attack Time: 21:41:24 +07 (First unauthorized login)
Triggered Alerts: Multiple "External Login Attempt" alerts at 21:41:24 +07, 21:44:37 +07, and 21:45:26 +07
Evaluation: Splunk generated critical alerts in real-time for each unauthorized login attempt. The consistency and immediacy of these alerts confirm Splunk's effectiveness in detecting and flagging unauthorized access attempts.
[3]	Data Exfiltration Detection






Attack Time:
21:44 +07 (First file transfer via scp)
21:45 +07 (Second file transfer via scp)
Triggered Alerts: "File Transfer via SSH" alerts at 21:44:32 +07, 21:44:35 +07, and 21:45:28 +07
Evaluation: Splunk's real-time detection capabilities are further validated by the immediate generation of alerts during the data exfiltration phase. The alerts were triggered at the exact times corresponding to the scp commands executed by the attacker.
Conclusion
The evaluation of the project based on the provided attack and alert information demonstrates that the implementation of Splunk for real-time monitoring and alerting on a CentOS system is highly effective. Splunk's ability to detect and alert on security incidents such as brute force attacks, unauthorized access, and data theft in real-time aligns perfectly with the project's aim and objective. This real-time capability ensures that potential threats are identified promptly, allowing for immediate response and mitigation, thereby significantly strengthening the security infrastructure of the CentOS environment.


*Ref 1: Network Diagram*
