# Securing-Networks-By-Leveraging-Splunk

## Objective

Enhance CentOS cybersecurity by implementing Splunk SIEM to detect, alert, and report on security incidents, focusing on brute force attacks and unauthorized file access. This project aims to develop a real-time monitoring solution for proactive threat detection and response.

### Skills Learned

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

## System Desgin

<img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/53d2ee3d-27d5-4965-adcf-00713ccdd18c" width="700" height="600" />
 
Fig 1: Proposed System Design

This setup is designed to monitor and manage security using Splunk. It involves an attacker machine and a CentOS server. Here’s a simplified overview:

### Components:
- Attacker Machine (192.168.80.152): Attempts to gain unauthorized access to the CentOS server using brute force attacks.
- CentOS Server (192.168.80.161): Hosts the Splunk Security Information and Event Management (SIEM) system. It is the target of the attacks and the main component for monitoring and analyzing logs.

### Attack Detection:

- Splunk monitors for high volumes of failed login attempts and specific attack patterns.
- When a brute force attack is detected, Splunk triggers an alert.

### Log Management:

- The victim's PC sends logs to the Indexer on port 9997.
- The Indexer processes and indexes these logs for analysis.
- The Search Head retrieves and analyzes the logs.

### User Access:

- Users access the system through a Web Interface on ports 8000 and 8089.
- Role-Based Access Control (RBAC) is implemented to manage user permissions.

### Network Setup:

- PC (Victim): Sends log data to the Indexer.
- Indexer: Processes and indexes the logs.
- Search Head: Analyzes the indexed logs.
- Web Interface: Allows user access and interaction with the system.
- Attacker: Connects via SSH on port 22 to attempt attacks.

### Security Measures:

- Real-time Monitoring: Continuous monitoring for suspicious activities.
- Alerting: Immediate alerts for potential brute force attacks, including details like source IP, targeted accounts, and failed attempts.
- Response: Security analysts can block the attacker’s IP and take additional measures to protect the system.

## Steps
### 1. Security Side: Using Splunk Enterprise for Monitoring and Alerts
### 1.1 Environment Setup

CentOS Virtual Machine Configuration
<ul>
  <li>Operating System: CentOS Linux 7</li>
  <li>Virtualization Platform: VMware Workstation</li>
  <li>Network Configuration: NAT</li>
  <li>IP Address: 192.168.80.161</li>
  <li>System Specifications:
    <ul>
      <li>Memory: 1 GB</li>
      <li>Processor: 1 Core</li>
      <li>Hard Disk: 50 GB</li>
    </ul>
  </li>
</ul>

The CentOS virtual machine serves as the host for Splunk Enterprise, providing a stable environment for monitoring and security analysis.

 <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/e34d9378-e542-46fb-bcb5-0d185a40dbd9c" width="800" height="400" /></div>

   Fig 2: Centos Linux Intstalled on Vmware Workstation

### 1.2 Installation and Configuration of Splunk Enterprise

#### Network Interface Activation and SSH Access

  1. Activate Network Interface:
     
            ifup ens33

  2. Establish SSH Connection: Utilize Putty to SSH into the CentOS virtual machine using IP address 192.168.80.161.

     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/38591fd8-284c-4ac4-84d9-3c422134848d" width="800" height="400" /></div>

        Fig 3: Putty through SSH(port:22)

#### Root User Account Creation

  1. Create Root User Account:

         sudo useradd lunar
         sudo passwd lunar
         sudo usermod -aG wheel lunar

     <ul>
        <li>Username: lunar</li>
        <li>Password: LNar19@</li>
     </ul>  
     <br>

     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/3b41f89e-cb10-4920-98ec-48a4def96443" width="800" height="400" /></div>

        Fig 4: Creating an root user account named 'lunar'

  2. Create Exploitable Directories and Files:

     <ul>
        <li>Directories: "Personal_Doc" and "Client_Projects"</li>
        <li>Purpose: To simulate sensitive data for monitoring.</li>
     </ul>  
          <br>

     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/21e3b293-30f5-49c0-ae08-3e81c9d0c97c" width="500" height="200" /></div>

        Fig 5: Exploitable files under 'lunar' account

#### Installing Splunk Enterprise

 1. Download Splunk Enterprise:
    
     <ul>
        <li>Obtain the download link from the <a href="https://www.splunk.com">Splunk Website</a>.</li>
     </ul>  
     <br>
     
     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/fd69998c-87bc-4917-a521-1adfe9f3d09f" width="800" height="400" /></div>
 
    Fig 6: Copying 'Splunk Enterprise' download link from Splunk Website

2. Installation Commands:

       wget -O splunk-8.2.4-87e2dabb1c2a-Linux-x86_64.tgz [download-link]
       tar -xvf splunk-8.2.4-87e2dabb1c2a-Linux-x86_64.tgz -C /opt
   
     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/6fd9b533-de00-49b5-bdf3-d92a82cdd584" width="800" height="430" /></div>

     Fig 7: Installing ‘Splunk Enterprise’

 3. Start Splunk and Accept License:

        /opt/splunk/bin/splunk start --accept-license

    <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/b1fd705c-23e6-4417-802f-f176c57bf316" width="500" height="250" /></div>

    Fig 8: Activation 'Splunk Enterprise'

### 1.3 Monitoring and Data Input

#### Accessing Splunk Enterprise

   <ul>
        <li>Login: Open a web browser and navigate to http://192.168.80.161:8000. Use the default login credentials created during Splunk setup.</li>
     </ul>  

<div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/7eed21fc-bf38-4e0e-98af-0e00ede6f204" width="800" height="300" /></div>

Fig 9: ‘Splunk Enterprise’ login form

#### Adding Data for Monitoring

 1. Add Monitoring Directory:

        /opt/splunk/bin/splunk add monitor /var/log

    <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/a1326940-1cce-40f0-92ca-e372860c8064" width="500" height="150" /></div>

    Fig 10: Adding data to Splunk environment

2. Verify Data Input:

     <ul>
        <li>Navigate to the Data Summary in Splunk to ensure /var/log is being monitored.</li>
     </ul>  
     <br>
    <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/04f5aca7-9a1e-4c12-b6b6-18921641d173" width="800" height="400" /></div>

    Fig 11: Checking the monitoring data

### 1.4 Alert Configuration

The Splunk dashboard shown in the image provides a detailed view of various logs and their sources, which can be used to configure alerts for different security events. Based on the provided information, four specific alerts have been configured, likely using the signatures of the logs shown in the dashboard:
1.	Brute Force Attack Detection
2.	External Login Attempt Detection
3.	File Transfer via SSH Detection
4.	Root Password Unauthorized Access Detection

#### 1. Brute Force Attack Detection

 1. Search Query

        host="localhost.localdomain" "/var/log/audit/audit.log" res=failed

 2. Alert Settings:

     <ul>
        <li>Trigger: More than five failed login attempts within one minute.</li>
     </ul> 
     <br>
     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/64570252-f799-42fb-9514-5a82288da02c" width="500" height="250" /></div>

     Fig 12: Splunk Processing Language of Brute Force Attack alerts

    <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/1437e9a7-ee8b-42cf-84e2-1c4417934d31" width="500" height="380" /></div>

    Fig 13: Configuration of Brute Force Attack alert(1)

    <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/91a08445-b97f-4961-b597-138bc3b96436" width="500" height="380" /></div>

    Fig 14: Configuration of Brute Force Attack alert(2)

    The Brute Force Attack alert in Splunk monitors failed login attempts from `localhost.localdomain` in the `/var/log/audit/audit.log` file where the result is marked as "failed." Named "Brute Force Attack," the alert highlights multiple failed password attempts. It triggers in real-time, remains active for 24 hours, and activates when more than five failed login attempts occur within one minute. A 60-second throttle prevents frequent alerts. With a critical severity level, this setup ensures timely detection and response to brute force attacks, enhancing system security.

#### 2. External Login Attempt Detection

 1. Search Query

        host="localhost.localdomain" "/var/log/audit/audit.log" Protocols=ssh2 AoF=Accepted user_access=192.168.80.152

 2. Alert Settings:

     <ul>
        <li>Trigger: Each event matching the search query.</li>
     </ul> 
     <br>
     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/1de2bd61-d4bf-4ce2-b021-3d24e8394d39" width="500" height="180" /></div>

     Fig 15: Splunk Processing Language of External Login Attack alerts

     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/6d721e9a-bfe6-46c3-9b17-ff0a4bb7aa9f" width="500" height="380" /></div>

     Fig 16: Configuration of External Login Attempt alert(1)

     <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/4be8ddf9-76eb-4810-955c-da0434abdba7" width="500" height="380" /></div>

     Fig 17: Configuration of External Login Attempt alert(2)

    The External Login Attempt alert in Splunk monitors external login attempts by filtering logs from the host `localhost.localdomain` within the `/var/log/secure` file, specifically for SSH protocol events where user access is accepted from the IP address `192.168.88.152`. Named "External Login Attempt," the alert emphasizes the importance of detecting external logins to user accounts. It triggers in real-time, remains active for 24 hours, and activates for each event that matches the search query. With a critical severity level, this setup ensures timely detection and response to unauthorized external login attempts, enhancing system security.

#### 3. File Transfer via SSH Detection

 1. Search Query

         host="localhost.localdomain" "/var/log/audit/audit.log" file_access "/usr/libexec/openssh/sftp-server"

 2. Alert Settings:

      <ul>
         <li>Trigger: Each event matching the search query.</li>
      </ul> 
     <br>
      <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/f4146f07-6691-44bb-b9b6-84eed803fb78" width="500" height="180" /></div>

      Fig 18: Splunk Processing Language of File Tranfer via SSH alerts

      <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/8e423feb-a1bd-41d0-89bc-81fd1f7ce7e0" width="500" height="380" /></div>

      Fig 19: Configuration of File Tranfer via SSH alert(1)

      <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/bdbe2cd8-3acd-4131-97c5-b08c9fec7a15" width="500" height="380" /></div>

      Fig 20: Configuration of File Tranfer via SSH alert(2)

    The File Transfer via SSH alert in Splunk monitors for file access events involving the SFTP server by filtering logs from the host `localhost.localdomain` within the `/var/log/audit/audit.log` file, specifically looking for the execution of `/usr/libexec/openssh/sftp-server`. Named "File Transfer via SSH," the alert highlights the significance of file transfers, especially following a brute force attack, indicating a potential security breach. It triggers in real-time, remains active for 24 hours, and activates for each event that matches the search query. With a medium severity level, this setup ensures timely detection and response to potential unauthorized file transfers, enhancing system security.

#### 4. Root Password Unauthorized Access Detection

 1. Search Query

         host="localhost.localdomain" "/var/log/audit/audit.log" acct=root addr!=192.168.80.161 res=success

 2. Alert Settings:

      <ul>
         <li>Trigger: Each event matching the search query.</li>
      </ul> 
     <br>
      <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/3c89e66e-be27-4011-ba7f-4d1225169471" width="500" height="150" /></div>

      Fig 21: Splunk Processing Language of Root Password Unauthorized Access alerts

      <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/c9faca05-7675-470d-974c-b7eeaa00b8f6" width="500" height="380" /></div>

      Fig 22: Configuration of Root Password Unauthorized Access alert(1)

      <div><img src="https://github.com/Rollan19/Securing-Networks-By-Leveraging-Splunk/assets/157499734/4345fae4-5562-4bdd-b261-4f5db53e3337" width="500" height="380" /></div>

      Fig 23: Configuration of Root Password Unauthorized Access alert(2)

    The "Root Password Unauthorized Access" alert in Splunk monitors successful root logins from any IP address other than `192.168.80.161` by filtering logs from the host `localhost.localdomain` within the `/var/log/audit/audit.log` file. Named "Root Password Unauthorized Access," the alert triggers in real-time, remains active for 24 hours, and activates when more than three successful root login attempts occur within a 10-minute window. A 60-second throttle prevents alert flooding. With a critical severity level, this setup ensures timely detection and response to unauthorized root access attempts, enhancing system security.

### 2. Attacker Side: Performing Brute Force Attacks with Hydra

#### 2.1. Kali Linux Setup

Kali Linux is installed on VMware Workstation with the following configuration:

   <ul>
    <li>Memory: 1 GB</li>
    <li>Processor: 2</li>
    <li>Hard Disk: 30 GB</li>
    <li>IP Address: 192.168.80.152 (NAT configuration)</li>
   </ul>

This Kali Linux machine is used to perform a brute force attack on a CentOS virtual machine via SSH port 22 to gain unauthorized access.

<div><img src="https://github.com/user-attachments/assets/c0d025d7-c405-4de0-8d46-0a0e48050588" width="800" height="400" /></div>

Fig 24: Kali Linux Installed on Vmware Workstation

#### 2.2. Network Scanning with nmap

`nmap -A 192.168.80.161`

A network scan using the nmap command on IP address 192.168.80.161 reveals open ports. The scan identifies port 22/tcp running the SSH service with OpenSSH version 7.4.

<div><img src="https://github.com/user-attachments/assets/c946cea9-035f-4568-8cd3-22c4d8c2d33e" width="600" height="400" /></div>

Fig 25: Port scanning with 'nmap'

#### 2.3. Brute Force Attack with Hydra

A brute force attack is executed using the hydra tool with the following command:

`hydra -L username.txt -P password.txt -f ssh://192.168.80.161`

username.txt: The username list comprises potential usernames that could be used in a brute force attack on a CentOS system. Each entry represents a common or plausible username that might be configured on the target system. The list is exhaustive and includes variations to increase the likelihood of a successful breach.

password.txt: The password list contains potential passwords that could be used in a brute force attack on a CentOS system. Each entry represents a common or plausible password that might be set on the target system. To increase the chances of a successful breach, the list is comprehensive and includes variations.

<div><img src="https://github.com/user-attachments/assets/849b278a-26cd-4244-a06f-c4f026205b84" width="550" height="400" /></div>

Fig 26: Implementating Brute Force attack using 'hydra'

Hydra successfully identifies valid credentials:

<ul>
    <li>Username: lunar</li>
    <li>Password: LNar19@</li>
  </ul>


  
#### Brute Force Attack Alert on SPLUNK:

<ul>
    <li>Trigger Condition: More than five failed login attempts within a one-minute window.</li>
    <li>Action: Hydra's multiple login attempts trigger this alert.</li>
  </ul>

#### External Login Attempt Alert:

<ul>
    <li>Trigger Condition: Unauthorized access detected.</li>
    <li>Action: Successful login with compromised credentials triggers this alert.</li>
  </ul>

<div><img src="https://github.com/user-attachments/assets/3e3c907d-743a-443e-b4ac-b2bf1f57f424" width="800" height="200" /></div>

Fig 27: Triggered 'Brute Force Attack' alerts

#### 2.4. Unauthorized Access and Data Discovery

After gaining access using the compromised credentials, the attacker logs into the target machine and finds sensitive directories:

<ul>
    <li>Directories: "Client_Projects" and "Personal_Doc"</li>
  </ul>

<div><img src="https://github.com/user-attachments/assets/14410e2c-7332-4b68-8092-f6d73c121921" width="600" height="170" /></div>

Fig 28: 2 files on the victim

#### 2.5. Data Exfiltration

The attacker uses the scp command to download sensitive files:

<ul>
    <li>Command: scp username@192.168.80.161:/path/to/directory /local/directory</li>
    <li>Alerts Triggered: "File Transfer via SSH" alerts for each file transfer.</li>
  </ul>

<div><img src="https://github.com/user-attachments/assets/2eb844c1-5db9-4291-a62d-36174481c05c" width="500" height="350" /></div>

Fig 29: File tranfering using 'scp' command

<div><img src="https://github.com/user-attachments/assets/9012fe74-ce8a-43d9-bed8-ad9d0dba9ccb" width="800" height="200" /></div>

Fig 30: Triggered 'File Tranfer via SSH' alerts

### Sequence of Events

  <ul>
    <li>
        <strong>Brute Force Attack Initiation:</strong>
        <ul>
            <li>Time: Around 21:40 +07</li>
            <li>Action: Hydra attempts multiple login combinations against the SSH service.</li>
        </ul>
        <br>
    </li>
    <li>
        <strong>Successful Credential Compromise:</strong>
        <ul>
            <li>Time: 21:41 +07</li>
            <li>Action: Hydra identifies valid credentials.</li>
        </ul>
        <br>
    </li>
    <li>
        <strong>Unauthorized Access:</strong>
        <ul>
            <li>Time: 21:41:24 +07</li>
            <li>Action: Attacker logs into the target machine.</li>
            <li>Alert: "External Login Attempt" alert triggered.</li>
        </ul>
        <br>
    </li>
    <li>
        <strong>Initial Data Discovery:</strong>
        <ul>
            <li>Time: Shortly after 21:41 +07</li>
            <li>Action: Attacker finds sensitive directories.</li>
        </ul>
        <br>
    </li>
    <li>
        <strong>Data Exfiltration – First Transfer:</strong>
        <ul>
            <li>Time: 21:44:32 +07</li>
            <li>Action: Attacker uses scp to download "Client_Projects" directory.</li>
            <li>Alert: "File Transfer via SSH" alert triggered.</li>
        </ul>
        <br>
    </li>
    <li>
        <strong>Continued Unauthorized Access:</strong>
        <ul>
            <li>Time: 21:44:37 +07</li>
            <li>Action: Further unauthorized login attempts.</li>
            <li>Alert: Another "External Login Attempt" alert triggered.</li>
        </ul>
        <br>
    </li>
    <li>
        <strong>Data Exfiltration – Second Transfer:</strong>
        <ul>
            <li>Time: 21:44:35 +07 and 21:45:28 +07</li>
            <li>Action: Attacker uses scp to download "Personal_Doc" directory.</li>
            <li>Alert: Additional "File Transfer via SSH" alerts triggered.</li>
        </ul>
        <br>
    </li>
    <li>
        <strong>Subsequent Unauthorized Access:</strong>
        <ul>
            <li>Time: 21:45:26 +07</li>
            <li>Action: Another unauthorized login attempt.</li>
            <li>Alert: Another "External Login Attempt" alert triggered.</li>
        </ul>
        <br>
    </li>
</ul>

<div><img src="https://github.com/user-attachments/assets/3eddd9b2-6c32-49a7-af11-be3c21693319" width="800" height="300" /></div>

Fig 31: Brute force attack detection

<div><img src="https://github.com/user-attachments/assets/0159fb92-8847-4a41-820d-fff7a83761b2" width="800" height="300" /></div>

Fig 32: Unauthorized access detection

<div><img src="https://github.com/user-attachments/assets/33ee994b-589f-4bb0-94d9-897450087f89" width="800" height="300" /></div>

Fig 33: Data exfiltration detection

### Evaluation
The implementation of Splunk for real-time monitoring and alerting is highly effective. Splunk's ability to detect and alert on security incidents such as brute force attacks, unauthorized access, and data theft in real-time ensures that potential threats are identified promptly, allowing for immediate response and mitigation.

### Conclusion
This project demonstrates that using Splunk for real-time monitoring and alerting significantly enhances the security infrastructure of a CentOS environment by providing timely detection and response to security incidents.

