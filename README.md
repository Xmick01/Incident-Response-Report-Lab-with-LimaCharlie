# Incident Response Report Lab with LimaCharlie (Wevtutil.exe Abuse)

## Objective

This project simulates a real-world incident involving the misuse of wevtutil.exe to demonstrate the capabilities of LimaCharlie as an endpoint detection and response (EDR) tool. The primary objective is to enhance incident detection and response strategies by understanding how legitimate tools can be leveraged for malicious purposes
## Steps and Components

### 1. Setup Overview
- **Windows VM:** Client machine that will simulate suspicious activity involving `wevtutil.exe`.
- **Ubuntu VM:** SOC monitor with LimaCharlie deployed for incident detection and response.
- **LimaCharlie:** Used for endpoint detection and response (EDR) to monitor and respond to the incident

![instances](https://github.com/user-attachments/assets/5a35a1de-7d81-448b-adac-1f6efa796679)

* Install LimaCharlie agent on Windows instance.
  ![limacharlie windows installation 2](https://github.com/user-attachments/assets/4b691068-a45e-42ba-bdb8-730869d9a74d)
  ![limacharlie windows installation 3](https://github.com/user-attachments/assets/757d638f-6623-4fa5-a11a-a5ec667599b9)
  ![limacharlie windows installation complete](https://github.com/user-attachments/assets/545343bf-0254-4ee0-8479-a097d7169e2a)

* Install LimaCharlie agent on Ubuntu instance.
![limacharlie ubuntu installation 1 ](https://github.com/user-attachments/assets/df02ed84-2f2f-4dc2-b8d1-671a5f327371)
![limacharlie ubuntu installation ](https://github.com/user-attachments/assets/9e4253ce-85bd-4938-9dd5-6d77aa2eb676)
![limacharlie ubuntu installation complete ](https://github.com/user-attachments/assets/73953033-ff19-4f63-accf-2331120574fd)

* The LimaCharlie agents' role is to monitor and alert for suspicious activities.

### 2. Incident Simulation
- **Attack Vector:** The simulation will involve suspicious use of `wevtutil.exe`, a legitimate Windows tool often misused by attackers to clear event logs or access event data for malicious purposes.
  - On the Windows VM, run the following command to simulate suspicious activity:
    ```bash
    wevtutil cl System
    ```
    This command clears the System event log, which is highly suspicious and often indicates an attempt to cover tracks.
  
- **Task:** Use LimaCharlie to detect this activity and isolate the Windows machine once the misuse of `wevtutil.exe` is identified.

  ![wevtutil executed over and over again](https://github.com/user-attachments/assets/29185738-4cde-46e0-ad55-5dd94a022458)

### 3. Data Collection and Analysis
- **Using LimaCharlie:**
  - Monitor for unusual command execution, such as the use of `wevtutil.exe` to clear event logs.
  - Collect relevant event logs and process information before the logs are cleared.
  - Use the EDR’s detection capabilities to identify malicious behavior and trigger an alert.

![logs wevtutil](https://github.com/user-attachments/assets/b54a633e-22ce-4256-85c2-8e30ffdc12f1)


* LimaCharlie will note whether the wevtutil usage is suspicous or not. It gives you the option to mark the event as a false positive as well. This is useful because wevtutil itself is not a malicious program, but it can be used maliciously.
![suspicious wevtutil usage](https://github.com/user-attachments/assets/c8cc192f-8c39-4704-973b-84f7595b719a)

* Notably, when the hash file was submitted to VirusTotal, it was identified as benign. However, LimaCharlie flagged the file as suspicious, demonstrating that while VirusTotal can be a valuable tool in incident response, it should not be relied upon as the sole method of detection. Utilizing multiple tools ensures a more comprehensive analysis, as attackers may use techniques to evade detection by certain platforms
![virustotal scan of wetv](https://github.com/user-attachments/assets/451e4899-f40f-4802-acad-1da37c4f0761)
- **Artifacts to Collect:**
  - Event logs: Before they are cleared, collect logs to identify potential signs of compromise.
  - Process execution: Collect details of the `wevtutil.exe` process and command-line arguments.
  - Network activity: Examine any external connections that might indicate exfiltration attempts.
  - LimaCharlie logs and alerts generated by this activity.

![malicous wetvutil exe](https://github.com/user-attachments/assets/52df02b6-08d6-4306-8214-586175f5dcb8)

### 4. Incident Response Steps
- **Detection:** Detect the abnormal use of `wevtutil.exe` using LimaCharlie.
- **Isolation:** Isolate the Windows VM after detecting the malicious activity.
- **Data Collection:** Retrieve event logs and details from LimaCharlie before the logs are cleared.
- **Analysis:** Analyze the artifacts to determine if the `wevtutil.exe` misuse was part of a larger attack chain (e.g., clearing logs to cover up malicious activity).
- **Mitigation:** Apply containment measures, such as isolating the machine and removing any malicious processes.

* At first glance, wevtutil.exe appeared benign and did not initially seem to justify isolating the Windows instance. However, upon noticing multiple executions of the cl command, it became apparent that isolation was necessary for further investigation. The repeated clearing of event logs may indicate an attempt to cover up a larger attack, warranting deeper analysis.
![isolated windows](https://github.com/user-attachments/assets/6ad054bc-c71a-4ee2-8c42-fcc3dc10ea8e)

### 5. Creating the Incident Response Report
- **Executive Summary:** Provide a high-level summary of the incident involving the suspicious use of `wevtutil.exe`, its potential impact, and the steps taken to mitigate it.
- **Detection and Investigation:** Detail the LimaCharlie logs and alerts that flagged the misuse of `wevtutil.exe` and include any other abnormal findings from event logs, processes, or network traffic.
- **Root Cause Analysis:** Analyze why and how the event log clearing occurred and whether it was part of a larger attack strategy.
- **Mitigation Steps:** Document the actions taken, such as isolating the affected system and identifying the malicious process.
- **Lessons Learned:** Suggest improvements in monitoring, detection, or policy to prevent future incidents involving misuse of legitimate tools like `wevtutil.exe`.
- **Artifacts Collected:** Include a list of event logs, process information, network activity, and LimaCharlie alerts that were collected during the investigation.












# **Incident Response Report**

- **Incident Date:** October 13, 2024
- **Reported By:** Xarius (SOC Analyst)
- **Affected System:** Windows Instance (`EC2AMAZ-H6D1H61`)
- **Incident Summary:** Malicious log clearing activities were detected on the Windows instance using `wevtutil.exe`. The log clearing behavior aligns with MITRE ATT&CK **Sub-technique T1070.001** (Indicator Removal on Host: Clear Windows Event Logs), potentially indicating an attempt to cover up malicious activity.

## **Executive Summary**
On 2024-10-13, multiple suspicious events were detected on the instance `ec2amaz-h6d1h61.us-east-2.compute.internal`, indicating potential malicious activity involving event log clearing and configuration changes. The use of `wevtutil.exe`, a legitimate Windows tool, to clear security logs raises significant concerns, particularly in an environment where monitoring and logging are crucial for detecting unauthorized activities. This behavior aligns with **MITRE ATT&CK Sub-technique T1070.001**.

## **Incident Details**

### Timeline of Events
| Timestamp              | Event Type                                 | Description                                                                                                                                                   |
|------------------------|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2024-10-13 04:29:36    | Suspicious Eventlog Clearing Activity      | Command executed: `wevtutil cl System` to clear the System event log.                                                                                      |
| 2024-10-13 04:30:37    | Suspicious Eventlog Clearing Activity      | Command executed: `wevtutil cl System` (duplicate of previous).                                                                                             |
| 2024-10-13 04:31:09    | Suspicious Eventlog Clearing Activity      | Command executed: `wevtutil cl security` to clear the Security event log.                                                                                   |
| 2024-10-13 05:32:12    | Suspicious Eventlog Clearing Activity      | Command executed: `wevtutil cl security` to clear the Security event log (duplicate).                                                                       |
| 2024-10-13 05:32:27    | Suspicious Eventlog Clearing Activity      | Command executed: `wevtutil cl security` to clear the Security event log again.                                                                             |

**Initial Detection:** 
LimaCharlie’s monitoring flagged suspicious use of `wevtutil.exe` on the Windows instance. LimaCharlie marked the event as suspicious, despite VirusTotal reporting the hash as benign, demonstrating that VirusTotal alone may not be sufficient for incident detection.

**Malicious Activity Summary:**
- The executable `wevtutil.exe` was used to clear both the System and Security logs on the Windows instance.
- The commands were executed under the `Administrator` account (`EC2AMAZ-H6D1H61\Administrator`), which has elevated privileges.
- Multiple instances of the `cl` command were observed, raising suspicion of repeated attempts to cover tracks.

## **Tools and Techniques Used**

- **Tools Involved:**
  - **`wevtutil.exe`:** A legitimate Windows executable for managing event logs. Its usage to clear event logs in this context is suspicious and indicative of potential malicious activity.
  - **`powershell.exe` and `cmd.exe`:** Common command-line tools were used to initiate the event log clearing, further obscuring the activity.

![command line history](https://github.com/user-attachments/assets/247e2856-b670-4298-8c4a-3686db57ff24)

* The command-line history from the Windows instance shows that wevtutile was indeed executed multiple times.

- **MITRE ATT&CK Framework:**
  - **Sub-technique T1070.001** (Indicator Removal on Host: Clear Windows Event Logs) was identified as the relevant tactic used by the attacker to hide evidence of malicious behavior.

## **Event Analysis**

- **User Context:** 
  The commands were executed under the `Administrator` account, which has elevated privileges, indicating the potential misuse of a privileged account.
  
- **Process Details:** 
  The clearing of both System and Security logs was initiated using `powershell.exe` and `cmd.exe`. These command-line tools are common in both administrative and malicious activities, making it harder to detect malicious behavior.

- **Pattern of Activity:**
  Clearing both log types within a short timeframe suggests a deliberate attempt to erase traces of unauthorized actions. The repeated use of the `cl` command to clear logs points to a systematic attempt to cover tracks.

## **Event Correlation**

The suspicious use of `wevtutil.exe` to clear event logs aligns with the MITRE ATT&CK **Sub-technique T1070.001** (Indicator Removal on Host: Clear Windows Event Logs). This technique is commonly used by attackers to erase evidence from system logs after performing unauthorized actions. The repeated clearing of logs indicates an ongoing attempt to hide potentially malicious activities.

## **Potential Impact**

The clearing of logs, especially System and Security logs, severely hampers the ability to detect and respond to incidents. If malicious activity was involved, it could indicate a broader compromise of the `Administrator` account or exploitation of vulnerabilities within the system. Without logs, further malicious activity may have gone unnoticed.

## **Recommendations**

### **Immediate Actions**
1. **Isolate the Windows Instance:** To prevent further malicious activities from occurring.
2. **Preserve Logs and Evidence:** Despite the logs being cleared, other evidence such as memory and disk snapshots should be captured for analysis.
3. **Alert Relevant Teams:** Notify the incident response and forensic teams for further investigation.

### **Further Investigation**
1. **Forensic Analysis:** Perform a full forensic analysis of the Windows instance to determine:
   - User activity leading up to the event log clearing.
   - Any unauthorized external communications.
   - Presence of any additional indicators of compromise (IoCs) on the system.
2. **Review of Network Traffic:** Investigate network traffic for any signs of lateral movement or communication with malicious external addresses.

### **Mitigation Measures**
1. **Enhance Access Controls:** Restrict administrative privileges and ensure only authorized personnel have access to sensitive accounts.
2. **Implement Log Integrity Controls:** Introduce mechanisms that prevent the clearing or tampering of logs without proper authorization and alert the SOC on such actions.
3. **Educate Users:** Provide training for staff on the importance of log integrity and the risks of administrative tools like `wevtutil.exe`.

### **Post-Incident Review**
1. **Root Cause Analysis:** Investigate the root cause of the log clearing incident and document findings.
2. **Update Security Policies:** Adjust incident response plans and security policies based on the findings to prevent similar incidents in the future.
3. **Enhance Monitoring:** Implement specific alerts in LimaCharlie or other monitoring tools for suspicious activity related to event log clearing and administrative tool misuse.
4. **Training and Awareness:** Recommend training for users on recognizing potential security incidents and the importance of log retention.

## **Conclusion**
The event involving the clearing of logs via `wevtutil.exe` represents a significant threat to the security posture of the environment. The behavior matches **MITRE ATT&CK Sub-technique T1070.001**, indicating a deliberate attempt to hide malicious activity by removing log evidence. The incident requires immediate containment, further investigation, and post-incident analysis to determine the full scope of any compromise. Strengthening access controls, implementing better log monitoring, and educating staff on the misuse of administrative tools will help mitigate similar risks in the future.
