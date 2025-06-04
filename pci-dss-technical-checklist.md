# PCI DSS v4.0.1 Technical Assessment Checklist

## Pre-Assessment Information Gathering

### Environment Overview
- [ ] Request network topology diagrams
- [ ] Identify all cardholder data flows
- [ ] List all system components in scope
- [ ] Identify all payment channels (card-present, e-commerce, etc.)
- [ ] Document all third-party connections

### Key Questions:
- What payment card brands do you accept?
- What is your merchant level?
- Do you store, process, or transmit cardholder data?
- Where is cardholder data stored (databases, files, logs, backups)?
- What is your transaction volume?

---

## Requirement 1: Network Security Controls

### Firewall Configuration Review
- [x] Review firewall ruleset configurations
- [x] Verify "deny all" default rule
- [x] Check for any "any-any" rules
- [ ] Review NAT and port forwarding rules
- [ ] Verify stateful inspection is enabled
- [ ] Check anti-spoofing measures
- [ ] Logs
- [ ] Firewall rules to Database

### Network Segmentation
- [ ] Verify CDE network segmentation
- [ ] Review DMZ configuration
- [ ] Check VLAN configurations
- [ ] Test segmentation effectiveness
- [ ] Review internal network zones

### Technical Questions:
1. **Firewall Infrastructure:**
   - What firewall vendors/models are in use?
   - How many firewalls protect the CDE?
   - Are firewalls configured in HA/cluster mode?
   - What is the current firmware version?

2. **Network Architecture:**
   - Is the CDE on a separate network segment?
   - How is traffic between CDE and non-CDE controlled?
   - Are there any direct connections from the internet to the CDE?
   - What protocols/ports are allowed into the CDE?

3. **Rule Management:**
   - How often are firewall rules reviewed?
   - Show me rules allowing inbound traffic to CDE
   - Show me rules for outbound traffic from CDE
   - Are there any temporary rules currently active?

### Evidence to Request:
- Firewall configuration files
- Current firewall rulesets
- NAT translation tables
- Connection statistics
- Anti-spoofing configuration

---

## Requirement 2: Secure Configurations

### System Hardening
- [ ] Review OS hardening standards
- [ ] Check for unnecessary services
- [ ] Verify default accounts are disabled/renamed
- [ ] Review file system permissions
- [ ] Check registry/kernel parameters
- [ ] Verify secure protocols only (no telnet, FTP, etc.)

### Technical Questions:
1. **Configuration Standards:**
   - What hardening standards do you follow (CIS, DISA STIG)?
   - Show me the baseline configuration for [Windows/Linux] servers
   - How do you ensure consistency across systems?

2. **Default Accounts:**
   - Have all vendor default passwords been changed?
   - Show me how you check for default accounts
   - Are there any shared/generic accounts in use?

3. **Services and Protocols:**
   - What method is used to identify unnecessary services?
   - Show me running services on a sample CDE system
   - How is remote administrative access secured?

### Evidence to Request:
- List of enabled services on all CDE systems
- Network listening ports on all systems
- User account listings showing all local accounts
- Evidence of disabled default accounts
- System hardening documentation/checklists

---

## Requirement 3: Stored Data Protection

### Data Discovery and Classification
- [ ] Identify all CHD storage locations
- [ ] Review database encryption
- [ ] Check file-level encryption
- [ ] Verify key management procedures
- [ ] Review data retention policies
- [ ] Check for sensitive authentication data

### Technical Questions:
1. **Data Storage:**
   - Where is cardholder data stored (databases, files, logs)?
   - Show me the data flow diagram
   - Is there any CHD in non-production environments?
   - How do you search for unencrypted CHD?

2. **Encryption:**
   - What encryption methods are used (TDE, column-level, file-level)?
   - What encryption algorithms and key lengths are used?
   - Where are encryption keys stored?
   - How are keys rotated?

3. **Data Retention:**
   - What is your CHD retention period?
   - How is CHD securely deleted?
   - Show me the data purging process

### Evidence to Request:
- Database schema showing all tables/columns containing card data
- Database encryption status reports
- Results of data discovery scans
- Encryption key inventory and key management procedures
- Data retention and deletion logs
- Evidence of secure deletion processes

---

## Requirement 4: Encryption in Transit

### Network Encryption
- [ ] Review TLS/SSL configurations
- [ ] Check cipher suites and protocols
- [ ] Verify certificate management
- [ ] Review VPN configurations
- [ ] Check wireless encryption

### Technical Questions:
1. **TLS Configuration:**
   - What TLS versions are supported?
   - Show me the allowed cipher suites
   - How are certificates managed?
   - When do certificates expire?

2. **Data Transmission:**
   - How is CHD transmitted between systems?
   - Are there any unencrypted transmission channels?
   - How is data transmitted to third parties?

### Evidence to Request:
- TLS/SSL configuration files
- List of supported cipher suites and protocols
- Certificate inventory with expiration dates
- Network encryption topology showing all encrypted channels
- VPN configuration if used for CHD transmission

---

## Requirement 5: Anti-malware Protection

### Anti-malware Deployment
- [ ] Verify anti-malware on all systems
- [ ] Check for real-time protection
- [ ] Review update mechanisms
- [ ] Check scanning schedules
- [ ] Verify centralized management

### Technical Questions:
1. **Anti-malware Coverage:**
   - What anti-malware solution is deployed?
   - Show me systems without anti-malware
   - How do you ensure all systems are protected?

2. **Configuration:**
   - Is real-time scanning enabled?
   - How frequently are signatures updated?
   - Can users disable anti-malware?
   - Show me the anti-malware policy

### Evidence to Request:
- Anti-malware deployment status report
- Anti-malware policy configuration
- Signature update logs showing update frequency
- Scan schedules and recent scan results
- Central management console screenshots

---

## Requirement 6: Secure Development

### Application Security
- [ ] Review secure coding practices
- [ ] Check for security testing
- [ ] Verify change control process
- [ ] Review code review procedures
- [ ] Verify WAF deployment and configuration

### Web Application Firewall (WAF) - Requirement 6.4
- [x] Verify WAF is deployed for all public-facing web applications
- [x] Check WAF is actively running and up-to-date
- [ ] Review WAF rule sets and configurations
- [ ] Verify WAF is generating audit logs
- [x] Check if WAF is in blocking or detection mode
- [ ] Review WAF alerting mechanisms
- [ ] Verify WAF covers OWASP Top 10 and PCI DSS 6.2.4 vulnerabilities

### Technical Questions:
1. **Development Practices:**
   - Do you have custom applications handling CHD?
   - What secure coding standards are followed?
   - How is code reviewed before production?
   - Show me your SAST/DAST reports

2. **Web Application Security & WAF (Requirement 6.4):**
   - List all public-facing web applications that handle CHD
   - What WAF solution is deployed (vendor/version)?
   - Is the WAF in blocking mode or detection-only mode?
   - Show me the WAF configuration and rule sets
   - How often are WAF rules updated?
   - Show me WAF logs and recent blocked attacks
   - How are WAF alerts handled and investigated?
   - Does the WAF protect against all vulnerabilities in Requirement 6.2.4?
   - Are there any WAF bypasses configured?
   - How is the WAF protected from being bypassed?

3. **Change Management:**
   - Show me the change control process for production
   - How are security impacts assessed?
   - Is there separation between dev/test/prod?

### Evidence to Request:
- WAF configuration files and rule sets
- WAF operational mode settings (blocking vs detection)
- Recent WAF logs showing blocked attacks
- WAF rule update history
- WAF performance and availability reports
- Evidence that WAF cannot be bypassed

### WAF Configuration Checklist:
- [ ] WAF is deployed in front of ALL public-facing web applications
- [ ] WAF is configured in blocking mode (not just detection)
- [ ] WAF rules are updated regularly (check last update date)
- [ ] WAF protects against:
  - [ ] SQL injection attacks
  - [ ] XSS attacks
  - [ ] LDAP/XML/command injection
  - [ ] Buffer overflow attacks
  - [ ] Path traversal attacks
  - [ ] Remote file inclusion
  - [ ] Security misconfiguration exploits
- [ ] WAF logs are sent to centralized logging
- [ ] WAF alerts are actively monitored
- [ ] WAF cannot be bypassed (no direct access to web servers)
- [ ] WAF performance is monitored
- [ ] WAF failover/high availability is configured

---

## Requirement 7: Access Control

### Access Management
- [ ] Review access control systems
- [ ] Verify role-based access control
- [ ] Check least privilege implementation
- [ ] Review access provisioning process
- [ ] Verify periodic access reviews

### Technical Questions:
1. **Access Control Systems:**
   - What systems control access (AD, LDAP, RBAC)?
   - Show me the access control matrix
   - How is "need to know" enforced?
   - Is the default "deny all"?

2. **User Access:**
   - Show me users with access to CHD
   - How is privileged access managed?
   - Are there any shared accounts?

### Evidence to Request:
- Active Directory or LDAP user listings with group memberships
- Access control matrix documentation
- Administrator and privileged user listings
- Evidence of access reviews and approvals
- Service account inventory and permissions

---

## Requirement 8: Authentication

### Identity Management
- [ ] Verify unique user IDs
- [ ] Check password policies
- [ ] Review MFA implementation
- [ ] Verify account lockout settings
- [ ] Check session timeout settings

### Technical Questions:
1. **Authentication Methods:**
   - What authentication mechanisms are used?
   - Show me the password policy settings
   - Where is MFA implemented?
   - How are service accounts managed?

2. **Password Controls:**
   - What is the minimum password length?
   - Is password history enforced?
   - Show me the account lockout policy
   - How often are passwords changed?

3. **MFA Implementation:**
   - What MFA solution is used?
   - Show me MFA configuration for CDE access
   - Is MFA required for remote access?

### Evidence to Request:
- Password policy configuration from all systems
- Account lockout policy settings
- MFA configuration and deployment status
- List of accounts with/without MFA
- Session timeout configurations
- Evidence of password history enforcement

---

## Requirement 9: Physical Security

### Physical Access Controls
- [ ] Review facility entry controls
- [ ] Check badge access systems
- [ ] Verify visitor procedures
- [ ] Review camera coverage
- [ ] Check media controls

### Technical Questions:
1. **Facility Security:**
   - Show me the data center/server room
   - What physical access controls are in place?
   - How is access to network equipment restricted?
   - Are there cameras monitoring sensitive areas?

2. **Media Handling:**
   - How is removable media controlled?
   - Show me media destruction procedures
   - Is there an inventory of media with CHD?

3. **Device Security:**
   - How are POI devices protected?
   - Show me the POI device inventory
   - How often are devices inspected?

---

## Requirement 10: Logging and Monitoring

### Log Management
- [ ] Verify comprehensive logging
- [ ] Check log retention
- [ ] Review log protection
- [ ] Verify centralized logging
- [ ] Check time synchronization

### Technical Questions:
1. **Logging Coverage:**
   - What is logged for CDE systems?
   - Show me the logging configuration
   - Are logs centralized? Where?
   - How long are logs retained?

2. **Log Review:**
   - How are logs reviewed?
   - Show me evidence of daily log review
   - What triggers alerts?
   - Is there a SIEM solution?

3. **Time Synchronization:**
   - How is time synchronized?
   - Show me NTP configuration
   - What is the authoritative time source?

### Evidence to Request:
- Logging configuration files from all CDE systems
- Evidence of centralized log collection
- Log retention policies and evidence of enforcement
- Time synchronization configuration
- NTP server configuration and time source documentation
- Audit log samples showing required events are captured

---

## Requirement 11: Security Testing

### Vulnerability Management
- [ ] Review vulnerability scanning reports
- [ ] Check penetration test results
- [ ] Verify wireless scanning
- [ ] Review IDS/IPS deployment
- [ ] Check file integrity monitoring

### Technical Questions:
1. **Vulnerability Scanning:**
   - Show me recent internal scan reports
   - Show me ASV scan reports
   - How are vulnerabilities prioritized?
   - What is the patching timeline?

2. **Penetration Testing:**
   - When was the last pentest?
   - Show me the pentest report
   - Were all findings remediated?
   - Was segmentation tested?

3. **Security Monitoring:**
   - Is IDS/IPS deployed? Show me the configuration
   - What FIM solution is used?
   - Show me alerts from the last week

### Evidence to Request:
- Recent internal and external vulnerability scan reports
- ASV scan passing certificates
- Penetration testing reports (internal and external)
- Evidence of vulnerability remediation
- IDS/IPS configuration and alert samples
- FIM configuration and change detection logs
- Wireless scanning results

---

## Requirement 12: Security Program

### Security Management
- [ ] Review security policies
- [ ] Check incident response plan
- [ ] Verify security awareness program
- [ ] Review risk assessment process
- [ ] Check vendor management

### Technical Questions:
1. **Incident Response:**
   - Do you have an incident response plan?
   - Who is on the incident response team?
   - When was the last incident response test?
   - Show me the communication flowchart

2. **Risk Management:**
   - When was the last risk assessment?
   - Show me the risk register
   - How are risks tracked and mitigated?

3. **Third-Party Management:**
   - List all service providers with CHD access
   - Show me their PCI compliance status
   - How do you monitor their compliance?

---

## Post-Assessment Actions

### Immediate Actions Required:
1. Document all findings with evidence
2. Prioritize critical/high-risk findings
3. Create remediation timeline
4. Schedule follow-up validation

### Report Structure:
1. Executive Summary
2. Scope and Methodology
3. Detailed Findings by Requirement
4. Risk Ratings
5. Remediation Recommendations
6. Appendices with Evidence

### Key Deliverables:
- [ ] Assessment report
- [ ] Finding details with evidence
- [ ] Remediation roadmap
- [ ] Risk assessment matrix
- [ ] Compliance gap analysis