![image](https://github.com/user-attachments/assets/d030b99a-9f49-4dc0-a640-2d79aef14b6e)# Snapped-Phish-ing-Line

![image](https://github.com/user-attachments/assets/d29c2c43-a8c3-49e7-a5c5-af9685025162)

## Personal Project: Analyzing a Phishing Incident Leading to Stolen Credentials


### Scenario: An Ordinary Midsummer Day...

As a member of the IT department at SwiftSpend Financial, one of my responsibilities is to support fellow employees with their technical concerns. What seemed like an ordinary and mundane day quickly turned challenging when several employees from various departments reported receiving unusual emails. Unfortunately, some had already submitted their credentials and could no longer log in.

I began investigating the situation by analyzing the email samples provided by my colleagues, reviewing the phishing URLs, retrieving the phishing kit used by the adversary, and using Cyber Threat Intelligence (CTI) tools to gather more information.

#### 1. Who is the individual who received an email attachment containing a PDF?

To answer this question, I first navigated to the "phish-emails" folder on the desktop, where several emails were stored. I opened the emails using Thunderbird, focusing on the one that had a PDF attachment, which stood out from the others. This email revealed that the individual who received the email attachment containing a PDF was Zoe Duncan.

![image](https://github.com/user-attachments/assets/c4c21435-c2c9-44b9-bfdc-f14169babe0e)

Answer: William McClean

#### 2. What email address was used by the adversary to send the phishing emails?

The same email containing the PDF attachment provided the answer to this question. By carefully examining the email headers and the "From" field, I identified the email address used by the adversary.

Answer: Accounts.Payable@groupmarketingonline.icu

#### 3. What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)

I checked the code of the phishing page attachment sent to Zoe Duncan. The redirection URL was clearly embedded in the HTML source code of the attachment. To ensure safety, I defanged the URL using CyberChef by replacing periods with "[.]" and omitting any clickable elements, making it inoffensive.

![image](https://github.com/user-attachments/assets/8edabeef-3b0e-4304-9baf-bb0422aa21a8)

![image](https://github.com/user-attachments/assets/e4db31c9-afdd-4245-ae5d-fceaf238aad0)


Answer: hxxps://malicious-site[.]com/phishing

#### 4. What is the URL to the .zip archive of the phishing kit? (defanged format)

To find the URL to the .zip archive of the phishing kit, I needed to explore the phishing site further. Using Firefox, I carefully navigated through the site, ensuring I was working within an isolated VM. After some manual enumeration and backtracking, I located the URL pointing to the .zip archive. Again, I used CyberChef to defang the URL.

![image](https://github.com/user-attachments/assets/6bcec2b4-cc16-4bf2-9436-6a13967b42e1)


![image](https://github.com/user-attachments/assets/24743e48-bb96-414c-ab2f-bd32f897b30b)

Answer: hxxps://malicious-site[.]com/phishing-kit.zip

#### 5. What is the SHA256 hash of the phishing kit archive?

After downloading the .zip archive, I used the terminal to generate the SHA256 hash. This process was straightforward and confirmed the integrity of the phishing kit.

![image](https://github.com/user-attachments/assets/8abee242-5e2a-4f77-95ab-2953fa4bc6d5)

Answer: ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686

### 6. When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM
UTC)


With the SHA256 hash in hand, I conducted an OSINT search on VirusTotal to gather more information about the phishing kit. The first submission date was clearly displayed in the search results.

![image](https://github.com/user-attachments/assets/6553e8d9-8389-4812-aa01-c947b8783ea2)

![image](https://github.com/user-attachments/assets/d3bc3887-5ee9-430a-81e0-f62309c822bb)

Answer: 2020-04-08 21:55:50 UTC

#### 7. When was the phishing domain that was used to host the phishing kit archive first registered? (format: YYYY-MM-DD)

The domain in question was "kennaroads.buzz." Since it was no longer registered, a simple WHOIS lookup was not effective. Instead, I used the ThreatBook tool to investigate the domain further, which provided the registration date.

![image](https://github.com/user-attachments/assets/4ed2e725-a56a-4a50-8a37-5761dedc1a68)

Answer: 2020-06-25

### 8. What was the email address used by the adversary to collect compromised credentials?

To answer this question, I extracted the contents of the phishing kit archive and examined the scripts within it. The "submit.php" file contained the code that captured and sent the stolen credentials to the adversary's email address.


![image](https://github.com/user-attachments/assets/cd3a0566-d2db-485c-a37e-7a80ae9ae98c)

![image](https://github.com/user-attachments/assets/9216d3e8-9771-499a-9901-9152438df4ba)



Answer: m3npat@yandex.com

#### 9. The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in “@gmail.com”?

During my analysis of the phishing kit, I also found an additional email address in the "script.sc" file. This email address ended with "@gmail.com."

![image](https://github.com/user-attachments/assets/a151f1ae-1c07-45ab-869f-1d4d348f9e5a)

Answer: jamestanner2299@gmail.com

#### 10. What is the hidden flag?

The final challenge involved finding a hidden flag within the phishing URL. After some careful enumeration, I located the encoded flag within the URL. I used CyberChef to decode it from base64 and reversed it to match the typical TryHackMe flag format.

![image](https://github.com/user-attachments/assets/7a6565d7-7d5e-47a7-95d1-60f78ef13d59)

![Screenshot from 2024-08-31 01-17-06](https://github.com/user-attachments/assets/2ed87063-edcd-4626-b5fe-a2e4ba596941)

Answer: THM{pL4y_w1Th_tH3_URL}


#### Experience Gained and Benefits

This project enhanced my ability to analyze phishing incidents comprehensively, from examining email headers to deconstructing phishing kits. I learned the importance of meticulous investigation and the use of OSINT tools to gather detailed information about threats. The benefits of this experience include improved incident response skills, a deeper understanding of phishing tactics, and the ability to better protect organizations from similar attacks in the future.

#### Conclusion

Through this project, I gained hands-on experience in analyzing phishing emails and understanding how attackers craft phishing kits to steal sensitive information. The process of defanging URLs, verifying hash values, and using CTI tools like VirusTotal and ThreatBook was invaluable in tracking down and identifying the adversary's methods. Additionally, the importance of working within a secure, isolated environment was reinforced, ensuring that the investigation could proceed without risking further compromise.
