# CIS_Checker

CIS_Checker automates the process of evaluating the compliance of AWS environments against the latest CIS 4.0.0 benchmarks.

## Key Features:
***Automated Compliance Checks:*** Automatically evaluates various AWS resources against best practices.

***Customizable AWS Profiles:*** Supports running checks against multiple AWS profiles, allowing for flexible assessments.

***Detailed Reporting:*** Generates comprehensive reports in both JSON and HTML formats.

***Screenshot Functionality:*** Captures and stores screenshots of failed checks, providing visual evidence of compliance status.

***Paginator Support:*** Efficiently handles large datasets and responses from AWS services using paginators.

## Requirements:
* Python 3.x
* AWS CLI configured with the necessary access permissions

## Usage:
* Configure AWS CLI with access keys
* Run the tool with no argument to use a default profile or specify an AWS profile


```
python CIS_Checker.py [--profile PROFILE_NAME] [--check "1.8,1.4"] [--html-only]
```

The tool will perform a series of compliance checks and generate a report outlining the compliance status of the AWS resources. Screenshots of non-compliant items and detailed JSON and HTML reports are saved for further analysis and record-keeping.


## Examples

<img width="1117" alt="Screenshot 2023-12-01 at 12 46 46 PM" src="https://github.com/Michaeladsl/CIS_Checker/assets/89179287/c8c34ce2-a31a-40b9-a1c6-8329841e4a44">
<img width="1203" alt="Screenshot 2023-12-01 at 12 50 16 PM" src="https://github.com/Michaeladsl/CIS_Checker/assets/89179287/700fa128-9733-4606-b727-34efb0f85d2f">


