# AWS WAF Data Collector

This script collects AWS WAF (Web Application Firewall) data across multiple AWS accounts and organizations. It gathers information about both WAFv1 and WAFv2 resources across all AWS regions.

## Features

- Collects WAFv1 and WAFv2 data
- Supports multiple AWS accounts and organizations
- Gathers data from all AWS regions
- Implements rate limiting to avoid API throttling
- Uses multithreading for improved performance
- Provides comprehensive error handling and logging

## Prerequisites

- Python 3.6 or higher
- boto3 library
- AWS credentials with appropriate permissions

## Installation

1. Clone this repository or download the script.

2. Install the required Python library:

   ```
   pip install boto3
   ```

3. Ensure you have AWS credentials configured. You can do this by:
   - Setting up AWS CLI (`aws configure`)
   - Setting environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
   - Using an AWS credentials file

## Usage

Run the script from the command line with the following syntax:

```
python aws_waf_data_collector.py <role_name> <output_file>
```

- `<role_name>`: The name of the IAM role to assume in each account
- `<output_file>`: The path where the output JSON file should be saved

Example:

```
python aws_waf_data_collector.py WAFDataCollectionRole waf_data_output.json
```

## Output

The script generates a JSON file containing WAF data for all accounts and regions. The structure of the output is as follows:

```json
[
  {
    "AccountId": "123456789012",
    "WAFv1": {
      "Global": { ... },
      "Regional": {
        "us-east-1": { ... },
        "us-west-2": { ... },
        ...
      }
    },
    "WAFv2": {
      "Global": { ... },
      "Regional": {
        "us-east-1": { ... },
        "us-west-2": { ... },
        ...
      }
    }
  },
  ...
]
```

## Error Handling

The script implements comprehensive error handling:

- Errors are logged but do not stop the entire process
- If data collection fails for a specific account or region, the error is recorded in the output
- The script continues to process other accounts and regions even if some fail

## Permissions

The IAM role used must have permissions to:

- Assume roles in other accounts
- List AWS Organizations and accounts
- Access WAF and WAFv2 resources in all regions

## Rate Limiting

The script implements rate limiting to avoid AWS API throttling. It limits API calls to 5 per second.

## Caution

This script may take a considerable amount of time to run, especially if you have many accounts or WAF resources. It's recommended to run it in a stable environment, such as an EC2 instance.
