import boto3
import json
import logging
import argparse
import time
from botocore.exceptions import ClientError, ParamValidationError
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from functools import wraps

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Rate limiting parameters
CALLS = 5
RATE_LIMIT = 1

class RateLimiter:
    def __init__(self, calls, period):
        self.calls = calls
        self.period = period
        self.timestamps = deque()

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            while len(self.timestamps) >= self.calls:
                elapsed = time.time() - self.timestamps[0]
                if elapsed < self.period:
                    time.sleep(self.period - elapsed)
                self.timestamps.popleft()
            self.timestamps.append(time.time())
            return func(*args, **kwargs)
        return wrapper

rate_limiter = RateLimiter(CALLS, RATE_LIMIT)

@rate_limiter
def rate_limited_api_call(func, *args, **kwargs):
    """
    Wrapper function to apply rate limiting to API calls.
    """
    return func(*args, **kwargs)

def safe_api_call(func, *args, **kwargs):
    """
    Wrapper function to safely make API calls with error handling.
    """
    try:
        return rate_limited_api_call(func, *args, **kwargs)
    except ClientError as e:
        logger.error(f"API call failed: {func.__name__}, Error: {e}")
        return None
    except ParamValidationError as e:
        logger.error(f"Invalid parameters for API call: {func.__name__}, Error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in API call: {func.__name__}, Error: {e}")
        return None

def assume_role(account_id, role_name):
    """
    Assume a role in the specified account.
    """
    sts_client = boto3.client('sts')
    try:
        response = rate_limited_api_call(
            sts_client.assume_role,
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName='WAFDataCollection'
        )
        credentials = response['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except ClientError as e:
        logger.error(f"Failed to assume role in account {account_id}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error when assuming role in account {account_id}: {e}")
        return None

def get_all_regions(session):
    """
    Get a list of all AWS regions.
    """
    ec2_client = session.client('ec2')
    try:
        response = safe_api_call(ec2_client.describe_regions)
        return [region['RegionName'] for region in response['Regions']] if response else []
    except Exception as e:
        logger.error(f"Failed to get list of regions: {e}")
        return []

def handle_pagination(client, method, **kwargs):
    """
    Handle pagination for AWS API calls.
    """
    results = []
    try:
        if method == 'list_web_acls':
            # Special handling for list_web_acls which doesn't support pagination
            response = safe_api_call(getattr(client, method), **kwargs)
            results.append(response if response else {})
        else:
            paginator = client.get_paginator(method)
            for page in paginator.paginate(**kwargs):
                results.append(page)
    except Exception as e:
        logger.error(f"Error in {method}: {str(e)}")
        results.append({"Error": str(e)})
    
    return results

def get_wafv1_data(session):
    """
    Collect WAFv1 data using the provided session.
    """
    data = {
        'Global': {
            'WebACLs': [],
            'Rules': [],
            'IPSets': [],
            'ByteMatchSets': [],
            'SqlInjectionMatchSets': [],
            'XssMatchSets': [],
            'SizeConstraintSets': [],
            'RegexPatternSets': []
        },
        'Regional': {}
    }
    
    # Global WAFv1 (CLOUDFRONT)
    waf = session.client('waf')
    data['Global'] = collect_wafv1_data(waf, 'Global')
    
    # Regional WAFv1
    regions = get_all_regions(session)
    for region in regions:
        try:
            waf_regional = session.client('waf-regional', region_name=region)
            data['Regional'][region] = collect_wafv1_data(waf_regional, region)
        except Exception as e:
            logger.error(f"Error collecting WAFv1 data for region {region}: {e}")
            data['Regional'][region] = {'Error': str(e)}
    
    return data

def collect_wafv1_data(client, scope):
    """
    Collect WAFv1 data for a specific client (global or regional).
    """
    data = {
        'WebACLs': [],
        'Rules': [],
        'IPSets': [],
        'ByteMatchSets': [],
        'SqlInjectionMatchSets': [],
        'XssMatchSets': [],
        'SizeConstraintSets': [],
        'RegexPatternSets': []
    }

    # Get WebACLs
    webacls = handle_pagination(client, 'list_web_acls')
    for page in webacls:
        for acl in page.get('WebACLs', []):
            acl_id = acl['WebACLId']
            acl_details = safe_api_call(client.get_web_acl, WebACLId=acl_id)
            data['WebACLs'].append({
                'ListedACL': acl,
                'Details': acl_details.get('WebACL') if acl_details else None,
                'Error': None if acl_details else 'Failed to get WebACL details'
            })

    # Get Rules
    rules = handle_pagination(client, 'list_rules')
    for page in rules:
        for rule in page.get('Rules', []):
            rule_id = rule['RuleId']
            rule_details = safe_api_call(client.get_rule, RuleId=rule_id)
            data['Rules'].append({
                'ListedRule': rule,
                'Details': rule_details.get('Rule') if rule_details else None,
                'Error': None if rule_details else 'Failed to get Rule details'
            })

    # Get IPSets
    ipsets = handle_pagination(client, 'list_ip_sets')
    for page in ipsets:
        for ipset in page.get('IPSets', []):
            ipset_id = ipset['IPSetId']
            ipset_details = safe_api_call(client.get_ip_set, IPSetId=ipset_id)
            data['IPSets'].append({
                'ListedIPSet': ipset,
                'Details': ipset_details.get('IPSet') if ipset_details else None,
                'Error': None if ipset_details else 'Failed to get IPSet details'
            })

    # Get ByteMatchSets
    byte_match_sets = handle_pagination(client, 'list_byte_match_sets')
    for page in byte_match_sets:
        for byte_match_set in page.get('ByteMatchSets', []):
            byte_match_set_id = byte_match_set['ByteMatchSetId']
            byte_match_set_details = safe_api_call(client.get_byte_match_set, ByteMatchSetId=byte_match_set_id)
            data['ByteMatchSets'].append({
                'ListedByteMatchSet': byte_match_set,
                'Details': byte_match_set_details.get('ByteMatchSet') if byte_match_set_details else None,
                'Error': None if byte_match_set_details else 'Failed to get ByteMatchSet details'
            })

    # Get SqlInjectionMatchSets
    sql_injection_match_sets = handle_pagination(client, 'list_sql_injection_match_sets')
    for page in sql_injection_match_sets:
        for sql_injection_match_set in page.get('SqlInjectionMatchSets', []):
            sql_injection_match_set_id = sql_injection_match_set['SqlInjectionMatchSetId']
            sql_injection_match_set_details = safe_api_call(client.get_sql_injection_match_set, SqlInjectionMatchSetId=sql_injection_match_set_id)
            data['SqlInjectionMatchSets'].append({
                'ListedSqlInjectionMatchSet': sql_injection_match_set,
                'Details': sql_injection_match_set_details.get('SqlInjectionMatchSet') if sql_injection_match_set_details else None,
                'Error': None if sql_injection_match_set_details else 'Failed to get SqlInjectionMatchSet details'
            })

    # Get XssMatchSets
    xss_match_sets = handle_pagination(client, 'list_xss_match_sets')
    for page in xss_match_sets:
        for xss_match_set in page.get('XssMatchSets', []):
            xss_match_set_id = xss_match_set['XssMatchSetId']
            xss_match_set_details = safe_api_call(client.get_xss_match_set, XssMatchSetId=xss_match_set_id)
            data['XssMatchSets'].append({
                'ListedXssMatchSet': xss_match_set,
                'Details': xss_match_set_details.get('XssMatchSet') if xss_match_set_details else None,
                'Error': None if xss_match_set_details else 'Failed to get XssMatchSet details'
            })

    # Get SizeConstraintSets
    size_constraint_sets = handle_pagination(client, 'list_size_constraint_sets')
    for page in size_constraint_sets:
        for size_constraint_set in page.get('SizeConstraintSets', []):
            size_constraint_set_id = size_constraint_set['SizeConstraintSetId']
            size_constraint_set_details = safe_api_call(client.get_size_constraint_set, SizeConstraintSetId=size_constraint_set_id)
            data['SizeConstraintSets'].append({
                'ListedSizeConstraintSet': size_constraint_set,
                'Details': size_constraint_set_details.get('SizeConstraintSet') if size_constraint_set_details else None,
                'Error': None if size_constraint_set_details else 'Failed to get SizeConstraintSet details'
            })

    # Get RegexPatternSets
    regex_pattern_sets = handle_pagination(client, 'list_regex_pattern_sets')
    for page in regex_pattern_sets:
        for regex_pattern_set in page.get('RegexPatternSets', []):
            regex_pattern_set_id = regex_pattern_set['RegexPatternSetId']
            regex_pattern_set_details = safe_api_call(client.get_regex_pattern_set, RegexPatternSetId=regex_pattern_set_id)
            data['RegexPatternSets'].append({
                'ListedRegexPatternSet': regex_pattern_set,
                'Details': regex_pattern_set_details.get('RegexPatternSet') if regex_pattern_set_details else None,
                'Error': None if regex_pattern_set_details else 'Failed to get RegexPatternSet details'
            })

    return data

def get_wafv2_data(session):
    """
    Collect WAFv2 data using the provided session.
    """
    data = {
        'Global': {},
        'Regional': {}
    }
    
    # Global WAFv2 (CLOUDFRONT)
    wafv2_global = session.client('wafv2', region_name='us-east-1')
    data['Global'] = collect_wafv2_data(wafv2_global, 'CLOUDFRONT')
    
    # Regional WAFv2
    regions = get_all_regions(session)
    for region in regions:
        try:
            wafv2_regional = session.client('wafv2', region_name=region)
            data['Regional'][region] = collect_wafv2_data(wafv2_regional, 'REGIONAL')
        except Exception as e:
            logger.error(f"Error collecting WAFv2 data for region {region}: {e}")
            data['Regional'][region] = {'Error': str(e)}
    
    return data

def collect_wafv2_data(client, scope):
    """
    Collect WAFv2 data for a specific client (global or regional).
    """
    data = {
        'WebACLs': [],
        'IPSets': [],
        'RegexPatternSets': [],
        'RuleGroups': [],
        'ManagedRuleSets': []
    }

    # Get WebACLs
    webacls = handle_pagination(client, 'list_web_acls', Scope=scope)
    for page in webacls:
        for acl in page.get('WebACLs', []):
            acl_details = safe_api_call(client.get_web_acl, Name=acl['Name'], Scope=scope, Id=acl['Id'])
            data['WebACLs'].append({
                'ListedACL': acl,
                'Details': acl_details.get('WebACL') if acl_details else None,
                'Error': None if acl_details else 'Failed to get WebACL details'
            })

    # Get IPSets
    ipsets = handle_pagination(client, 'list_ip_sets', Scope=scope)
    for page in ipsets:
        for ipset in page.get('IPSets', []):
            ipset_details = safe_api_call(client.get_ip_set, Name=ipset['Name'], Scope=scope, Id=ipset['Id'])
            data['IPSets'].append({
                'ListedIPSet': ipset,
                'Details': ipset_details.get('IPSet') if ipset_details else None,
                'Error': None if ipset_details else 'Failed to get IPSet details'
            })

    # Get RegexPatternSets
    regex_pattern_sets = handle_pagination(client, 'list_regex_pattern_sets', Scope=scope)
    for page in regex_pattern_sets:
        for regex_set in page.get('RegexPatternSets', []):
            regex_set_details = safe_api_call(client.get_regex_pattern_set, Name=regex_set['Name'], Scope=scope, Id=regex_set['Id'])
            data['RegexPatternSets'].append({
                'ListedRegexPatternSet': regex_set,
                'Details': regex_set_details.get('RegexPatternSet') if regex_set_details else None,
                'Error': None if regex_set_details else 'Failed to get RegexPatternSet details'
            })

    # Get RuleGroups
    rule_groups = handle_pagination(client, 'list_rule_groups', Scope=scope)
    for page in rule_groups:
        for rule_group in page.get('RuleGroups', []):
            rule_group_details = safe_api_call(client.get_rule_group, Name=rule_group['Name'], Scope=scope, Id=rule_group['Id'])
            data['RuleGroups'].append({
                'ListedRuleGroup': rule_group,
                'Details': rule_group_details.get('RuleGroup') if rule_group_details else None,
                'Error': None if rule_group_details else 'Failed to get RuleGroup details'
            })

    # Get ManagedRuleSets
    managed_rule_sets = handle_pagination(client, 'list_available_managed_rule_groups', Scope=scope)
    for page in managed_rule_sets:
        for managed_rule_set in page.get('ManagedRuleGroups', []):
            # We can't get details of managed rule sets, so we'll just store the basic info
            data['ManagedRuleSets'].append({
                'ListedManagedRuleSet': managed_rule_set,
                'Details': None,
                'Error': None
            })

    return data

def process_account(account_id, role_name):
    """
    Process a single AWS account.
    """
    logger.info(f"Processing account: {account_id}")
    session = assume_role(account_id, role_name)
    if session:
        try:
            wafv1_data = get_wafv1_data(session)
            wafv2_data = get_wafv2_data(session)
            return {
                'AccountId': account_id,
                'WAFv1': wafv1_data,
                'WAFv2': wafv2_data
            }
        except Exception as e:
            logger.error(f"Error processing account {account_id}: {e}")
            return {
                'AccountId': account_id,
                'Error': str(e)
            }
    else:
        logger.warning(f"Failed to assume role for account {account_id}")
        return {
            'AccountId': account_id,
            'Error': 'Failed to assume role'
        }

def main(role_name, output_file):
    """
    Main function to collect WAF data from all accounts in all organizations.
    """
    result = []
    
    # Get the list of all AWS Organizations
    org_client = boto3.client('organizations')
    try:
        organizations = safe_api_call(org_client.list_roots)
        if not organizations:
            logger.error("Failed to list AWS Organizations")
            return
        organizations = organizations.get('Roots', [])
    except Exception as e:
        logger.error(f"Failed to list AWS Organizations: {e}")
        return
    
    for org in organizations:
        try:
            accounts = []
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                accounts.extend(page['Accounts'])
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_account = {executor.submit(process_account, account['Id'], role_name): account['Id'] for account in accounts}
                for future in as_completed(future_to_account):
                    account_id = future_to_account[future]
                    try:
                        data = future.result()
                        if data:
                            result.append(data)
                    except Exception as exc:
                        logger.error(f"Account {account_id} generated an exception: {exc}")
                        result.append({
                            'AccountId': account_id,
                            'Error': str(exc)
                        })
        
        except ClientError as e:
            logger.error(f"Failed to list accounts for organization {org['Id']}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error when processing organization {org['Id']}: {e}")
    
    # Write results to JSON file
    try:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        logger.info(f"Data collection complete. Results written to {output_file}")
    except IOError as e:
        logger.error(f"Failed to write results to file {output_file}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error when writing results to file {output_file}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect AWS WAF data across multiple accounts and organizations.")
    parser.add_argument("role_name", help="The name of the IAM role to assume in each account")
    parser.add_argument("output_file", help="The path to the output JSON file")
    args = parser.parse_args()
    
    main(args.role_name, args.output_file)

# Example usage:
# python aws_waf_data_collector.py WAFDataCollectionRole waf_data_output.json