"""FoxSec Dynamo worker"""
import os
import datetime
import functools
import time
import ipaddress
from pprint import pprint
import requests
import boto3
from botocore.exceptions import ClientError

# Config
#region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
WAF_IPSET_ID = os.environ.get('IPSET_ID')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

# Constants
DYNAMODB = boto3.resource('dynamodb').Table('foxsec-waf')
WAFREGIONAL = boto3.client('waf-regional')

def retry(retry_count=5, delay=5, allowed_exceptions=()):
    """Decorator that allows function retries"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for _ in range(retry_count):
                try:
                    result = func(*args, **kwargs)
                    if result:
                        return result
                except allowed_exceptions as current_exception:
                    last_exception = current_exception
                print("%s: Waiting for %s seconds before retrying again"
                      % (datetime.datetime.utcnow(), delay))
                time.sleep(delay)

            if last_exception is not None:
                raise type(last_exception) from last_exception
            return result
        return wrapper
    return decorator

def ip_address_validate(address):
    """Confirm valid IP and identify v4/v6"""
    ip_types = {4:'IPV4', 6:'IPV6'}

    try:
        ip_network = ipaddress.ip_network(address)
    except ValueError as err:
        print("ip_network failed: %s" % err)
        return err
    else:
        return str(ip_network), ip_types[ip_network.version]

def waf_mark_ipset_delete(source_address, source_type, waf_updates):
    """
    Mark an address for deletion in waf_updates
    """
    waf_update = {'Action': 'DELETE',
                  'IPSetDescriptor': {'Type': source_type,
                                      'Value': source_address}}

    if not waf_update in waf_updates:
        waf_updates.append(waf_update)

@retry(retry_count=5, delay=5)
def waf_update_ip_set(waf_ipset_id, waf_updates):
    """Update WAF ip set"""
    # Get our change token

    try:
        change_token = WAFREGIONAL.get_change_token() #print(token['ChangeToken'])
    except ClientError as err:
        print("waf get_change_token failed: %s" % err)
        return False

    # ChangeTokenStatus, ResponseMetadata.RetryAttempts
    try:
        token_status = WAFREGIONAL.get_change_token_status(ChangeToken=change_token['ChangeToken'])
        print("TOKEN %s" % change_token['ChangeToken'])
        pprint(token_status)
    except ClientError as err:
        print("waf get_change_token_status failed: %s" % err)
        return False

    # Update our WAF ipset and return if successful
    try:
        WAFREGIONAL.update_ip_set(IPSetId=waf_ipset_id,
                                  ChangeToken=change_token['ChangeToken'],
                                  Updates=waf_updates)
    except ClientError as err:
        print("waf update_ip_set failed: %s" % err)
        return False
    else:
        return True

def dynamodb_delete_items(items):
    """
    Remove item ids from dynamodb
    """

    for item in items:
        try:
            DYNAMODB.delete_item(Key={'id': item})
        except ClientError as err:
            print("dynamodb delete_item failed: %s" % err)

def slack_log_expiration(source_address, expires_at, slack_messages):
    """
    Post a message to Slack when a WAF entry expires
    """

    slack_data = {
        "attachments": [{
            "fallback": "WAF Blacklist entry removed for {}".format(source_address),
            "color": "#36a64f",
            "pretext": "WAF Blacklist entry removed",
            "fields": [{
                "title": "Address",
                "value": source_address,
                "short": False
            }, {
                "title": "Expired",
                "value": expires_at,
                "short": False
            }],
            "footer": "Foxsec dynamo worker"
        }]
    }

    # Queue message
    slack_messages.append(slack_data)

def slack_log_untracked(source_address, slack_messages):
    """
    Post a message to Slack when a WAF entry is not tracked in Dynamo
    """

    slack_data = {
        "attachments": [{
            "fallback": "Untracked WAF blacklist entry {} removed".format(source_address),
            "color": "#ff004f",
            "pretext": "Untracked WAF blacklist entry removed",
            "fields": [{
                "title": "Address",
                "value": source_address,
                "short": False
            }],
            "footer": "Foxsec dynamo worker"
        }]
    }

    # Queue message
    slack_messages.append(slack_data)

def post_slack_messages(slack_messages):
    """
    Post a message to Slack
    """

    for slack_data in slack_messages:
        # Post the message to webhook
        response = requests.post(SLACK_WEBHOOK_URL, json=slack_data,
                                 headers={'Content-Type': 'application/json'})

        # Slack docs say 1 message/s
        time.sleep(1)

        if response.status_code != 200:
            raise ValueError(
                'Request to slack returned an error %s, the response is:\n%s'
                % (response.status_code, response.text)
            )

def main():
    """Main"""
    # Init
    waf_updates = []
    waf_rogue_addresses = 0
    dynamodb_pending_delete = []
    dynamodb_expired_addresses = 0
    slack_messages = []

    # Get current time
    current_time = datetime.datetime.utcnow()

    # Get Dynamo items
    dynamodb_items = DYNAMODB.scan(ProjectionExpression='id, address, expires_at')

    # Get ipset contents
    waf_ip_set = WAFREGIONAL.get_ip_set(IPSetId=WAF_IPSET_ID)
    ipset_descriptors = waf_ip_set.get('IPSet').get('IPSetDescriptors')
    ip_networks = [ipset.get('Value') for ipset in ipset_descriptors]

    # Iteriate through DynamoDB
    for item in dynamodb_items.get('Items'):
        # Limit how many rules we evaluate per run
        if dynamodb_expired_addresses >= 75:
            break

        source_address, source_type = ip_address_validate(item.get('address'))
        expires_at = datetime.datetime.strptime(item.get('expires_at'),
                                                "%Y-%m-%d %H:%M:%S.%f")
        if expires_at < current_time:
            if source_address in ip_networks:
                # Console log
                print('[Dynamo] Marking address %s for removal (expired %s)'
                      % (source_address, expires_at))

                # Slack log
                slack_log_expiration(source_address=source_address,
                                     expires_at=expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                                     slack_messages=slack_messages)

                # Mark for deletion in DynamoDB
                dynamodb_pending_delete.append(item.get('id'))
                dynamodb_expired_addresses += 1

                # Mark for removal from waf ipset
                waf_mark_ipset_delete(source_address, source_type, waf_updates)


    # Iteriate through WAF ipset
    items = dynamodb_items.get('Items')
    for ip in ip_networks: # pylint: disable-msg=C0103
        # Limit how many WAF entries we evaluate per run
        if waf_rogue_addresses >= 75:
            break

        source_address, source_type = ip_address_validate(ip)

        if not list(filter(lambda item: item.get('address') == source_address, items)):
            # Console log
            print('[waf] Rogue ipset address %s marked for removal' % source_address)

            # Slack log
            slack_log_untracked(source_address=source_address,
                                slack_messages=slack_messages)

            # Mark for removal from waf ipset
            waf_mark_ipset_delete(source_address, source_type, waf_updates)
            waf_rogue_addresses += 1

    # Execute Dynamo updates
    if dynamodb_pending_delete:
        dynamodb_delete_items(dynamodb_pending_delete)

    # Execute WAF updates
    if waf_updates:
        if not waf_update_ip_set(WAF_IPSET_ID, waf_updates):
            print("waf_update_ip_set failed")
            return False

    # Post to Slack
    post_slack_messages(slack_messages)

    print("Removed %d expired ipset entries, and %d rogue WAF entries"
          % (dynamodb_expired_addresses, waf_rogue_addresses))

if __name__ == "__main__":
    main()
