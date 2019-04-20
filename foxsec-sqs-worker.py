"""FoxSec SQS worker"""
import os
import datetime
import functools
import time
import json
import pprint
import ipaddress
import boto3
from botocore.exceptions import ClientError

# Config
#region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
WAF_IPSET_ID = os.environ.get('IPSET_ID')
WAF_IPSET_EXPIRATION_HOURS = os.environ.get('IPSET_EXPIRATION_HOURS', 24)

# Constants
DYNAMODB = boto3.resource('dynamodb').Table('foxsec-waf')
SQS = boto3.client('sqs')
WAFREGIONAL = boto3.client('waf-regional')
PRETTYPRINT = pprint.PrettyPrinter(indent=4)

def parse_arn(arn):
    """Parse ARN"""

    elements = arn.split(':', 5)
    result = {
        'arn': elements[0],
        'partition': elements[1],
        'service': elements[2],
        'region': elements[3],
        'account': elements[4],
        'resource': elements[5],
        'resource_type': None
    }

    if '/' in result['resource']:
        result['resource_type'], result['resource'] = result['resource'].split('/', 1)
    elif ':' in result['resource']:
        result['resource_type'], result['resource'] = result['resource'].split(':', 1)

    return result

def retry(retry_count=5, delay=5, allowed_exceptions=()):
    """Decorator that allows function retries"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for _ in range(retry_count):
                try:
                    result = func(*args, **kwargs)
                    if result:
                        return result
                except allowed_exceptions as current_exception:
                    last_exception = current_exception
                print("%s: Waiting for %s seconds before retrying again"
                      % (datetime.datetime.now(), delay))
                time.sleep(delay)

            if last_exception is not None:
                raise type(last_exception) from last_exception
            return result
        return wrapper
    return decorator

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
        PRETTYPRINT.pprint(token_status)
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

def sqs_delete_messages(arn, messages):
    """Delete messages from SQS arn"""
    # Parse SQS ARN
    arn = parse_arn(arn)

    # Get queue url from queue name
    try:
        queue_url = SQS.get_queue_url(QueueName=arn.get('resource'))
    except ClientError as err:
        print("sqs get_queue_url failed: %s" % err)
        return False

    # Delete received messages and return if successful
    try:
        SQS.delete_message_batch(QueueUrl=queue_url.get('QueueUrl'), Entries=messages)
    except ClientError as err:
        print("sqs delete_message_batch failed: %s" % err)
        return False
    else:
        return True

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

def dynamodb_put_items(items):
    """Put items in DynamoDB. One item at a time."""
    for item in items:
        try:
            DYNAMODB.put_item(Item=item)
        except ClientError as err:
            print("dybamodb put item failed: %s" % err)

def lambda_handler(event, context):
    """Main entrypoint handler"""
    # Initialize
    del context # Unused
    waf_updates = []
    sqs_entries = []
    dynamodb_items = []

    # Evaluate each record
    record = None
    for record in event.get('Records'):
        # Mark SQS message for deletion early
        sqs_entry = {'Id': record.get('messageId'), 'ReceiptHandle': record.get('receiptHandle')}
        sqs_entries.append(sqs_entry)

        # Skip invalid records
        if not record.get('body'):
            print("Missing body")
            continue

        # Load JSON
        body = json.loads(record.get('body'))

        # Skip records without metadata
        if not body.get('metadata'):
            print("Missing metadata")
            continue

        # List of dict to dict
        metadata = {item['key']:item['value'] for item in body['metadata']}

        # Parse window_timestamp to datetime, calculate expires_at
        window_timestamp = datetime.datetime.strptime(metadata['window_timestamp'],
                                                      "%Y-%m-%dT%H:%M:%S.%fZ")
        expires_at = window_timestamp + datetime.timedelta(hours=int(WAF_IPSET_EXPIRATION_HOURS))

        # Validate sourceaddress
        try:
            source_address, source_type = ip_address_validate(metadata['sourceaddress'])
        except: # pylint: disable-msg=W0702
            print("Invalid sourceaddress, continuing")
            continue

        # Sanity check
        if expires_at < datetime.datetime.now():
            print("Expire date in the past, continuing")
            continue

        # Put item in dynamodb put list
        dynamodb_item = {'id': body['id'],
                         'summary': body['summary'],
                         'address': source_address,
                         'blocked_at': str(datetime.datetime.now()),
                         'expires_at': str(expires_at)}
        dynamodb_items.append(dynamodb_item)

        # Add update to waf updates
        waf_update = {'Action': 'INSERT',
                      'IPSetDescriptor': {'Type': source_type,
                                          'Value': source_address}}
        waf_updates.append(waf_update)

    # Delete SQS messages
    if sqs_entries:
        print("SQS")
        PRETTYPRINT.pprint(sqs_entries)
        sqs_delete_messages(record.get('eventSourceARN'), sqs_entries)

    # Put items in DynamoDB
    if dynamodb_items:
        print("DYNAMODB")
        PRETTYPRINT.pprint(dynamodb_items)
        dynamodb_put_items(items=dynamodb_items)

    # Update WAF ip sets
    if waf_updates:
        print("WAF")
        PRETTYPRINT.pprint(waf_updates)
        waf_update_ip_set(WAF_IPSET_ID, waf_updates)
