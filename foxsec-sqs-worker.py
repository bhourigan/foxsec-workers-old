"""FoxSec SQS worker"""
import os
import datetime
import functools
import time
import json
import pprint
import boto3
from botocore.exceptions import ClientError

# Config
#region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
WAF_IPSET_ID = os.environ.get('IPSET_ID')

# Constants
DYNAMODB = boto3.resource('dynamodb').Table('foxsec-waf')
SQS = boto3.client('sqs')
WAFREGIONAL = boto3.client('waf-regional')

def parse_arn(arn):
    """Parse ARN string
    http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
    """

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
    pretty_print = pprint.PrettyPrinter(indent=8)

    # Get our change token
    try:
        change_token = WAFREGIONAL.get_change_token() #print(token['ChangeToken'])
    except ClientError as current_exception:
        print("waf get_change_token failed: %s" % current_exception)
        return False

    # ChangeTokenStatus, ResponseMetadata.RetryAttempts
    try:
        token_status = WAFREGIONAL.get_change_token_status(ChangeToken=change_token['ChangeToken'])
        print("Token %s status" % change_token['ChangeToken'])
        pretty_print.pprint(token_status)
    except ClientError as current_exception:
        print("waf get_change_token_status failed: %s" % current_exception)
        return False

    # Update our WAF ipset
    try:
        WAFREGIONAL.update_ip_set(IPSetId=waf_ipset_id,
                                  ChangeToken=change_token['ChangeToken'],
                                  Updates=waf_updates)
    except ClientError as current_exception:
        print("waf update_ip_set failed: %s" % current_exception)
        return False

    return True

def lambda_handler(event, context):
    """Main entrypoint handler"""
    pretty_print = pprint.PrettyPrinter(indent=4)

    waf_updates = []
    sqs_entries = []

    record = None
    for record in event.get('Records'):
        # Parse Records[].body
        body = json.loads(record.get('body'))
        # Parse body['metadata']
        metadata = {item['key']:item['value'] for item in body['metadata']}
        # Parse metadata window_timestamp
        window_timestamp = datetime.datetime.strptime(metadata['window_timestamp'],
                                                      "%Y-%m-%dT%H:%M:%S.%fZ")

        # DEBUG: Pretty print body
        print("Body")
        pretty_print.pprint(body)

        # Put item in DynamoDB
        try:
            expires_at = str(window_timestamp + datetime.timedelta(days=1))
            DYNAMODB.put_item(Item={'id': body['id'],
                                    'summary': body['summary'],
                                    'address': metadata['sourceaddress'],
                                    'blocked_at': datetime.datetime.now(),
                                    'expires_at': expires_at})

        except ClientError as current_exception:
            print("dybamodb put item failed: %s" % current_exception)

        # TODO: Validate sourceaddress

        # Put item in waf_updates list
        waf_update = {'Action': 'INSERT',
                      'IPSetDescriptor': {'Type': 'IPV4',
                                          'Value': metadata['sourceaddress']+"/32"}}
        waf_updates.append(waf_update)

        # Put item in sqs_entries list
        sqs_entry = {'Id': record.get('messageId'), 'ReceiptHandle': record.get('receiptHandle')}
        sqs_entries.append(sqs_entry)

    # DEBUG: Print waf_updates
    print("WAF Updates")
    pretty_print.pprint(waf_updates)

    # Update WAF ip set
    waf_update_ip_set(WAF_IPSET_ID, waf_updates)

    # Get our queue url from the arn provided to us through the trigger
    arn = parse_arn(record.get('eventSourceARN'))

    # Get queue url
    try:
        queue_url = SQS.get_queue_url(QueueName=arn.get('resource'))
    except ClientError as current_exception:
        print("sqs get_queue_url failed: %s" % current_exception)

    # Delete received messages
    try:
        SQS.delete_message_batch(QueueUrl=queue_url.get('QueueUrl'), Entries=sqs_entries)
    except ClientError as current_exception:
        print("sqs delete_message_batch failed: %s" % current_exception)

    print("END OF EXECUTION")
