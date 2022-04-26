"""Use cases:
1. Communications and control network protection: Ensure no rule exists which allows all ingress traffic in default
Network ACL
2. Communications and control network protection: Ensure no rule exists which allows all ingress traffic in
Network ACL which is associated with a subnet
"""

import os
from botocore.config import Config
from utils.awsapi_helpers import BotoSession
from utils.logger import Logger
import csv
import s3fs
import urllib

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

LAMBDA_ROLE = 'BPR-0-6-NACLTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
LAMBDA_ROLE += '_' + AWS_REGION

s3 = s3fs.S3FileSystem(anon=False)


def lambda_handler(event, context):
    """
    Lambda handler for the use cases:
    1. Rule Name: Communications and control network protection: Ensure no rule exists which allows all ingress traffic
                  in default Network ACL
       Definition: NetworkACL should not have IsDefault eq true and Rules with [ RuleAction eq "allow" and Protocol
                   eq "-1" and Egress eq False and CidrBlock eq 0.0.0.0/0 ]
    2. Rule Name: Communications and control network protection: Ensure no rule exists which allows all ingress traffic
                  in Network ACL which is associated with a subnet
       Definition: NetworkACL where Subnets len( ) gt 0  should not have Rules with [ Egress eq False and RuleAction eq
                   "allow" and Protocol eq "-1" and CidrBlock eq 0.0.0.0/0 ]

    Removes entry from NACL having CidrBlock = '0.0.0.0/0', Egress = False (Only inbound rules),
    RuleAction = 'allow' and Protocol = '-1'
    """
    try:
        # retrieve the events from csv file
        csv_file_reader = read_csv_from_bucket(event=event)

        # Process the event row wise
        for row in csv_file_reader:
            account_id = row[0]
            nacl_id = row[1]
            region = row[2]
            logger.info(f"Parsed alert details. Network ACL ID: {nacl_id}, region: {region}, account ID: {account_id}")

            is_entries_removed = remove_rule_entry_from_network_acl(account_id=account_id, network_acl_id=nacl_id)
            if is_entries_removed:
                logger.info(
                    f'Remediation was successfully done for Account ID {account_id},'
                    f' Network ACL ID {nacl_id} and region {region}')

    except Exception as error:
        raise Exception(f'Error occurred while doing remediation of the use case. Reason: {error}') from error


def read_csv_from_bucket(event):
    """
    Retrieve the file from the bucket and return the csv reader object
    :param event: Dictionary containing information related to event
    """
    try:
        s3_event = event['Records'][0]['s3']
        bucket = s3_event['bucket']['name']
        key = urllib.parse.unquote_plus(s3_event['object']['key'], encoding='utf-8')
        input_file = os.path.join(bucket, key)
        logger.info(f'Input file received: {input_file}')
        input_file = s3.open(input_file, 'r', newline='\n', encoding='utf-8-sig')
        file_reader = csv.reader(input_file)
        return file_reader
    except Exception as error:
        raise Exception('Error occurred while reading CSV file from bucket. Reason: {error}') from error


def remove_rule_entry_from_network_acl(account_id, network_acl_id):
    """
    Removes rule entries matching the condition, 
    CidrBlock = '0.0.0.0/0', Egress = False (Only inbound rules),
    RuleAction = 'allow' and Protocol = '-1'
    from Network ACL

    :param account_id: Account ID of the AWS
    :param network_acl_id: Network ACL ID
    """
    try:
        is_entries_removed = False
        sess = BotoSession(account_id, LAMBDA_ROLE, AWS_PARTITION)
        ec2_resource = sess.resource('ec2')
        logger.debug('Opened EC2 session')

        network_acl = ec2_resource.NetworkAcl(network_acl_id)
        for entry in network_acl.entries:
            if entry.get('CidrBlock') == '0.0.0.0/0' and entry.get('Egress') is False and \
                    entry.get('RuleAction') == 'allow' and entry.get('Protocol') == '-1':
                network_acl.delete_entry(Egress=False, RuleNumber=entry.get('RuleNumber'))
                logger.info(f'Rule entry {entry} removed from network ACL')
                is_entries_removed = True

        if not is_entries_removed:
            logger.info(f'No rule entries present in Network ACL {network_acl_id} which satisfies the rule condition.')

        return is_entries_removed
    except Exception as error:
        logger.exception(f'Error occurred while removing entry from Network ACL. Reason: {error}')
