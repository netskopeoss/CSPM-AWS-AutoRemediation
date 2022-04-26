"""Use case: Remote access: Ensure access keys are rotated every 90 days or less."""

import os
from botocore.config import Config
from utils.awsapi_helpers import BotoSession
from utils.logger import Logger
import csv
import s3fs
import urllib
from datetime import datetime
from dateutil.tz import tzutc

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

LAMBDA_ROLE = 'CIS-1-2-0-1-4-AccessKeyRotationTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
LAMBDA_ROLE += '_' + AWS_REGION
BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    },
    region_name=AWS_REGION
)
INACTIVE_ACCESS_KEYS_AFTER_DAYS = 90

s3 = s3fs.S3FileSystem(anon=False)


def lambda_handler(event, context):
    """
    Lambda handler for the use case:
    Rule Name: Remote access: Ensure access keys are rotated every 90 days or less.
    Definition: IAMUser should not have  AccessKey with [ Active and LastRotatedTime isEarlierThan ( -90 , "days" ) ]

    Inactive the access keys that are older than 90 days
    """
    try:
        # retrieve the events from csv file
        csv_file_reader = read_csv_from_bucket(event=event)

        # Process the event row wise
        for row in csv_file_reader:
            account_id = row[0]
            username = row[1]
            region = row[2]
            logger.info(f'Parsed alert details. Username: {username}, region: {region}, account ID: {account_id}')

            is_access_key_inactivated = check_and_inactive_access_keys(account_id=account_id, username=username)
            if is_access_key_inactivated:
                logger.info(
                    f'Remediation was successfully done for Account ID {account_id},'
                    f' Username {username} and region {region}')

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


def check_and_inactive_access_keys(account_id, username):
    """
    Inactive Access keys of user that are older than 90 days

    :param account_id: Account ID of the AWS
    :param username: Username of the AWS account
    """
    try:
        is_access_key_inactivated = False
        sess = BotoSession(account_id, LAMBDA_ROLE, AWS_PARTITION)
        iam = sess.client('iam')
        logger.debug('Opened IAM session')

        access_keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata')
        for access_key in access_keys:
            if access_key.get('Status') == 'Active' and \
                    (datetime.now(tz=tzutc()) - access_key.get('CreateDate')).days >= INACTIVE_ACCESS_KEYS_AFTER_DAYS:
                iam.update_access_key(UserName=username, AccessKeyId=access_key.get('AccessKeyId'),
                                      Status='Inactive')
                logger.info(f'Access key {access_key.get("AccessKeyId")} inactivated for the {username}')
                is_access_key_inactivated = True

        if not is_access_key_inactivated:
            logger.info(f'No active access keys found that were created before 90 days for user {username}.')

        return is_access_key_inactivated
    except Exception as error:
        logger.exception(f'Error occurred while performing access keys operation. Reason: {error}')
