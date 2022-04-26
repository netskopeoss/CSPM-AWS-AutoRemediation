"""Use case: Ensure S3 Bucket is not publicly accessible."""
import csv
import os
import urllib.parse
import s3fs
import botocore
from botocore.config import Config
from utils.awsapi_helpers import BotoSession
from utils.logger import Logger

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

LAMBDA_ROLE = 'BPR-1-0-0-S3BucketPublicAccessTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
LAMBDA_ROLE += '_' + AWS_REGION

s3 = s3fs.S3FileSystem(anon=False)


def lambda_handler(event, context):
    """
    Lambda handler for the use case:
    Rule Name: Ensure S3 Bucket is not publicly accessible.
    Definition: S3Bucket should not have Access eq "Public"
    """
    try:
        # retrieve the events from csv file
        csv_file_reader = read_csv_from_bucket(event=event)

        for row in csv_file_reader:
            account_id = row[0]
            bucket_name = row[1]
            region = row[2]
            logger.debug(f'Parsed alert details. region: {region}, account ID: {account_id}, bucket: {bucket_name}')

            is_public_access_blocked = enable_block_public_access_settings_from_bucket(account_id, bucket_name)

            if is_public_access_blocked:
                logger.info(f'Remediation was successfully done for account {account_id}, region {region}'
                            f' and bucket {bucket_name}.')

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


def enable_block_public_access_settings_from_bucket(account_id, bucket_name):
    """
    Enable all settings that blocks public access to the bucket
    :param account_id: Account ID of the AWS
    :param bucket_name: Name of the bucket
    """
    try:
        sess = BotoSession(account_id, LAMBDA_ROLE, AWS_PARTITION)

        s3_client = sess.client('s3')
        logger.debug('Opened S3 session')

        set_block_public_access_settings = False

        # It raises NoSuchPublicAccessBlockConfiguration exception if the
        # block public-access settings are disabled.
        try:
            public_block_access_response = s3_client.get_public_access_block(Bucket=bucket_name,
                                                                             ExpectedBucketOwner=account_id)
            logger.debug(f'Public Block Access settings for bucket:'
                         f' {public_block_access_response["PublicAccessBlockConfiguration"]}')

            public_access_block_configuration = public_block_access_response['PublicAccessBlockConfiguration']

            if public_access_block_configuration['IgnorePublicAcls'] is False or \
               public_access_block_configuration['RestrictPublicBuckets'] is False:
                public_access_block_configuration['IgnorePublicAcls'] = True
                public_access_block_configuration['RestrictPublicBuckets'] = True
                set_block_public_access_settings = True

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                public_access_block_configuration = {'IgnorePublicAcls': True, 'RestrictPublicBuckets': True}
                set_block_public_access_settings = True
            else:
                raise e

        if set_block_public_access_settings:
            s3_client.put_public_access_block(Bucket=bucket_name,
                                              PublicAccessBlockConfiguration=public_access_block_configuration,
                                              ExpectedBucketOwner=account_id)

            logger.info(f'Block public access settings IgnorePublicAcls and RestrictPublicBuckets '
                        f'are set to true for this {bucket_name} bucket')
            return True
        else:
            logger.info(f'Bucket {bucket_name} already have IgnorePublicAcls and RestrictPublicBuckets'
                        f' block public access settings enabled.')

    except Exception as error:
        logger.exception(f'Error occurred while enabling block public access settings on'
                         f' the bucket {bucket_name}. Reason: {error}')

