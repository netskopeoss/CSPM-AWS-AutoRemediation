import csv
import os
import s3fs
import urllib.parse
from botocore.config import Config
from utils.awsapi_helpers import BotoSession
from utils.logger import Logger

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

ASSUME_ROLE = 'CIS-1-2-0-2-2-CloudTrailLogFileTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
ASSUME_ROLE += '_' + AWS_REGION

s3 = s3fs.S3FileSystem(anon=False)


def lambda_handler(event, context):
    """
    Lambda handler for the following use case:
       Rule Name: Secure audit trails so they cannot be altered : CloudTrail Log Files Lack Integrity Validation
       Definition: CloudTrail should have LogFile Validation Enabled.
    """
    try:
        # read file from triggered object
        logger.debug(f'Event from trigger: {event}')
        file_reader = read_file_from_bucket(event)

        # perform remediation for all CloudTrails in file row-wise
        for row in file_reader:
            account_id = row[0]
            trail_arn = row[1]
            region = row[2]

            logger.info(
                f'Got event with AWS Account ID: {account_id}, CLoudTrail: {trail_arn} and Region: {region}')
            enable_cloudtrail_logfile_validation(region, account_id, trail_arn)

    except Exception as error:
        raise Exception(f'Error occurred while doing remediation of the use case. Reason: {error}') from error


def read_file_from_bucket(event):
    """
    This function retrieve the file from the bucket and return the csv reader object
    :param event: Event contains data for a Lambda function to process
    :return: file_reader - csv reader object
    """
    try:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(
            event['Records'][0]['s3']['object']['key'], encoding='utf-8')
        input_file = os.path.join(bucket, key)
        logger.info('Got input file: ' + input_file)

        input_file = s3.open(input_file, 'r', newline='\n',
                             encoding='utf-8-sig')
        file_reader = csv.reader(input_file)
        return file_reader

    except Exception as error:
        raise Exception('Error occurred while reading file from bucket. Error: {error}') from error


def enable_cloudtrail_logfile_validation(region, account_id, trail_arn):
    """
    This function enables CloudTrail Log File validation by invoking runbook via SSM
    :param region: Region of CloudTrail
    :param account_id: AWS Account ID
    :param trail_arn: ARN of CloudTrail
    """
    try:
        sess = BotoSession(account_id, ASSUME_ROLE, AWS_PARTITION)
        ssm = sess.client('ssm')
        logger.debug('Opened SSM session')
        cloudtrail = sess.client('cloudtrail')
        logger.debug('Opened cloudtrail session')

        # Check is log file validation enabled for CloudTrail
        cloudtrail_payload = cloudtrail.get_trail(Name=trail_arn)
        logger.debug(f'get_trail method response: {cloudtrail_payload}')
        if cloudtrail_payload['Trail']['LogFileValidationEnabled']:
            logger.info(f'Remediation was already completed earlier for AWS Account ID: {account_id},'
                        f'CloudTrail: {trail_arn} and Region: {region}')
        else:
            # Invoking Runbook via AWS SSM
            response = ssm.start_automation_execution(
                DocumentName='AWSConfigRemediation-EnableCloudTrailLogFileValidation',
                DocumentVersion='1',
                Parameters={
                    'TrailName': [trail_arn],
                    'AutomationAssumeRole': ['arn:' + AWS_PARTITION + ':iam::' + account_id + ':role/' + ASSUME_ROLE]
                }
            )
            logger.debug(f'Response from SSM start automation execution :{response}')
            logger.info(
                f'Remediation was successfully completed via AWS Systems Manager for AWS Account ID: {account_id},'
                f'CloudTrail: {trail_arn} and Region: {region}')

    except Exception as error:
        logger.exception(
            f'Error occurred while doing remediation of CloudTrail:{trail_arn} of AWS Account ID: {account_id} and '
            f'Region: {region}.Error: {error}. Skipping remediation of this CloudTrail')
