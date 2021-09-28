import os
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import logging
import json
from utils.awsapi_helpers import AWSClient, BotoSession
from utils.logger import Logger
import io
import csv
import time
import uuid
import s3fs
import urllib

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

LAMBDA_ROLE = 'CIS-1-2-0-4-1-SecurityGroupsTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
LAMBDA_ROLE += '_' + AWS_REGION
BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    },
    region_name=AWS_REGION
)
AWS = AWSClient(AWS_PARTITION, AWS_REGION)
s3 = s3fs.S3FileSystem(anon=False)

def lambda_handler(event, context):

    logger.debug(event)
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    input_file = os.path.join(bucket,key)
    

    try:
        inFile = s3.open(input_file, 'r', newline='\n', encoding='utf-8-sig')
        fileReader = csv.reader(inFile)
        for row in fileReader:
                account_id = row[0]
                resource_id = row[1]
                region = row[2]
                logger.info('Got event: '+account_id+' '+ resource_id)
              
                sess = BotoSession(account_id, LAMBDA_ROLE)
                ssm = sess.client('ssm')
                logger.debug('Opened SSM session')
   
                response = ssm.start_automation_execution(
                    DocumentName='AWS-DisablePublicAccessForSecurityGroup',
                    DocumentVersion='1',
                    Parameters={
                        'GroupId': [ resource_id ],
                        'AutomationAssumeRole': ['arn:' + AWS_PARTITION + ':iam::' + \
                           account_id + ':role/' + LAMBDA_ROLE]
                    }
                )
                logger.debug(response)
                logger.info('Remediation was successfully invoked via AWS Systems Manager for ' +account_id+' '+ resource_id )
    except Exception as e:
        logger.error(e)
        logger.error('Error getting object from bucket. Make sure they exist and your bucket is in the same region as this function. '+ input_file)
        raise e