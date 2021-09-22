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

assume_role = 'CIS-1-4-0-3-9-VPCFlowLogsTargetRole'
VPCFlowLogs_role = 'CIS-1-4-0-3-9-VPCFlowLogsRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
assume_role += '_' + AWS_REGION
boto_config = Config(
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
    logger.info('Got input file: '+input_file)
    

    try:
        inFile = s3.open(input_file, 'r', newline='\n', encoding='utf-8-sig')
        fileReader = csv.reader(inFile)
        for row in fileReader:
                account_id = row[0]
                resource_id = row[1]
                region = row[2]
                logger.info('Got event: '+account_id+' '+ resource_id)
            
                lambdaFunctionSeshToken = os.getenv('AWS_SESSION_TOKEN', '')  
            
                DeliverLogsPermissionArn = 'arn:' + AWS_PARTITION + ':iam::' + account_id + \
                    ':role/'+VPCFlowLogs_role+'_'+AWS_REGION
    
                try:
                    sess = BotoSession(account_id, assume_role)
                    cwl = sess.client('logs')
                    ec2 = sess.client('ec2')
                except Exception as e:
                    logger.error(e)
                    
                vpcFlowLogGroup = "VPCFlowLogs/" + resource_id + lambdaFunctionSeshToken[0:32]        
               
                try:
                    confirmFlowlogs = ec2.describe_flow_logs(
                        DryRun=False,
                        Filters=[
                            {
                                'Name': 'log-group-name',
                                'Values': [vpcFlowLogGroup]
                            },
                        ]
                    )
                    logger.debug(confirmFlowlogs)
                    if len(confirmFlowlogs['FlowLogs']):
                        flowStatus = str(confirmFlowlogs['FlowLogs'][0]['FlowLogStatus'])
                        if flowStatus == 'ACTIVE':
                            logger.info('Remediation was already completed earlier for ' +account_id+' '+ resource_id )
                            continue
                except Exception as e:
                    logger.error(e)
               
                try:
                    create_log_grp = cwl.create_log_group(logGroupName=vpcFlowLogGroup)
                except Exception as e:
                    logger.error(e)
                    
                # wait for CWL creation to propagate
                time.sleep(3)
                # create VPC Flow Logging
                try:
                    enableFlowlogs = ec2.create_flow_logs(
                        DryRun=False,
                        DeliverLogsPermissionArn=DeliverLogsPermissionArn,
                        LogGroupName=vpcFlowLogGroup,
                        ResourceIds=[resource_id],
                        ResourceType='VPC',
                        TrafficType='ALL',
                        LogDestinationType='cloud-watch-logs'
                    )
                    logger.debug(enableFlowlogs)
                except Exception as e:
                    logger.error(e)
                  
                time.sleep(2)
                try:
                    confirmFlowlogs = ec2.describe_flow_logs(
                        DryRun=False,
                        Filters=[
                            {
                                'Name': 'log-group-name',
                                'Values': [vpcFlowLogGroup]
                            },
                        ]
                    )
                    logger.debug(confirmFlowlogs)
                    flowStatus = str(confirmFlowlogs['FlowLogs'][0]['FlowLogStatus'])
                    if flowStatus == 'ACTIVE':
                        logger.info('Remediation was successfully invoked for ' +account_id+' '+ resource_id )
                        
                    else:
                        
                        logger.error(e)
                      
                except Exception as e:
                    logger.error(e)
                    
                    
    except Exception as e:
        logger.error(e)
        raise e