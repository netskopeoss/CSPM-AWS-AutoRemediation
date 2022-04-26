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

ASSUME_ROLE = 'BPR-1-9-RedShiftClusterPublicTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
ASSUME_ROLE += '_' + AWS_REGION

s3 = s3fs.S3FileSystem(anon=False)


def lambda_handler(event, context):
    """
    Lambda handler for the following use case:
       Rule Name: Access permissions and authorizations: Ensure Redshift Clusters are not Publicly accessible
       Definition: Redshift Clusters should not be accessible to the public.
    """
    try:
        # retrieve file from triggered object
        logger.debug(event)
        file_reader = read_file_from_bucket(event)

        # perform remediation for all RedShift clusters in file
        for row in file_reader:
            account_id = row[0]
            cluster_id = row[1]
            region = row[2]

            logger.info(f'Got event with AWS Account ID: {account_id}, Cluster ID: {cluster_id} and Region: {region}')
            disable_public_access_of_redshift_cluster(region, account_id, cluster_id)

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


def disable_public_access_of_redshift_cluster(region, account_id, cluster_id):
    """
    This function disable public access of RedShift clusters by invoking runbook via SSM
    :param region: Region of RedShift Cluster
    :param account_id: AWS Account ID
    :param cluster_id: RedShift Cluster ID
    """
    try:
        sess = BotoSession(account_id, ASSUME_ROLE, AWS_PARTITION)
        ssm = sess.client('ssm')
        logger.debug('Opened SSM session')
        redshift = sess.client('redshift')
        logger.debug('Opened redshift session')

        cluster_response = redshift.describe_clusters(ClusterIdentifier=cluster_id)
        logger.debug(f'describe_clusters method response: {cluster_response}')
        clusters = cluster_response['Clusters']
        for cluster in clusters:
            if cluster['PubliclyAccessible']:
                # Invoking Runbook via AWS SSM
                response = ssm.start_automation_execution(
                    DocumentName='AWSConfigRemediation-DisablePublicAccessToRedshiftCluster',
                    DocumentVersion='1',
                    Parameters={
                        'ClusterIdentifier': [cluster_id],
                        'AutomationAssumeRole': ['arn:' + AWS_PARTITION + ':iam::' +
                                                 account_id + ':role/' + ASSUME_ROLE]
                    }
                )
                logger.debug(f'Response from SSM start automation execution :{response}')
                logger.info(
                    f'Remediation was successfully completed via AWS Systems Manager for AWS Account ID: '
                    f'{account_id}, Cluster ID: {cluster_id} and Region: {region}')
            else:
                logger.info(f'Remediation was already completed earlier for AWS Account ID: {account_id}, '
                            f'Cluster ID: {cluster_id} and Region: {region}')

    except Exception as error:
        logger.exception(
            f'Error occurred while doing remediation of Cluster:{cluster_id} of AWS Account ID: {account_id} and '
            f'Region: {region}.Error: {error}. Skipping remediation of this cluster')
