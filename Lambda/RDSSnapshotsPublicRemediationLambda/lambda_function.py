import os
import csv
import s3fs
import urllib.parse
from botocore.config import Config
from utils.awsapi_helpers import BotoSession
from utils.logger import Logger

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

ASSUME_ROLE = 'BPR-3-8-RDSSnapshotsPublicTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')
ASSUME_ROLE += '_' + AWS_REGION

s3 = s3fs.S3FileSystem(anon=False)


def lambda_handler(event, context):
    """
    Lambda handler for the following use case:
        Rule Name: Access permissions and authorizations: Ensure RDS Instances do not have Publicly Accessible Snapshots
        Definition: RDS Instances should not have publicly accessible snapshots.
    """

    try:
        # read file from triggered object
        logger.debug(f'Event from trigger: {event}')
        file_reader = read_file_from_bucket(event)

        # perform remediation for snapshots of all databases in file row-wise
        for row in file_reader:
            account_id = row[0]
            database_id = row[1]
            region = row[2]
            logger.info(f'Got event with AWS Account ID: {account_id}, Database ID: {database_id} and Region: {region}')
            disable_public_access_of_snapshots(region, account_id, database_id)

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


def disable_public_access_of_snapshots(region, account_id, database_id):
    """
    This function disables public access for each snapshot of database
    :param region: Region of Database
    :param account_id: AWS Account ID
    :param database_id: Database ID
    """
    try:
        sess = BotoSession(account_id, ASSUME_ROLE, AWS_PARTITION)
        rds = sess.client('rds')
        logger.debug('Opened RDS Session')

        db_payload = rds.describe_db_instances(DBInstanceIdentifier=database_id)
        logger.debug(f'payload of database: {db_payload}')

        dbsnapshots = rds.describe_db_snapshots(DBInstanceIdentifier=database_id,
                                                SnapshotType='public')['DBSnapshots']
        logger.debug(f'describe_db_snapshots method response: {dbsnapshots}')
        if not dbsnapshots:
            logger.info(f'No snapshot is public for Database ID: {database_id}')
        else:
            for snapshot in dbsnapshots:
                try:
                    # make public snapshot private
                    snapshot_id = snapshot['DBSnapshotIdentifier']
                    snapshot_response = rds.modify_db_snapshot_attribute(DBSnapshotIdentifier=snapshot_id,
                                                                         AttributeName='restore',
                                                                         ValuesToRemove=['all'])
                    logger.debug(f'Updated Snapshot Response: {snapshot_response}')
                    logger.info('Invoked remediation')
                    # Checking remediation is successful or not
                    snapshot_payload = rds.describe_db_snapshots(DBInstanceIdentifier=database_id,
                                                                 DBSnapshotIdentifier=snapshot_id,
                                                                 SnapshotType='public')
                    if not snapshot_payload['DBSnapshots']:
                        logger.info(f'Remediation successfully completed for snapshot ID: {snapshot_id} of '
                                    f'Database: {database_id},AWS Account ID: {account_id} and Region: {region}')
                    else:
                        raise Exception(f'The snapshot still appears to be public after the remediation.')

                except Exception as e:
                    logger.error(
                        f'Error occurred while doing remediation of snapshot:{snapshot_id} of database: {database_id}.'
                        f'Error: {e} - Skipping remediation of this snapshot')

    except Exception as error:
        logger.exception(
            f'Error occurred while doing remediation of database:{database_id} of AWS Account ID: {account_id} and '
            f'Region: {region}.Error: {error} - Skipping remediation of this database')
