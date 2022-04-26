import boto3
import botocore
from datetime import datetime, timezone
import json
import requests
import os
from utils.logger import Logger

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

s3_client = boto3.client("s3")
S3_BUCKET = os.environ['security_assessment_results_s3_bucket']
TENANT_FQDN = os.environ['tenant_fqdn']
CHUNK_SIZE = 100
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
secret_arn = os.environ['api_token']
AWS_REGIONS = {
    "us-east-1": "US East(N. Virginia)",
    "us-east-2": "US East(Ohio)",
    "us-west-1": "US West(N. California)",
    "us-west-2": "US West(Oregon)",
    "af-south-1": "Africa(Cape Town)",
    "ap-east-1": "Asia Pacific(Hong Kong)",
    "ap-southeast-3": "Asia Pacific(Jakarta)",
    "ap-south-1": "Asia Pacific(Mumbai)",
    "ap-northeast-3": "Asia Pacific(Osaka)",
    "ap-southeast-2": "Asia Pacific(Sydney)",
    "ap-northeast-2": "Asia Pacific(Seoul)",
    "ap-southeast-1": "Asia Pacific(Singapore)",
    "ap-northeast-1": "Asia Pacific(Tokyo)",
    "ca-central-1": "Canada(Central)",
    "eu-central-1": "EU(Frankfurt)",
    "eu-west-1": "EU(Ireland)",
    "eu-west-2": "EU(London)",
    "eu-west-3": "EU(Paris)",
    "eu-north-1": "EU(Stockholm)",
    "eu-south-1": "EU(Milan)",
    "sa-east-1": "South America(Sao Paulo)"
}


def lambda_handler(event, context):
    try:
        token = json.loads(get_secret(secret_arn))['token']

        rule_name = event['rule_name']
        rule_short_name = event['rule_short_name']

        file_name = str(TENANT_FQDN) + '.' + rule_short_name + '.' + datetime.now().strftime(
            "%m%d%Y%H%M%S")
        page_number = 0
        alert_count = 0
        resp = get_status(rule_name, token, str(CHUNK_SIZE), str(page_number * CHUNK_SIZE))
        logger.debug(resp)
        file_data = ""
        while len(resp):
            for item in resp:
                logger.debug('Got violation for the account ' + item['account_id'] + ' account name ' + item[
                    'account_name'] + ' resource_id ' + item['resource_id'] + ' resource_name ' + item[
                                 'resource_name'] + ' rule_name ' + item['rule_name'])
                if item['region_name'] == AWS_REGIONS[AWS_REGION] or item['region_name'] == 'global':
                    logger.info(
                        'Got violation from this region for the account ' + item['account_id'] + ' account name ' + item[
                            'account_name'] + ' resource_id ' + item['resource_id'] + ' resource_name ' + item[
                            'resource_name'] + ' rule_name ' + item['rule_name'])
                    file_data += item['account_id'] + ',' + item['resource_id'] + ',' + item[
                        'region_name'] + "\n"
                    alert_count = alert_count + 1
                    logger.debug("Violation is from this region")
                else:
                    logger.debug("Violation is from another region")
            page_number = page_number + 1
            resp = get_status(rule_name, token, str(CHUNK_SIZE), str(page_number * CHUNK_SIZE))
            logger.debug(resp)

        if alert_count > 0:
            logger.info('Got ' + str(alert_count) + ' total violations for the rule ' + rule_name)
            file_path = rule_short_name + '/' + file_name
            s3_client.put_object(Key=file_path, Bucket=S3_BUCKET, Body=file_data)
        else:
            logger.info('Got ' + str(alert_count) + ' total violations for the rule ' + rule_name)

    except Exception as e:
        logger.error(f'Error occurred while getting Netskope CSPM results. Reason: {e}')
        raise e


def get_status(rule_name, token, limit, skip):
    try:
        get_url = 'https://' + TENANT_FQDN + '/api/v1/security_assessment'
        payload = {'token': token, 'cloud_provider': 'aws', 'status': 'Failed', 'muted': 'No', 'rule_name': rule_name,
                   'limit': limit, 'skip': skip}

        logger.info('Calling Netskope API for ' + rule_name)

        r = requests.get(get_url, params=payload)

        return r.json()['data']
    except Exception as e:
        logger.error(f'Error occurred while calling Netskope API.')
        raise e


def get_secret(secret_arn):
    logger.debug(secret_arn)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=AWS_REGION
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        response = client.describe_secret(SecretId=secret_arn)

        get_secret_value_response = client.get_secret_value(
            SecretId=response['Name']
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
            print(e)
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        secret = get_secret_value_response['SecretString']
    return (secret)