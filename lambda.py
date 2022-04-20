"""
Lambda function which Formats and publishes Inspector finding events to various outlets
"""
import boto3
import botocore
import os
import json
import requests
from typing import Any, Dict
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer
from aws_lambda_powertools.utilities.data_classes import event_source, EventBridgeEvent

service_name = "inspector-alerts"  # Set service name used by Logger/Tracer here

# Setup CloudWatch and Xray
logger = Logger(service=service_name)
tracer = Tracer(service=service_name, disabled=bool(os.getenv("ENABLE_XRAY", False)))

# Generic Configuration
sev_list = os.getenv("SEV_LIST", [])

# Configuration via Enviroment Variables
enabled_sns = os.getenv("ENABLE_SNS", False)
sns_arn = os.getenv("SNS_ARN", None)

# Slack Configuration
enable_slack = bool(os.getenv("ENABLE_SLACK", False))
slack_url = os.getenv("SLACK_URL", None)

# Configuration from AWS supplied environment variables
aws_region = os.environ["AWS_REGION"]


def send_slack_alert(event: EventBridgeEvent):
    """
    Send an Alert to Slack Webhook

    Parameters
    ----------
    event: EventBridgeEvent Dictionary
    """

    if slack_url is None:
        logger.error("Slack URL not provided")
        exit

    if event.detail["severity"] == "CRITICAL":
        emoji = ":red_circle:"
    elif event.detail["severity"] == "HIGH":
        emoji = ":large_orange_circle:"
    else:
        emoji = ":large_green_circle:"

    resources = []
    for resource in event.detail["resources"]:
        resources.append(resource["id"])

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": emoji + " " + event.detail["severity"] + ": " + event.detail["title"]
            },
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*AWS Account:*\n" + event.detail["awsAccountId"]
                },
                {
                    "type": "mrkdwn",
                    "text": "*Time:*\n" + event.time
                },
                {
                    "type": "mrkdwn",
                    "text": "*Finding Type:*\n" + event.detail["type"].lower().replace("_", " "),
                },
                {
                    "type": "mrkdwn",
                    "text": "*Finding Info:*\n" + event.detail["packageVulnerabilityDetails"]["sourceUrl"],
                },
                {
                    "type": "mrkdwn",
                    "text": "*Resources:*\n" + "`" + ",".join(resources) + "`"
                }
            ]
        }
    ]

    return requests.post(slack_url, json={
        'blocks': json.dumps(blocks)
    })


def send_json_sns(event: EventBridgeEvent):
    """
    Send an Alert to SNS Topic

    Parameters
    ----------
    event: EventBridgeEvent Dictionary
    """
    if sns_arn is None:
        logger.error("SNS ARN not provided")

    sns = boto3.client('sns')

    resources = []
    for resource in event.detail["resources"]:
        resources.append(resource["id"])

    message = {
        "default": json.dumps({
            "AWS_ACCOUNT": event.detail["awsAccountId"],
            "SEVERITY": event.detail["severity"],
            "TIME": event.time,
            "FINDING_TYPE": event.detail["type"],
            "FINDING": event.detail["title"],
            "FINDING_INFO": event.detail["packageVulnerabilityDetails"]["sourceUrl"],
            "RESOURCES": resources,
        })
    }

    try:
        sns.publish(
            TopicArn=sns_arn,
            Message=json.dumps(message),
            Subject=event.detail["severity"] + ": " + event.detail["title"],
            MessageStructure="json",
        )
    except botocore.exceptions.ClientError as error:
        raise error
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))


@logger.inject_lambda_context
@event_source(data_class=EventBridgeEvent)
@tracer.capture_lambda_handler
def lambda_handler(event: EventBridgeEvent, context: LambdaContext) -> Dict[str, Any]:
    """
    Main Lambda entry point.

    Parameters
    ----------
    event: Lambda event objectw
    context: Lambda context object
    """
    if event.detail["severity"] in sev_list:
        if enabled_sns:
            logger.debug("Sending SNS Message")
            send_json_sns(event)

        if enable_slack:
            logger.debug("Sending Slack Message")
            send_slack_alert(event)

    return {"statusCode": 200}
