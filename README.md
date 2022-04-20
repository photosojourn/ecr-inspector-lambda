# AWS Lambda Python Template

This Lambda function that revices Inspector 2 events filters and processes them before sending on to several outlets.

## Supported Outlets

* SNS Topic in JSON format
* Formatted Slack Webhook using Block Kit

## Enviroment Variables

### General Configuration

* SEV_LIST : List of Severities which you wish to forward. Default `[]`
* LOG_LEVEL: Set the level of Logging provided. Default `INFO`
* ENABLED_XRAY : Wether to enable or disable XRAY Tracing. Default `False`

### SNS Configuration

* ENABLE_SNS: Set wether SNS message delivery should be enabled. Default `False`
* SNS_ARN : ARN of the destination SNS topic. Default `None`

### Slack Webhook Configuration

* ENABLE_SLACK: Set wether Slack message delivery should be enabled. Default `False`
* SLACK_URL: SLack Webhook URL for the Slack App. Default `None`
