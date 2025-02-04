#!/bin/bash
STACK_NAME="FeatureFlagStack"
TEMPLATE_FILE="aws_infra/cloudformation.yaml"

echo "🚀 Deploying CloudFormation Stack: $STACK_NAME..."

aws cloudformation create-stack --stack-name $STACK_NAME \
    --template-body file://$TEMPLATE_FILE \
    --capabilities CAPABILITY_NAMED_IAM

echo "✅ Stack creation initiated. Run 'scripts/check_stack.sh' to monitor progress."
