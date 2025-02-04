#!/bin/bash
STACK_NAME="FeatureFlagStack"

echo "📡 Checking status of CloudFormation Stack: $STACK_NAME..."
aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].StackStatus"
