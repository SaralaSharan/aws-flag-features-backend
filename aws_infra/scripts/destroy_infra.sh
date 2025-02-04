#!/bin/bash
STACK_NAME="FeatureFlagStack"

echo "⚠️ WARNING: This will delete all AWS resources for $STACK_NAME!"
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "❌ Deletion canceled."
    exit 1
fi

echo "🗑️ Deleting CloudFormation Stack: $STACK_NAME..."
aws cloudformation delete-stack --stack-name $STACK_NAME

echo "✅ Deletion initiated. Run 'scripts/check_stack.sh' to monitor progress."
