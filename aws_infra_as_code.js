module.exports = {
  ECS: {
    FeatureFlagECSCluster: {
      Type: "AWS::ECS::Cluster",
      Properties: {
        ClusterName: "FeatureFlagCluster",
      },
    },
    FeatureFlagECRRepository: {
      Type: "AWS::ECR::Repository",
      Properties: {
        RepositoryName: "feature-flag-api",
      },
    },
  },

  DynamoDB: {
    FeatureFlagDynamoDBTable: {
      Type: "AWS::DynamoDB::Table",
      Properties: {
        TableName: "Users",
        AttributeDefinitions: [
          { AttributeName: "email", AttributeType: "S" },
          { AttributeName: "userId", AttributeType: "S" },
        ],
        KeySchema: [{ AttributeName: "email", KeyType: "HASH" }],
        ProvisionedThroughput: {
          ReadCapacityUnits: 5,
          WriteCapacityUnits: 5,
        },
        GlobalSecondaryIndexes: [
          {
            IndexName: "userId-index",
            KeySchema: [{ AttributeName: "userId", KeyType: "HASH" }],
            Projection: {
              ProjectionType: "ALL",
            },
            ProvisionedThroughput: {
              ReadCapacityUnits: 5,
              WriteCapacityUnits: 5,
            },
          },
        ],
      },
    },
  },

  LoadBalancer: {
    FeatureFlagALB: {
      Type: "AWS::ElasticLoadBalancingV2::LoadBalancer",
      Properties: {
        Name: "FeatureFlagALB",
        Subnets: ["subnet-0cd78b016439cf8dc", "subnet-0d040064b875c9c45"],
        SecurityGroups: ["sg-01d29c8797210e047"],
        Scheme: "internet-facing",
        LoadBalancerAttributes: [
          { Key: "deletion_protection.enabled", Value: "false" },
        ],
      },
    },
    FeatureFlagTargetGroup: {
      Type: "AWS::ElasticLoadBalancingV2::TargetGroup",
      Properties: {
        Name: "FeatureFlagTargetGroup",
        Port: 80,
        Protocol: "HTTP",
        VpcId: "vpc-0da00d77dbd6789d0",
        HealthCheckProtocol: "HTTP",
        HealthCheckPort: "80",
        HealthCheckPath: "/",
        Matcher: {
          HttpCode: "200",
        },
        TargetType: "instance",
      },
    },
    FeatureFlagListener: {
      Type: "AWS::ElasticLoadBalancingV2::Listener",
      Properties: {
        LoadBalancerArn: { Ref: "FeatureFlagALB" },
        Protocol: "HTTP",
        Port: 80,
        DefaultActions: [
          {
            Type: "forward",
            TargetGroupArn: { Ref: "FeatureFlagTargetGroup" },
          },
        ],
      },
    },
  },

  CloudWatch: {
    FeatureFlagCloudWatchLogGroup: {
      Type: "AWS::Logs::LogGroup",
      Properties: {
        LogGroupName: "FeatureFlagAPI-Logs",
        RetentionInDays: 30,
      },
    },
  },

  IAM: {
    FeatureFlagIAMRole: {
      Type: "AWS::IAM::Role",
      Properties: {
        RoleName: "FeatureFlagECSExecutionRole",
        AssumeRolePolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: { Service: "ecs-tasks.amazonaws.com" },
              Action: "sts:AssumeRole",
            },
          ],
        },
        Policies: [
          {
            PolicyName: "FeatureFlagECSPolicy",
            PolicyDocument: {
              Version: "2012-10-17",
              Statement: [
                {
                  Effect: "Allow",
                  Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
                  Resource: "*",
                },
                {
                  Effect: "Allow",
                  Action: ["secretsmanager:GetSecretValue", "ssm:GetParameter"],
                  Resource: "*",
                },
              ],
            },
          },
        ],
      },
    },
  },
};
