require("dotenv").config();
const express = require("express");
const admin = require("firebase-admin");
const AWS = require("aws-sdk");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const winston = require("winston");
require("winston-cloudwatch");

const secretsManager = new AWS.SecretsManager();

// Initialize Firebase Admin SDK using AWS Secrets Manager
async function initializeFirebase() {
  try {
    const secretData = await secretsManager
      .getSecretValue({ SecretId: "FirebaseServiceKey" })
      .promise();
    const serviceAccount = JSON.parse(secretData.SecretString);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log(
      "✅ Firebase initialized successfully with AWS Secrets Manager"
    );
  } catch (error) {
    console.error("❌ Error initializing Firebase:", error);
    process.exit(1);
  }
}
initializeFirebase();

const app = express();
app.use(express.json());

// Ensure AWS Region is Set
const awsRegion = process.env.AWS_REGION || "us-east-1";
// AWS Configuration
AWS.config.update({ region: awsRegion });

const cloudwatch = new AWS.CloudWatch();

// Initialize CloudWatch Logger with Retention Policy
const cloudwatchConfig = {
  logGroupName: "FeatureFlagAPI-Logs",
  logStreamName: `api-logs-${new Date().toISOString().split("T")[0]}`,
  awsRegion: process.env.AWS_REGION,
  jsonMessage: true,
};

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.CloudWatch(cloudwatchConfig),
  ],
});

// Configure CloudWatch Log Retention
const cloudwatchLogs = new AWS.CloudWatchLogs();
cloudwatchLogs.putRetentionPolicy(
  {
    logGroupName: "FeatureFlagAPI-Logs",
    retentionInDays: 30,
  },
  (err) => {
    if (err) {
      console.error("Error setting log retention policy:", err);
    } else {
      console.log("Log retention policy set to 30 days");
    }
  }
);

// Function to send CloudWatch metrics
const sendMetric = (metricName, value) => {
  const params = {
    Namespace: "FeatureFlagAPI",
    MetricData: [
      {
        MetricName: metricName,
        Value: value,
        Unit: "Count",
        Timestamp: new Date(),
      },
    ],
  };

  cloudwatch.putMetricData(params, (err, data) => {
    if (err) {
      console.error(`Error sending CloudWatch metric ${metricName}:`, err);
    } else {
      console.log(`Metric ${metricName} sent to CloudWatch.`);
    }
  });
};

// AWS DynamoDB Config
const dynamodb = new AWS.DynamoDB();
const documentClient = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = "Users";

// Middleware to Verify Firebase Authentication Token
async function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    logger.warn("Invalid or expired token", { error });
    sendMetric("UnauthorizedRequests", 1);
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

// User Sign-up
app.post(
  "/signup",
  [
    body("email").isEmail().withMessage("Invalid email"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
    body("displayName").notEmpty().withMessage("Display name is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn("Invalid sign-up attempt", { errors: errors.array() });
      sendMetric("FailedSignUpAttempts", 1);
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, displayName } = req.body;
    const userId = uuidv4();
    const createdAt = new Date().toISOString();

    try {
      const userRecord = await admin
        .auth()
        .createUser({ email, password, displayName });
      const hashedPassword = await bcrypt.hash(password, 10);

      await documentClient
        .put({
          TableName: USERS_TABLE,
          Item: {
            userId,
            email,
            displayName,
            password: hashedPassword,
            createdAt,
          },
        })
        .promise();

      logger.info("User signed up successfully", { userId, email });
      sendMetric("SuccessfulSignUp", 1);
      res
        .status(201)
        .json({ message: "User created successfully!", uid: userRecord.uid });
    } catch (error) {
      logger.error("Error creating user", { error });
      sendMetric("SignUpErrors", 1);
      res.status(500).json({ error: error.message });
    }
  }
);

// Retrieve User by Email or UserId
app.get("/users/:identifier", async (req, res) => {
  const { identifier } = req.params;

  const paramsByEmail = {
    TableName: USERS_TABLE,
    Key: { email: identifier },
  };

  const paramsById = {
    TableName: USERS_TABLE,
    IndexName: "userId-index",
    KeyConditionExpression: "userId = :userId",
    ExpressionAttributeValues: { ":userId": identifier },
  };

  try {
    let data = await documentClient.get(paramsByEmail).promise();
    if (!data.Item) {
      data = await documentClient.query(paramsById).promise();
      if (data.Items.length > 0) {
        data.Item = data.Items[0];
      }
    }

    if (data.Item) {
      const { userId, email, displayName, createdAt } = data.Item;
      res.status(200).json({ userId, email, displayName, createdAt });
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    logger.error("Error retrieving user", { error });
    res.status(500).json({ error: error.message });
  }
});

// Protected Feature Flags Route
app.get("/feature-flags", verifyToken, async (req, res) => {
  try {
    const result = await documentClient
      .scan({ TableName: "FeatureFlags" })
      .promise();
    logger.info("Feature flags retrieved");
    sendMetric("FeatureFlagsRetrieved", result.Items.length);
    res.json(result.Items);
  } catch (err) {
    logger.error("Error retrieving feature flags", { error: err.message });
    sendMetric("FeatureFlagsErrors", 1);
    res.status(500).json({ error: err.message });
  }
});

// Root Route
app.get("/", (req, res) => {
  logger.info("API Health Check Requested");
  sendMetric("HealthCheckRequests", 1);
  res.json({
    message: "Feature Flag API with CloudWatch Logging and Metrics is running!",
  });
});

// Start Express Server
const PORT = process.env.PORT || 8001;
app.listen(PORT, () => logger.info(`Secure server running on port ${PORT}`));
