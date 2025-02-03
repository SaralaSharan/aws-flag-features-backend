require("dotenv").config();
const express = require("express");
const admin = require("firebase-admin");
const AWS = require("aws-sdk");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const winston = require("winston");
require("winston-cloudwatch");

// Initialize Firebase Admin SDK
const serviceAccount = require("./serviceAccountKey.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(express.json());

// AWS Configuration
AWS.config.update({ region: process.env.AWS_REGION });

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
      res
        .status(201)
        .json({ message: "User created successfully!", uid: userRecord.uid });
    } catch (error) {
      logger.error("Error creating user", { error });
      res.status(500).json({ error: error.message });
    }
  }
);

// User Login
app.post(
  "/login",
  [
    body("email").isEmail().withMessage("Invalid email"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn("Invalid login attempt", { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      const user = await admin.auth().getUserByEmail(email);
      const customToken = await admin.auth().createCustomToken(user.uid);

      logger.info("User logged in successfully", { email });
      res.json({ message: "Login successful!", token: customToken });
    } catch (error) {
      logger.error("Login error", { error });
      res.status(400).json({ error: "Invalid email or password." });
    }
  }
);

// Protected Feature Flags Route
app.get("/feature-flags", verifyToken, async (req, res) => {
  try {
    const result = await documentClient
      .scan({ TableName: "FeatureFlags" })
      .promise();
    logger.info("Feature flags retrieved");
    res.json(result.Items);
  } catch (err) {
    logger.error("Error retrieving feature flags", { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Root Route
app.get("/", (req, res) => {
  logger.info("API Health Check Requested");
  res.json({ message: "Feature Flag API with CloudWatch Logging is running!" });
});

// Start Express Server
const PORT = process.env.PORT || 8001;
app.listen(PORT, () => logger.info(`Secure server running on port ${PORT}`));
