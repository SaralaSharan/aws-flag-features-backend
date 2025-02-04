const fs = require("fs");

const yaml = require("js-yaml");
const cloudFormationConfig = require("./aws_infra_as_code"); // Import the infra config

// Convert JSON to YAML
const yamlOutput = yaml.dump(cloudFormationConfig, { noRefs: true });

// Write to file
fs.writeFileSync("aws_infra/cloudformation.yaml", yamlOutput, "utf8");

console.log("✅ CloudFormation YAML generated successfully.");
