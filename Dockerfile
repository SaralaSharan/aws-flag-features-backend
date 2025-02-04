# Use official Node.js runtime as a parent image
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install --only=production

# Copy the application source code
COPY . .

# Set environment variables explicitly
ENV AWS_REGION=us-east-1

# Expose the application port
EXPOSE 8001

# Run the application
CMD ["node", "server.js"]
