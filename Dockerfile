# Use the official Node.js image
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your code
COPY . .

# Expose the port your app runs on
EXPOSE 3000

# Start the application
CMD [ "node", "server.js" ]
