#!/bin/sh

# Check if the JAR_FILE environment variable is set
if [ -z "$JAR_FILE" ]; then
  echo "JAR_FILE environment variable is not set. Exiting."
  exit 1
fi

# Run the JAR file
exec java -jar "$JAR_FILE"
