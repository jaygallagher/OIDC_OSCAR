FROM eclipse-temurin:22-jdk-jammy
#FROM openjdk:17-jdk-alpine

# Set the working directory
WORKDIR /app

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]
