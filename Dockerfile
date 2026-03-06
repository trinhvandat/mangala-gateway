# Build stage
FROM maven:3.9.9-eclipse-temurin-21-alpine AS build

WORKDIR /app

# Copy common-security module (git submodule)
COPY mangala-common-security/pom.xml mangala-common-security/pom.xml
COPY mangala-common-security/src mangala-common-security/src

# Build common-security
WORKDIR /app/mangala-common-security
RUN mvn clean install -DskipTests -B

# Copy gateway service
WORKDIR /app/mangala-gateway
COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Add non-root user for security
RUN addgroup -S mangala && adduser -S mangala -G mangala
USER mangala

# Copy the built artifact
COPY --from=build /app/mangala-gateway/target/*.jar app.jar

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/actuator/health || exit 1

# JVM tuning for containers
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:InitialRAMPercentage=50.0"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
