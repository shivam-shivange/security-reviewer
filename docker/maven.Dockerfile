# Verify-stage sandbox for Java/Maven projects.
FROM maven:3.9-eclipse-temurin-17
WORKDIR /work
# Warm the local Maven cache from the copied pom so later offline test runs are fast.
COPY pom.xml ./
RUN mvn -B -q -DskipTests dependency:go-offline || true
CMD ["java", "-version"]
