# Verify-stage sandbox for Java/Gradle projects.
FROM gradle:8-jdk17
WORKDIR /work
CMD ["java", "-version"]
