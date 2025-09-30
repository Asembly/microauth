FROM maven:3.8.4-openjdk-17-slim AS builder
WORKDIR /app
COPY . .
RUN mkdir -p /root/.m2
COPY settings.xml /root/.m2/settings.xml
RUN mvn clean install -DskipTests
RUN ./mvnw -B package


FROM openjdk:17
WORKDIR /app
COPY --from=builder /app/target/*.jar ./app.jar
ENTRYPOINT ["java", "-jar", "app.jar", "--spring.profiles.active=prod"]