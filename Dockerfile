FROM openjdk:11
RUN mkdir /app
EXPOSE 8000
ARG JAR_FILE=build/libs/*.jar
COPY ${JAR_FILE} /app/app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]