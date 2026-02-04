FROM eclipse-temurin:21-jre

## 실행 경로
WORKDIR /app/myce-backend/api-gateway

## 실행 파일
COPY ./api/build/libs/*.jar myce-api-gateway.jar

## 실행 포트
EXPOSE 8083

ENTRYPOINT ["java", "-jar", "myce-core-api.jar", "--spring.profiles.active=product"]