docker exec hip-service_gateway_1 sh -c "cp -f /shared/gatewayStubConfigurations/imposters/*.ejs /mb"
docker stop hip-service_gateway_1
docker start hip-service_gateway_1
docker logs --tail 60 -f  hip-service_gateway_1
