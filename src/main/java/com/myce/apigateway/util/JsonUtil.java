package com.myce.apigateway.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static byte[] convertToBytes(Object object) throws JsonProcessingException {
        return objectMapper.writeValueAsBytes(object);
    }
}
