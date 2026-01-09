package com.myce.apigateway.util;

import tools.jackson.databind.ObjectMapper;

public class JsonUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static byte[] convertToBytes(Object object) {
        return objectMapper.writeValueAsBytes(object);
    }
}
