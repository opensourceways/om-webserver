package com.om.Utils;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SensitiveUtil {
    private static final Logger logger =  LoggerFactory.getLogger(SensitiveUtil.class);

    public static void stringClear(String sensitiveData) {
        try {
            Field valueFielfOfString = String.class.getDeclaredField("value");
            valueFielfOfString.setAccessible(true);
            byte[] value = (byte[]) valueFielfOfString.get(sensitiveData);
            Arrays.fill(value, (byte)0x00);
        } catch (Exception e) {
            logger.error("error msg: ", e);
        }
    }
}
