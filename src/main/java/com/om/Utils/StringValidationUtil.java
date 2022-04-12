package com.om.Utils;


import org.apache.commons.lang3.StringUtils;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringValidationUtil {

    public static boolean isEmail(String string) {
        if (string == null)
            return false;
        String regEx1 = "^[a-z0-9A-Z]+[-|a-z0-9A-Z._]+@([a-z0-9A-Z]+(-[a-z0-9A-Z]+)?\\.)+[a-z]{2,}$";
        Pattern p;
        Matcher m;
        p = Pattern.compile(regEx1);
        m = p.matcher(string);
        if (((Matcher) m).matches())
            return true;
        else
            return false;
    }

    public static boolean isDateTimeStrValid(String dateStr) {

        if (StringUtils.isBlank(dateStr)) {
            return true;
        }

        String format = "yyyy-MM-dd HH:mm:ss";
        DateTimeFormatter ldt = DateTimeFormatter.ofPattern(format.replace("y", "u")).withResolverStyle(ResolverStyle.STRICT);
        try {
            return LocalDate.parse(dateStr, ldt) != null;
        } catch (Exception e) {
            return false;
        }
    }


}
