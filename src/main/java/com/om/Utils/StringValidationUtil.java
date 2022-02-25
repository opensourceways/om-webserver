package com.om.Utils;

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

}
