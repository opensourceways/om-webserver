package com.om.Utils;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author xiazhonghai
 * @date 2021/2/23 14:15
 * @description:分页工具类
 */
public class PageUtils {
    /***
     * 功能描述:根据指定currentpage pagesize 返回指定的数据
     * @param currentPage:当前页
     * @param pageSize:每页数据
     * @param data:传入数据
     * @return: java.util.Map
     * @Author: xiazhonghai
     * @Date: 2021/2/23 14:23
     */
    public static Map getDataByPage(int currentPage, int pageSize, List data) {
        int datasize = data.size();
        int totalPage = datasize / pageSize + 1;

        HashMap<Object, Object> resultMap = new HashMap<>();
        int startindex = (currentPage - 1) * pageSize;
        int endindex = currentPage * pageSize;
        try {
            if (currentPage >= totalPage) {
                List list = data.subList(startindex, datasize);
                resultMap.put("data", list);
                resultMap.put("total", datasize);
            } else {
                List list = data.subList(startindex, endindex);
                resultMap.put("data", list);
                resultMap.put("total", datasize);
            }
        } catch (Exception e) {
            e.printStackTrace();
            resultMap.put("data", null);
            resultMap.put("total", datasize);
        }
        return resultMap;
    }
}
