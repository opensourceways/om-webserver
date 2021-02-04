package com.om.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import com.om.Modules.openEuler;
import com.om.Modules.openGauss;
import com.om.Modules.openLookeng;
import com.om.Result.Constant;
import com.om.Result.Failed;
import com.om.Result.Result;
import com.om.Result.Success;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author xiazhonghai
 * @date 2021/2/1 18:27
 * @description:GiteeAllservice层
 */
@Service
public class GiteeAllService {
    @Autowired
    QueryDao queryDao;

    static ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    RedisDao redisDao;

    @Autowired
    openEuler openEuler;

    @Autowired
    openGauss openGauss;

    @Autowired
    openLookeng openLookeng;

    @Autowired
    private Environment env;

    public Result getIssueData(String community, String milestone, String state, int currentPage, int pageSize, String sortKey, String sortValue) {
        String index = "";
        String querystr = "";
        switch (community) {
            case Constant.openeuler:
                index = openEuler.getGiteeAllIndex();
                querystr = openEuler.getGiteeAllQuerystr();
                break;
            case Constant.opengauss:
                index = openGauss.getGiteeAllIndex();
                querystr = openGauss.getGiteeAllQuerystr();
                break;
            case Constant.openlookeng:
                index = openLookeng.getGiteeAllIndex();
                querystr = openLookeng.getGiteeAllQuerystr();
                break;
        }
        if (StringUtils.isNotEmpty(index) && StringUtils.isNotEmpty(querystr)) {

        }
        String key = community + "issue" + currentPage + "" + pageSize;
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
           querystr= String.format(querystr,milestone);
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.query(index,querystr);
                Map datamap = objectMapper.readValue(result, Map.class);
                List<Map> resultdata = getresultMap(datamap);
                boolean set = redisDao.set(key, objectMapper.writeValueAsString(resultdata), Long.valueOf(env.getProperty("spring.redis.keyexpire")));
                if (set) {
                    System.out.println("update " + key + " success!");

                }
                return new Success().setCode(200).setMessage("Success").setTotal(resultdata.size()).setData(resultdata);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            } catch (JsonMappingException e) {
                e.printStackTrace();
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }

        }
        try {
            List list = objectMapper.readValue(result, List.class);
            return new Success().setCode(200).setMessage("Success").setTotal(list.size()).setData(list);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return new Failed().setCode(500).setMessage("Failed").setTotal(0).setData(null);
        }
    }

    /***
     * 功能描述:提取业务需要的数据map
     * @param datamap: 从es中获取的数据map
     * @return: java.util.Map
     * @Author: xiazhonghai
     * @Date: 2021/2/1 18:59
     */
    private List<Map> getresultMap(Map datamap) {
        ArrayList<Map> resultList = new ArrayList<>();
        Map hits = (Map) datamap.get("hits");
        List<Map> dataList = (List<Map>) hits.get("hits");
        for (Map m : dataList) {
            Map source = (Map) m.get("_source");
            String issue_id = source.get("issue_id") + "";
            String issue_title = source.get("issue_title") + "";
            String issue_type = source.get("issue_type") + "";
            String description = source.get("issue_body") + "";
            String assignee_name = source.get("assignee_name") + "";
            String state = source.get("assignee_name") + "";
            String issue_state = source.get("issue_state") + "";
            String plan_start_at = source.get("plan_start_at") + "";
            String plan_deadline_at = source.get("plan_deadline_at") + "";
            String closed_at = source.get("closed_at") + "";
            HashMap<String, String> resultmap = new HashMap<>();
            resultmap.put("issue_id", issue_id);
            resultmap.put("issue_title", issue_title);
            resultmap.put("issue_type", issue_type);
            resultmap.put("description", description);
            resultmap.put("assignee_name", assignee_name);
            resultmap.put("state", state);
            resultmap.put("issue_state", issue_state);
            resultmap.put("plan_start_at", plan_start_at);
            resultmap.put("plan_deadline_at", plan_deadline_at);
            resultmap.put("closed_at", closed_at);
            resultList.add(resultmap);
        }
        return resultList;
    }
}
