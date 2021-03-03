package com.om.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import com.om.Modules.mindSpore;
import com.om.Modules.openEuler;
import com.om.Modules.openGauss;
import com.om.Modules.openLookeng;
import com.om.Result.Constant;
import com.om.Utils.AsyncHttpUtil;
import com.om.Utils.PageUtils;
import com.om.Vo.Issue;
import com.om.Vo.MilestoneForIssueVo;
import org.apache.commons.lang3.StringUtils;
import org.asynchttpclient.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author xiazhonghai
 * @date 2021/2/1 18:27
 * @description:GiteeAllservice层
 */
@Service
public class GiteeIssueService {
    @Autowired
    QueryDao queryDao;

    static ObjectMapper objectMapper = new ObjectMapper();

    HashMap<String, ArrayList<Issue>> allissue = new HashMap<>();

    @Autowired
    RedisDao redisDao;

    @Value("${cveurl}")
    String CveUrl;

    @Autowired
    openEuler openEuler;

    @Autowired
    mindSpore mindSpore;

    @Autowired
    openGauss openGauss;

    @Autowired
    openLookeng openLookeng;

    @Autowired
    AsyncHttpUtil asyncHttpUtil;

    @Autowired
    private Environment env;

    public Map getIssueData(String community, String milestone, String state, int currentPage, int pageSize, String sortKey, String sortValue) {
        String index = "";
        String querystr = "";
        switch (community) {
            case Constant.openeuler:
                index = openEuler.getGiteeAllIndex();
                querystr = openEuler.getGiteeAll_qIssueStrBymil();
                break;
            case Constant.opengauss:
                index = openGauss.getGiteeAllIndex();
                querystr = openGauss.getGiteeAll_qIssueStrBymil();
                break;
            case Constant.openlookeng:
                index = openLookeng.getGiteeAllIndex();
                querystr = openLookeng.getGiteeAll_qIssueStrBymil();
                break;
            case Constant.mindspore:
                index = mindSpore.getGiteeAllIndex();
                querystr = mindSpore.getGiteeAll_qIssueStrBymil();
                break;
        }
        if (this.allissue.get(community) == null || this.allissue.get(community).size() <= 0) {
            //查询数据库，更新redis 缓存。
            if (StringUtils.isNotEmpty(index) && StringUtils.isNotEmpty(querystr)) {
                querystr = String.format(querystr);
            } else {
                System.out.println("query str format error");
            }
            try {
                String result = queryDao.query(index, querystr);
                Map datamap = objectMapper.readValue(result, Map.class);
                Map aggregations = (Map) datamap.get("hits");
                List<Map> buckets = (List) aggregations.get("hits");
                ArrayList<Issue> issvolist = new ArrayList<>();
                for (Map bucket : buckets) {
                    bucket = (Map) bucket.get("_source");
                    String issue_id = bucket.get("issue_id").toString();
                    String issue_title = bucket.get("issue_title").toString();
                    String issue_type = bucket.get("issue_type") == null ? "" : bucket.get("issue_type").toString();
                    String description = bucket.get("body") == null ? "" : bucket.get("body").toString();
                    String assignee_name = bucket.get("assignee_name") == null ? "" : bucket.get("assignee_name").toString();
                    String issue_state = bucket.get("issue_state") == null ? "" : bucket.get("issue_state").toString();
                    String plan_start_at = bucket.get("plan_started_at") == null ? "" : bucket.get("plan_started_at").toString();
                    String plan_deadline_at = bucket.get("deadline") == null ? "" : bucket.get("deadline").toString();
                    String closed_at = bucket.get("closed_at") == null ? "" : bucket.get("closed_at").toString();

                    String milestone_title = bucket.get("milestone_title").toString();

                    Issue issue = new Issue(issue_id, issue_title, issue_type, issue_state, description, assignee_name, plan_start_at, plan_deadline_at, closed_at, milestone_title);
                    issvolist.add(issue);
                }
                this.allissue.put(community, issvolist);
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
        if (StringUtils.isBlank(state)) {
            state = "all";
        }
        String returnalldata = "";
        if (currentPage == 0 || pageSize == 0) {
            returnalldata = "true";
        }
        if (StringUtils.isBlank(sortKey)) {
            sortKey = "closed_at";
        }
        if (StringUtils.isBlank(sortValue)) {
            sortValue = "descending";
        }
        ArrayList<Map> resultdata = new ArrayList<>();

        for (Issue issue : this.allissue.get(community)) {
            if (milestone == null) {
                if (!state.equals("all") && !state.equals(issue.getState())) {
                    continue;
                }
                HashMap<Object, Object> obj = new HashMap<>();
                obj.put("issue_id", issue.getId());
                obj.put("type", issue.getType());
                obj.put("state", issue.getState());
                obj.put("issue_title", issue.getTitle());
                obj.put("description", issue.getDescription());
                obj.put("plan_start_at", issue.getPlanStartAt());
                obj.put("plan_deadline_at", issue.getPlanDeadlineAt());
                obj.put("assignee_name", issue.getAssigeee());
                obj.put("closed_at", issue.getClosedAt());
                resultdata.add(obj);
            } else {
                if (milestone.equals(issue.getMileStone())) {
                    if (!state.equals("all") && !state.equals(issue.getState())) {
                        continue;
                    }
                    HashMap<Object, Object> obj = new HashMap<>();
                    obj.put("issue_id", issue.getId());
                    obj.put("type", issue.getType());
                    obj.put("state", issue.getState());
                    obj.put("issue_title", issue.getTitle());
                    obj.put("description", issue.getDescription());
                    obj.put("plan_start_at", issue.getPlanStartAt());
                    obj.put("plan_deadline_at", issue.getPlanDeadlineAt());
                    obj.put("assignee_name", issue.getAssigeee());
                    obj.put("closed_at", issue.getClosedAt());
                    resultdata.add(obj);
                }
            }
        }

        sortDataByType(resultdata, sortKey, sortValue);
        if ("true".equals(returnalldata)) {
        }
	if(currentPage==0||pageSize==0){
		HashMap resultmap=new HashMap();
		resultmap.put("data",resultdata);
		resultmap.put("total",resultdata.size());
		return resultmap;
	}
        return PageUtils.getDataByPage(currentPage, pageSize, resultdata);
    }

    public void sortDataByType(List<Map> resultdata, String type, String sortValue) {
        switch (type) {
            case "closed_at":
                if (sortValue.equals("ascending")) {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("closed_at") == null ? "" : a.get("closed_at").toString()));
                } else {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("closed_at") == null ? "" : a.get("closed_at").toString()));
                    Collections.reverse(resultdata);
                }
                break;
            case "issue_type":
                if (sortValue.equals("ascending")) {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("type") == null ? "" : a.get("type").toString()));
                } else {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("type") == null ? "" : a.get("type").toString()));
                    Collections.reverse(resultdata);
                }
                break;
            case "issue_state":
                if (sortValue.equals("ascending")) {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("state") == null ? "" : a.get("state").toString()));
                } else {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("state") == null ? "" : a.get("state").toString()));
                    Collections.reverse(resultdata);
                }
                break;
            case "plan_start_at":
                if (sortValue.equals("ascending")) {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("plan_start_at") == null ? "" : a.get("plan_start_at").toString()));
                } else {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("plan_start_at") == null ? "" : a.get("plan_start_at").toString()));
                    Collections.reverse(resultdata);
                }
                break;
        }
    }

    public Map getIssueById(String index, Long id) throws JsonProcessingException, KeyManagementException, NoSuchAlgorithmException {
        String querystr = String.format("{\"query\":{\"term\":{\"_id\":\"%s\"}}}", id);
        String data = queryDao.query(index, querystr);
        if (StringUtils.isNotEmpty(data)) {
            Map map = objectMapper.readValue(data, Map.class);
            return map;
        } else {
            return null;
        }
    }

    public Map getIssueByIssueNumber(String index, String number) throws JsonProcessingException, KeyManagementException, NoSuchAlgorithmException {
        String querystr = String.format("{\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"issue_number.keyword:\\\"%s\\\" AND is_gitee_issue:1\"}}]}}}", number);
        String data = queryDao.query(index, querystr);
        if (StringUtils.isNotEmpty(data)) {
            Map map = objectMapper.readValue(data, Map.class);
            try {
                return (Map) ((List<Map>) ((Map) map.get("hits")).get("hits")).get(0).get("_source");
            } catch (Exception e) {
                System.out.println("error issue number " + number);
                e.printStackTrace();
                return null;
            }
        } else {
            return null;
        }
    }

    public List<Map> assIssCve(String index, Map cvemap) throws JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        List<Map> bodys = (List) cvemap.get("body");
        ArrayList<Map> result = new ArrayList<>();
        for (Map body : bodys) {
            String issueNumber = body.get("issue_id").toString();
            Map issueData = getIssueByIssueNumber(index, issueNumber);
            if (issueData == null) {
                System.out.println(String.format("cve issue number %s not found in issue table", issueNumber));
                result.add(body);
                continue;
            }
            body.put("issue_title", issueData.get("issue_title"));
            body.put("type", issueData.get("issue_type"));
            //issue body 为描述 目前数据库中没有使用issue_title_analyzed代替
            body.put("description", issueData.get("body"));
            body.put("assignee_name", issueData.get("assignee_name"));
            body.put("state", issueData.get("issue_state"));
            body.put("plan_start_at", issueData.get("plan_start_at"));
            body.put("plan_deadline_at", issueData.get("plan_deadline_at"));
            body.put("closed_at", issueData.get("closed_at"));
            result.add(body);
        }
        return result;
    }

    private String getIndexByCommunity(String communtiy) {
        String index = "";
        switch (communtiy) {
            case Constant.openeuler:
                index = openEuler.getGiteeAllIndex();
                break;
            case Constant.opengauss:
                index = openGauss.getGiteeAllIndex();
                break;
            case Constant.openlookeng:
                index = openLookeng.getGiteeAllIndex();
                break;
            case Constant.mindspore:
                index = mindSpore.getGiteeAllIndex();
                break;
        }
        return index;
    }

    public Map getCveData(MilestoneForIssueVo vo) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {

        String result = (String) redisDao.get(Constant.allIssueResult + vo.getCommunity());
        if (result == null || result.equals("")) {
            //从缓存中获取数据
            String resCveStr = (String) redisDao.get(Constant.allIssueCveStr + vo.getCommunity());
            if (resCveStr == null || resCveStr.equals("")) {
                resCveStr = getAllCveStr();
                redisDao.set(Constant.allIssueCveStr + vo.getCommunity(), resCveStr, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            }
            Map cvemap = objectMapper.readValue(resCveStr, Map.class);
            List resultList = assIssCve(getIndexByCommunity(vo.getCommunity()), cvemap);
            result = objectMapper.writeValueAsString(resultList);
            redisDao.set(Constant.allIssueResult + vo.getCommunity(), result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
        }
        List<Map> resultList = objectMapper.readValue(result, List.class);
        Stream<Map> resutstream = resultList.stream().filter(o -> {
            Object state = o.get("state");
            Object milestone = o.get("milestone");
            String milestonein = vo.getMilestone();
            int milestoneresult = 0;
            int stateresult = 0;

            if ("all".equals(vo.getState()) || StringUtils.isEmpty(vo.getState())) {
                stateresult = 1;
            } else {
                if (vo.getState().equals(state)) {
                    stateresult = 1;
                } else {
                    stateresult = 0;

                }
            }
            if (milestonein == null) {
                milestoneresult = 1;
            } else {
                if(milestone==null){
                    milestoneresult=0;
                }else{
                    String[] milestoneItem = milestone.toString().split(",");
                    for (String s : milestoneItem) {
                        String[] milestoneAffect= s.split(":");
                        if(milestoneAffect.length==2&&milestoneAffect[0].equals(milestonein)&&milestoneAffect[1].equals("受影响")){
                            milestoneresult=1;
                        }
                    }
                }
            }
            if (milestoneresult == 1 && stateresult == 1) {
                return true;
            } else {
                return false;
            }
        });
        resultList = resutstream.collect(Collectors.toList());
        sortDataByType(resultList, vo.getSortKey(), vo.getSortValue());
        if(vo.getCurrentPage()==null||vo.getPageSize()==null){
            HashMap<Object, Object> resultmap = new HashMap<>();
            resultmap.put("data",resultList);
            resultmap.put("total",resultList.size());
                    return resultmap;

        }
        Map dataByPage = PageUtils.getDataByPage(Integer.parseInt(vo.getCurrentPage()), Integer.parseInt(vo.getPageSize()), resultList);
        return dataByPage;

    }

    /***
     * 功能描述:获取cve中的所有数据
     * @return: java.lang.String
     * @Author: xiazhonghai
     * @Date: 2021/2/25 9:31
     */
    public String getAllCveStr() throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        builder.setUrl(CveUrl);
        builder.setMethod("GET");
        String resCveStr = "";
        Request build = null;
        ArrayList<Param> params = new ArrayList<>();
        params.add(new Param("currentPage", "1"));
        params.add(new Param("pageSize", "1"));
        build = builder.setQueryParams(params).build();
        ListenableFuture<Response> reslisfu = client.executeRequest(build);
        Response response = reslisfu.get();
        resCveStr = response.getResponseBody(StandardCharsets.UTF_8);
        Map cvemap = objectMapper.readValue(resCveStr, Map.class);
        String total = cvemap.get("total").toString();

        RequestBuilder builder2 = asyncHttpUtil.getBuilder();
        builder2.setUrl(CveUrl);
        builder2.setMethod("GET");
        ArrayList<Param> params2 = new ArrayList<>();
        params2.add(new Param("currentPage", "1"));
        params2.add(new Param("pageSize", total));
        Request build2 = builder2.setQueryParams(params2).build();
        ListenableFuture<Response> reslisfu2 = client.executeRequest(build2);
        Response response2 = reslisfu2.get();
        resCveStr = response2.getResponseBody(StandardCharsets.UTF_8);
        return resCveStr;
    }
}
