package com.om.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import com.om.Modules.mindSpore;
import com.om.Modules.openEuler;
import com.om.Modules.openGauss;
import com.om.Modules.openLookeng;
import com.om.Result.Constant;
import com.om.Result.Failed;
import com.om.Result.Result;
import com.om.Result.Success;
import com.om.Vo.ContributionResultVo;
import com.om.Vo.Issue;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

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

    HashMap<String,ArrayList<Issue>> allissue=new HashMap<>();

    @Autowired
    RedisDao redisDao;

    @Autowired
    openEuler openEuler;

    @Autowired
    mindSpore mindSpore;

    @Autowired
    openGauss openGauss;

    @Autowired
    openLookeng openLookeng;

    @Autowired
    private Environment env;

    public List getIssueData(String community, String milestone, String state, int currentPage, int pageSize, String sortKey, String sortValue) {
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
                    bucket=(Map)bucket.get("_source");
                        String issue_id =  bucket.get("issue_id").toString();
                        String issue_title =  bucket.get("issue_title").toString();
                        String issue_type =  "缺陷";
                        String description =  "这是一个缺陷";
                        String assignee_name =  "unknow";
                        String issue_state=bucket.get("issue_state").toString();
                        String plan_start_at=new Date().toString();
                        String plan_deadline_at=new Date().toString();
                        String closed_at=bucket.get("closed_at")==null?"":bucket.get("closed_at").toString();
                        String milestone_title=bucket.get("milestone_title").toString();

                    Issue issue = new Issue(issue_id, issue_title, issue_type, issue_state, description, assignee_name, plan_start_at, plan_deadline_at, closed_at,milestone_title);
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
        if(StringUtils.isBlank(state)){
            state="all";
        }
        String returnalldata="";
        if(currentPage==0||pageSize==0){
            returnalldata="true";
        }
        if(StringUtils.isBlank(sortKey)){
            sortKey="closed_at";
        }
        if(StringUtils.isBlank(sortValue)){
            sortValue="descending";
        }
        ArrayList<Map> resultdata = new ArrayList<>();
        for (Issue issue : this.allissue.get(community)) {
            if(milestone.equals(issue.getMileStone())){
                if(!state.equals("all")&&!state.equals(issue.getState())){
                    continue;
                }
                HashMap<Object, Object> obj = new HashMap<>();
                obj.put("issue_id",issue.getId());
                obj.put("type",issue.getType());
                obj.put("state",issue.getState());
                obj.put("issue_title",issue.getTitle());
                obj.put("description",issue.getDescription());
                obj.put("plan_start_at",issue.getPlanStartAt());
                obj.put("plan_deadline_at",issue.getPlanDeadlineAt());
                obj.put("closed_at",issue.getClosedAt());
                resultdata.add(obj);
            }
        }

        switch (sortKey){
            case "closed_at":
                if(sortValue.equals("ascending")){
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("closed_at").toString()));
                }else {
                    Collections.sort(resultdata, Comparator.comparing(a ->a.get("closed_at").toString()));
                    Collections.reverse(resultdata);
                }
                break;
            case "issue_type":
                if(sortValue.equals("ascending")){
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("type").toString()));
                }else {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("type").toString()));
                    Collections.reverse(resultdata);
                }
                break;
            case "issue_state":
                if(sortValue.equals("ascending")){
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("state").toString()));
                }else {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("state").toString()));
                    Collections.reverse(resultdata);
                }
                break;
            case "plan_merage_at":
                if(sortValue.equals("ascending")){
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("plan_start_at").toString()));
                }else {
                    Collections.sort(resultdata, Comparator.comparing(a -> a.get("plan_start_at").toString()));
                    Collections.reverse(resultdata);
                }
                break;

        }
        if("true".equals(returnalldata)){
        }
        //todo分页
        return resultdata;
    }
}
