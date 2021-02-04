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
import com.om.Utils.AsyncHttpUtil;
import com.om.Utils.ContributionCompatorByComments;
import com.om.Utils.ContributionCompatorByIssue;
import com.om.Utils.ContributionCompatorByPr;
import com.om.Vo.ContributionResultVo;
import com.om.Vo.ContributionResultVoPie;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
public class ContributionDataService {
    @Autowired
    QueryDao queryDao;


    @Autowired
    AsyncHttpUtil asyncHttpUtil;

    @Value("${esurl}")
    String url;

    @Value("${userpass}")
    String user_pass;

    static ObjectMapper objectMapper = new ObjectMapper();

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

    Map<String, List<ContributionResultVo>> allCondata = new HashMap();
    Map<String, List<ContributionResultVo>> allCondatasortbypr = new HashMap();
    Map<String, List<ContributionResultVo>> allCondatasortbyissue = new HashMap();
    Map<String, List<ContributionResultVo>> allCondatasorybycomments = new HashMap();

    private void refreCacheData(String community) {
        String index = "";
        String querystr = "";
        switch (community) {
            case Constant.openeuler:
                index = openEuler.getGiteeAllIndex();
                querystr = openEuler.getGiteeAllQueryAllstr();
                break;
            case Constant.opengauss:
                index = openGauss.getGiteeAllIndex();
                querystr = openGauss.getGiteeAllQueryAllstr();
                break;
            case Constant.openlookeng:
                index = openLookeng.getGiteeAllIndex();
                querystr = openLookeng.getGiteeAllQueryAllstr();
                break;
            case Constant.mindspore:
                index = mindSpore.getGiteeAllIndex();
                querystr = mindSpore.getGiteeAllQueryAllstr();
                break;
        }

        if (this.allCondata.get(community) == null || this.allCondata.get(community).size() <= 0) {
            //查询数据库，更新redis 缓存。
            if (StringUtils.isNotEmpty(index) && StringUtils.isNotEmpty(querystr)) {
                querystr = String.format(querystr);
            } else {
                System.out.println("query str format error");
            }
            try {
                String result = queryDao.query(index, querystr);
                Map datamap = objectMapper.readValue(result, Map.class);
                Map aggregations = (Map) datamap.get("aggregations");
                Map tag_user_company = (Map) aggregations.get("tag_user_company");
                List<Map> buckets = (List) tag_user_company.get("buckets");
                ArrayList<ContributionResultVo> convolist = new ArrayList<>();
                for (Map bucket : buckets) {
                    Map user_login = (Map) bucket.get("user_login");
                    String company = bucket.get("key").toString();
                    List<Map> userbucktes = (List) user_login.get("buckets");
                    for (Map userbuckte : userbucktes) {
                        Double review_comment = (Double) ((Map) userbuckte.get("is_gitee_review_comment")).get("value");
                        Double issue_comment = (Double) ((Map) userbuckte.get("is_gitee_issue_comment")).get("value");
                        Double issue = (Double) ((Map) userbuckte.get("is_gitee_issue")).get("value");
                        Double pr = (Double) ((Map) userbuckte.get("is_gitee_pull_request")).get("value");
                        String name = userbuckte.get("key").toString();
                        ContributionResultVo contributionResultVo = new ContributionResultVo();
                        contributionResultVo.setComments(review_comment + issue_comment);
                        contributionResultVo.setIssue(issue);
                        contributionResultVo.setPr(pr);
                        contributionResultVo.setName(name);
                        contributionResultVo.setOriganization(company);
                        convolist.add(contributionResultVo);
                    }
                }
                this.allCondata.put(community, convolist);
                ArrayList<ContributionResultVo> issuelist = new ArrayList<>();
                ArrayList<ContributionResultVo> prlist = new ArrayList<>();
                ArrayList<ContributionResultVo> commentlist = new ArrayList<>();
                issuelist.addAll(convolist);
                prlist.addAll(convolist);
                commentlist.addAll(convolist);
                this.allCondatasortbyissue.put(community, issuelist);
                this.allCondatasortbypr.put(community, prlist);
                this.allCondatasorybycomments.put(community, commentlist);
                Collections.sort(this.allCondatasortbypr.get(community), ((o1, o2) -> ((Double) ((o1.getPr()) - (o2.getPr()))).intValue()));
                Collections.sort(this.allCondatasortbyissue.get(community), ((o1, o2) -> ((Double) ((o1.getIssue()) - (o2.getIssue()))).intValue()));
                Collections.sort(this.allCondatasorybycomments.get(community), ((o1, o2) -> ((Double) ((o1.getComments()) - (o2.getComments()))).intValue()));
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
    }

    public List getContributionData(String community, String type, String individualSearchKey, String organizationSearchKey, int currentPage, int pageSize, String sortKey, String sortValue) {
        refreCacheData(community);
        ArrayList<Object> resultdata = new ArrayList<>();
        switch (sortKey) {
            case "pr":
                List<ContributionResultVo> prdatacache = this.allCondatasortbypr.get(community);
                if (Constant.individual.equals(type) && individualSearchKey != null) {
                    ArrayList<ContributionResultVo> indivilist = new ArrayList<>();
                    for (ContributionResultVo prvo : prdatacache) {
                        if (prvo.getName().equals(individualSearchKey)) {
                            indivilist.add(prvo);
                        }
                    }
                    prdatacache = indivilist;
                } else if (Constant.organization.equals(type) && organizationSearchKey != null) {
                    ArrayList<ContributionResultVo> orglist = new ArrayList<>();
                    for (ContributionResultVo prvo : prdatacache) {
                        if (prvo.getOriganization().equals(organizationSearchKey)) {
                            orglist.add(prvo);
                        }
                    }
                    prdatacache = orglist;
                }
                if ("ascending".equals(sortValue)) {
                    int size = this.allCondatasortbypr.size();
                    //索引越界，返回最后一页数据
                    int lastpage = size % pageSize;
                    int startindex = (currentPage - 1) * pageSize;
                    int endindex = currentPage * pageSize - 1;
                    if (endindex > prdatacache.size()) {
                        endindex = startindex + lastpage - 1;
                    }
                    for (int i = startindex; i <= endindex; i++) {
                        ContributionResultVo contributionResultVo = prdatacache.get(i);
                        contributionResultVo.setRanking(i + 1 + 0d);
                        resultdata.add(contributionResultVo);
                    }
                } else {
                    ArrayList<ContributionResultVo> resverse = new ArrayList<>();
                    resverse.addAll(prdatacache);
                    Collections.reverse(resverse);
                    int size = resverse.size();
                    //索引越界，返回最后一页数据
                    int lastpage = size % pageSize;
                    int startindex = (currentPage - 1) * pageSize;
                    int endindex = currentPage * pageSize - 1;
                    if (endindex > resverse.size()) {
                        endindex = startindex + lastpage - 1;
                    }
                    for (int i = startindex; i <= endindex; i++) {
                        ContributionResultVo contributionResultVo = resverse.get(i);
                        contributionResultVo.setRanking(i + 1 + 0d);
                        resultdata.add(resverse.get(i));
                    }
                }
                break;
            case "issue":
                List<ContributionResultVo> issuedatacache = this.allCondatasortbyissue.get(community);
                if (Constant.individual.equals(type) && individualSearchKey != null) {
                    ArrayList<ContributionResultVo> indivilist = new ArrayList<>();
                    for (ContributionResultVo prvo : issuedatacache) {
                        if (prvo.getName().equals(individualSearchKey)) {
                            indivilist.add(prvo);
                        }
                    }
                    issuedatacache = indivilist;
                } else if (Constant.organization.equals(type) && organizationSearchKey != null) {
                    ArrayList<ContributionResultVo> orglist = new ArrayList<>();
                    for (ContributionResultVo prvo : issuedatacache) {
                        if (prvo.getOriganization().equals(organizationSearchKey)) {
                            orglist.add(prvo);
                        }
                    }
                    issuedatacache = orglist;
                }
                if ("ascending".equals(sortValue)) {
                    int size = this.allCondatasortbyissue.size();
                    //索引越界，返回最后一页数据
                    int lastpage = size % pageSize;
                    int startindex = (currentPage - 1) * pageSize;
                    int endindex = currentPage * pageSize - 1;
                    if (endindex > issuedatacache.size()) {
                        endindex = startindex + lastpage - 1;
                    }
                    for (int i = startindex; i <= endindex; i++) {
                        ContributionResultVo contributionResultVo = issuedatacache.get(i);
                        contributionResultVo.setRanking(i + 1 + 0d);
                        resultdata.add(contributionResultVo);
                    }
                } else {
                    ArrayList<ContributionResultVo> resverse = new ArrayList<>();
                    resverse.addAll(issuedatacache);
                    Collections.reverse(resverse);
                    int size = resverse.size();
                    //索引越界，返回最后一页数据
                    int lastpage = size % pageSize;
                    int startindex = (currentPage - 1) * pageSize;
                    int endindex = currentPage * pageSize - 1;
                    if (endindex > resverse.size()) {
                        endindex = startindex + lastpage - 1;
                    }
                    for (int i = startindex; i <= endindex; i++) {
                        ContributionResultVo contributionResultVo = resverse.get(i);
                        contributionResultVo.setRanking(i + 1 + 0d);
                        resultdata.add(resverse.get(i));
                    }
                }
                break;
            case "comments":
                List<ContributionResultVo> commentsatacache = this.allCondatasorybycomments.get(community);
                if (Constant.individual.equals(type) && individualSearchKey != null) {
                    ArrayList<ContributionResultVo> indivilist = new ArrayList<>();
                    for (ContributionResultVo prvo : commentsatacache) {
                        if (prvo.getName().equals(individualSearchKey)) {
                            indivilist.add(prvo);
                        }
                    }
                    commentsatacache = indivilist;
                } else if (Constant.organization.equals(type) && organizationSearchKey != null) {
                    ArrayList<ContributionResultVo> orglist = new ArrayList<>();
                    for (ContributionResultVo prvo : commentsatacache) {
                        if (prvo.getOriganization().equals(organizationSearchKey)) {
                            orglist.add(prvo);
                        }
                    }
                    commentsatacache = orglist;
                }
                if ("ascending".equals(sortValue)) {
                    int size = this.allCondatasortbyissue.size();
                    //索引越界，返回最后一页数据
                    int lastpage = size % pageSize;
                    int startindex = (currentPage - 1) * pageSize;
                    int endindex = currentPage * pageSize - 1;
                    if (endindex > commentsatacache.size()) {
                        endindex = startindex + lastpage - 1;
                    }
                    for (int i = startindex; i <= endindex; i++) {
                        ContributionResultVo contributionResultVo = commentsatacache.get(i);
                        contributionResultVo.setRanking(i + 1 + 0d);
                        resultdata.add(contributionResultVo);
                    }
                } else {
                    ArrayList<ContributionResultVo> resverse = new ArrayList<>();
                    resverse.addAll(commentsatacache);
                    Collections.reverse(resverse);
                    int size = resverse.size();
                    //索引越界，返回最后一页数据
                    int lastpage = size % pageSize;
                    int startindex = (currentPage - 1) * pageSize;
                    int endindex = currentPage * pageSize - 1;
                    if (endindex > resverse.size()) {
                        endindex = startindex + lastpage - 1;
                    }
                    for (int i = startindex; i <= endindex; i++) {
                        ContributionResultVo contributionResultVo = resverse.get(i);
                        contributionResultVo.setRanking(i + 1 + 0d);
                        resultdata.add(resverse.get(i));
                    }
                }
                break;
        }


        return resultdata;

    }

    public List getContributionDataPie(String community, String type) {
        refreCacheData(community);
        ArrayList<ContributionResultVoPie> resultlist = new ArrayList<>();
        switch (type) {
            case "pr":
                List<ContributionResultVo> prlist = this.allCondatasortbypr.get(community);
                for (ContributionResultVo vo : prlist) {
                    ContributionResultVoPie prpie = new ContributionResultVoPie();
                    prpie.setName(vo.getName());
                    prpie.setNumber(vo.getPr());
                    resultlist.add(prpie);
                }
                break;
            case "issue":
                List<ContributionResultVo> issuelist = this.allCondatasortbyissue.get(community);
                for (ContributionResultVo vo : issuelist) {
                    ContributionResultVoPie prpie = new ContributionResultVoPie();
                    prpie.setName(vo.getName());
                    prpie.setNumber(vo.getIssue());
                    resultlist.add(prpie);
                }
                break;
            case "comments":
                List<ContributionResultVo> commentsuelist = this.allCondatasorybycomments.get(community);
                for (ContributionResultVo vo : commentsuelist) {
                    ContributionResultVoPie compie = new ContributionResultVoPie();
                    compie.setName(vo.getName());
                    compie.setNumber(vo.getComments());
                    resultlist.add(compie);
                }
                break;
        }
        return resultlist;
    }

}
