package com.om.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.RedisDao;
import com.om.Modules.mindSpore;
import com.om.Modules.openEuler;
import com.om.Modules.openGauss;
import com.om.Modules.openLookeng;
import com.om.Utils.AsyncHttpUtil;
import com.om.Utils.PageUtils;
import org.apache.commons.lang3.StringUtils;
import org.asynchttpclient.ListenableFuture;
import org.asynchttpclient.Request;
import org.asynchttpclient.RequestBuilder;
import org.asynchttpclient.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * @author xiazhonghai
 * @date 2021/3/8 17:25
 * @description:
 */
@Service
public class VersionService {
    @Autowired
    RedisDao redisDao;
    @Autowired
    @Value("${esurl}")
    String url;
    @Autowired
    openEuler openeuler;
    @Autowired
    openGauss opengauss;
    @Autowired
    openLookeng openlookeng;
    @Autowired
    mindSpore mindspore;
    @Autowired
    AsyncHttpUtil asyncHttpUtil;
    @Autowired
    private Environment env;

    private static final String redisKey = "VERSION";

    private static ObjectMapper objectMapper = new ObjectMapper();

    private static final String giteeHosts = "https://gitee.com/";


    /***
     * 功能描述:
     * @param community:
     * @param repo:
     * @param pageSize:
     * @param currentPage:
     * @return: java.util.List
     * @Author: xiazhonghai
     * @Date: 2021/3/22 10:18
     */

    public Map getVersionByRepoBranch(String community, String repo, int pageSize, int currentPage) throws JsonProcessingException, InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException {

        String data = (String) redisDao.get(community + redisKey);
        if (StringUtils.isBlank(data)) {
            String url = "";
            long expire = 1000;
            switch (community) {
                case "openeuler":
                    url = this.url + openeuler.getGiteeAllIndex() + "/_search";
                    expire = Long.valueOf(env.getProperty("spring.redis.keyexpire"));
                    break;
                case "openlookeng":
                    url = this.url + openlookeng.getGiteeAllIndex() + "/_search";
                    expire = Long.valueOf(env.getProperty("spring.redis.keyexpire"));
                    break;
                case "opengauss":
                    url = this.url + opengauss.getGiteeAllIndex() + "/_search";
                    expire = Long.valueOf(env.getProperty("spring.redis.keyexpire"));
                    break;
                case "mindspore":
                    url = this.url + mindspore.getGiteeAllIndex() + "/_search";
                    expire = Long.valueOf(env.getProperty("spring.redis.keyexpire"));
                    break;
            }
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            String bodyData = "{\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"is_gitee_repo:1\"}}]}},\"_source\":[\"branches\"],\"size\":10000}";
            Request request = builder.setUrl(url).setBody(bodyData).build();
            ListenableFuture<Response> future = AsyncHttpUtil.getClient().executeRequest(request);
            Response response = future.get();
            String responseBody = response.getResponseBody(StandardCharsets.UTF_8);
            redisDao.set(community + redisKey, responseBody, expire);
            Map map = assemblyData(repo, responseBody, currentPage, pageSize);
            return map;
        } else {
            Map map = assemblyData(repo, data, currentPage, pageSize);
            return map;
        }

    }

    /***
     * 功能描述:组装过滤数据
     * @param branch:分支名称
     * @param data: 待处理数据，使用json 反序列化
     * @param page: 分页
     * @param pageSize:一页多少数据
     * @return: java.util.List
     * @Author: xiazhonghai
     * @Date: 2021/3/22 11:27
     */
    private Map assemblyData(String repo, String data, int page, int pageSize) throws JsonProcessingException {
        Map allDataMap = objectMapper.readValue(data, Map.class);
        List<Map> datas = (List) (((Map) allDataMap.get("hits")).get("hits"));
        Stream<Map> source = datas.stream().filter(map -> {
            Object source1 = map.get("_source");
            if (map == null || ((Map) source1).size() <= 0) {
                return false;
            }
            return true;
        });
        if (StringUtils.isNotBlank(repo)) {
            source = source.filter(map -> {
                String id = map.get("_id").toString();
                String repoName = id.substring(id.lastIndexOf("/") + 1);
                if (repo.equals(repoName)) {
                    return true;
                } else {
                    return false;
                }
            });
        }
        List<Map> collect = source.collect(Collectors.toList());
        for (Map map : collect) {
            map.remove("_type");
            map.remove("_score");
            map.remove("_index");
            String id = map.remove("_id").toString();
            String repoName = id.substring(id.lastIndexOf("/") + 1);
            Object sourceItem = map.remove("_source");
            map.put(repoName, sourceItem);
            //对description 进行下类型转换
            List branches = (List) ((Map) sourceItem).get("branches");
            if (branches != null && branches.size() > 0) {
                for (Map branch : (List<Map>) branches) {
                    List description = (List) branch.remove("description");
                    if (description == null) {
                        branch.put("description", "");
                    } else {
                        branch.put("description", description.get(0));
                    }

                }
            }
        }
        if(pageSize==0||page==0){
            Map map = new HashMap();
            map.put("data",collect);
            map.put("total",collect.size());
            return map;
        }else {
            Map dataByPage = PageUtils.getDataByPage(page, pageSize, collect);
            return dataByPage;
        }
    }
//   /***
//    * 功能描述:get all repos according to community name
//    * @param community: 社区名
//    * @param accessToken: gitee accessToken
//    * @return: java.util.List<java.util.Map>
//    * @Author: xiazhonghai
//    * @Date: 2021/3/10 11:52
//    */
//    public static List<Map> getAll(String community,String accessToken) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
//        //获取所有仓库信息
//        String url=giteeHosts+"api/v5/enterprises/"+community+"/repos";
//        String paramsFormat="?access_token=%s&visibility=%s&sort=%s&direction=%s&page=%d&per_page=%d";
//        String params= String.format(paramsFormat,accessToken,"all","full_name","asc",1,100);
//        Response response = AsyncHttpUtil.getHTML(url + params, "GET", Collections.emptyMap());
//        String responseBody = response.getResponseBody(StandardCharsets.UTF_8);
//        List list = objectMapper.readValue(responseBody, List.class);
//        ArrayList<Map> results = new ArrayList<>();
//        results.addAll(list);
//        //总共有多少页
//        String total_page = response.getHeader("total_page");
//        //循环获取所有数据
//
//
//    }

    /***
     * 功能描述:
     * @param datas:传入数据
     * @param community: 社区名称
     * @param repo: 仓库名称
     * @param branch:分支名称
     * @return: java.util.List
     * @Author: xiazhonghai
     * @Date: 2021/3/9 9:38
     */
    public static List filterDataByConditions(List<Map> datas, String repo, String branch) {
        //如果为空返回对应的全部数据 eg repo 为空返回该社区的所有repo对应的version数据
        Stream<Map> resultData = datas.stream().filter(map -> {
            boolean returnAllRepo = false;
            boolean returnAllBranch = false;
            String repoName = map.get("repo").toString();
            String repoBranch = map.get("branch").toString();
            if (StringUtils.isBlank(repo)) {
                returnAllRepo = true;
            }
            if (StringUtils.isBlank(branch)) {
                returnAllBranch = true;
            }
            if (returnAllBranch && returnAllRepo) {
                //repo 不为空，branch 为空 返回此branch的所有数据/
                return true;
            } else if (returnAllBranch) {
                //repo 不为空，branch 为空 返回此branch的所有数据
                if (repoName.equals(repo)) {
                    return true;
                }
            } else {
                //repo 不为空 branch 不为空，返回指定repo 中指定branch的数据。

                if (repoName.equals(repo) && repoBranch.equals(branch)) {
                    return true;
                }
            }
            return false;
        });
        List<Map> collect = resultData.collect(Collectors.toList());
        return collect;
    }
}
