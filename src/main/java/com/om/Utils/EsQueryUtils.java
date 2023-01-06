/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.UserTagInfo;
import com.om.Vo.PrReviewerVo;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.search.*;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.query.*;
import org.elasticsearch.index.reindex.BulkByScrollResponse;
import org.elasticsearch.index.reindex.DeleteByQueryRequest;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.SortOrder;


public class EsQueryUtils {
    private static final int MAXSIZE = 10000;
    private static final int MAXPAGESIZE = 5000;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public boolean deleteByQuery(RestHighLevelClient client, String indexname, DeleteByQueryRequest deleteByQueryRequest) {
        try {
            boolean exists = isExists(client, indexname);
            if (!exists) return true;
            client.deleteByQuery(deleteByQueryRequest, RequestOptions.DEFAULT);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean deleteIndex(RestHighLevelClient client, String indexname) {
        try {
            boolean exists = isExists(client, indexname);
            if (!exists) return true;
            DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(indexname);
            AcknowledgedResponse delete = client.indices().delete(deleteIndexRequest, RequestOptions.DEFAULT);
            return delete.isAcknowledged();
        } catch (IOException e) {
            return false;
        }
    }

    public boolean isExists(RestHighLevelClient client, String indexname) {
        boolean exists = false;
        try {
            GetIndexRequest request = new GetIndexRequest(indexname);
            exists = client.indices().exists(request, RequestOptions.DEFAULT);
        } catch (Exception ignored) {
        }
        return exists;
    }

    public HashMap<String, HashSet<String>>  queryBlueUserEmails(RestHighLevelClient client, String indexname) {
        SearchRequest request = new SearchRequest(indexname);
        request.scroll(TimeValue.timeValueMinutes(1));
        SearchSourceBuilder builder = new SearchSourceBuilder();
        builder.size(MAXSIZE);
        builder.query(QueryBuilders.matchAllQuery());
        request.source(builder);

        HashMap<String, HashSet<String>> id2emails = new HashMap<>();
        try {
            SearchResponse response = client.search(request, RequestOptions.DEFAULT);
            String scrollId = response.getScrollId();
            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                String id = hit.getId();
                ArrayList<String> emails = (ArrayList<String>) sourceAsMap.get("emails");
                HashSet<String> emailSet = new HashSet<>(emails);
                id2emails.put(id, emailSet);
            }

            ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
            clearScrollRequest.addScrollId(scrollId);
            ClearScrollResponse clearScrollResponse = client.clearScroll(clearScrollRequest, RequestOptions.DEFAULT);
        } catch (Exception e) {
            return id2emails;
        }

        return id2emails;
    }

    public String esScroll(RestHighLevelClient client, String item, String indexname) {
        SearchRequest request = new SearchRequest(indexname);
        request.scroll(TimeValue.timeValueMinutes(1));
        SearchSourceBuilder builder = new SearchSourceBuilder();
        builder.size(MAXSIZE);
        builder.sort("created_at", SortOrder.ASC);
//        String str = "CVE_num,issue_id";
//        builder.fetchSource(str.split(","), new String[]{});
        builder.query(QueryBuilders.matchAllQuery());
        request.source(builder);

        ArrayList<Object> list = new ArrayList<>();
        long totalCount = 0;
        try {
            SearchResponse response = client.search(request, RequestOptions.DEFAULT);
            totalCount = response.getHits().getTotalHits().value;
            String scrollId = response.getScrollId();
            // System.out.println(scrollId);

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                list.add(sourceAsMap);
            }
            while (true) {
                SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
                scrollRequest.scroll(TimeValue.timeValueMinutes(1));
                SearchResponse scroll = client.scroll(scrollRequest, RequestOptions.DEFAULT);
                // System.out.println(scroll.getScrollId());
                SearchHit[] hits = scroll.getHits().getHits();
                if (hits == null || hits.length < 10) {
                    break;
                }
                for (SearchHit hit : hits) {
                    Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                    list.add(sourceAsMap);
                }
            }

            ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
            clearScrollRequest.addScrollId(scrollId);
            ClearScrollResponse clearScrollResponse = client.clearScroll(clearScrollRequest, RequestOptions.DEFAULT);
            // System.out.println("clear scrollId success: " + clearScrollResponse.isSucceeded());
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        String s = objectMapper.valueToTree(list).toString();
        return "{\"code\":200,\"data\":" + s + ",\"totalCount\":" + totalCount + ",\"msg\":\"ok\"}";

    }

    public String esScroll(RestHighLevelClient restHighLevelClient, String item, String indexName,
                           int pageSize, SearchSourceBuilder sourceBuilder) {
        SearchRequest request = new SearchRequest(indexName);
        request.scroll(TimeValue.timeValueMinutes(2));

        if (pageSize > MAXPAGESIZE) pageSize = MAXPAGESIZE;
        sourceBuilder.size(pageSize);
        request.source(sourceBuilder);

        ArrayList<Object> list = new ArrayList<>();
        Long totalCount = 0L;
        String scrollId = null;
        try {
            SearchResponse response = restHighLevelClient.search(request, RequestOptions.DEFAULT);
            totalCount = response.getHits().getTotalHits().value;
            scrollId = response.getScrollId();
            // System.out.println(scrollId);

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                list.add(sourceAsMap);
            }

            while (true) {
                SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
                scrollRequest.scroll(TimeValue.timeValueMinutes(2));
                SearchResponse scroll = restHighLevelClient.scroll(scrollRequest, RequestOptions.DEFAULT);
                SearchHit[] hits = scroll.getHits().getHits();
                if (hits == null || hits.length < 1) {
                    break;
                }
                for (SearchHit hit : hits) {
                    Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                    list.add(sourceAsMap);
                }
            }

        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        } finally {
            ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
            clearScrollRequest.addScrollId(scrollId);
            try {
                ClearScrollResponse clearScrollResponse = restHighLevelClient.clearScroll(clearScrollRequest, RequestOptions.DEFAULT);
                if (clearScrollResponse != null) {
                    // System.out.println("clear scrollId success: " + clearScrollResponse.isSucceeded());
                } else {
                    System.out.println("failed to clear scrollId.");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        String data = objectMapper.valueToTree(list).toString();
        return "{\"code\":200,\"totalCount\":" + totalCount + ",\"msg\":\"ok\",\"data\":" + data + "}";

    }

    public String esScrollFromId(RestHighLevelClient client, String item, int pageSize, String indexname, String lastCursor, SearchSourceBuilder sourceBuilder) {
        SearchRequest request = new SearchRequest(indexname);
        SearchSourceBuilder builder = sourceBuilder;

        if (pageSize <= 0 || pageSize > MAXPAGESIZE) {
            pageSize = MAXPAGESIZE;
        }
        builder.size(pageSize);

        if (lastCursor != null && !lastCursor.isEmpty()) {
            builder.size(pageSize + 1);
            String sortValueStr = new String(Base64.getDecoder().decode(lastCursor));
            builder.searchAfter(sortValueStr.split(","));
        }
        request.source(builder);

        ArrayList<Object> list = new ArrayList<>();
        String endCursor = "";

        long totalCount = 0;
        try {
            SearchResponse response = client.search(request, RequestOptions.DEFAULT);
            totalCount = response.getHits().getTotalHits().value;
            for (SearchHit hit : response.getHits().getHits()) {
                String s = Arrays.toString(hit.getSortValues()).replace("[", "").replace("]", "");
                endCursor = Base64.getEncoder().encodeToString(s.getBytes());
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                list.add(sourceAsMap);
            }
        } catch (Exception ex) {
            list.clear();
            String s = objectMapper.valueToTree(list).toString();
            return "{\"code\":200,\"data\":" + s + ",\"cursor\":\"" + endCursor + "\",\"msg\":\"query error\"}";
        }

        if (endCursor.equals(lastCursor)) {
            list.clear();
        }
        if (list.size() > pageSize) {
            list.remove(0);
        }
        String s = objectMapper.valueToTree(list).toString();
        return "{\"code\":200,\"data\":" + s + ",\"cursor\":\"" + endCursor + "\",\"totalCount\":" + totalCount + ",\"msg\":\"ok\"}";
    }

    public String esFromId(RestHighLevelClient client, String item, String lastCursor, int pageSize, String indexname) {
        SearchRequest request = new SearchRequest(indexname);
        SearchSourceBuilder builder = new SearchSourceBuilder();

        builder.sort("created_at", SortOrder.ASC);
        builder.sort("_id", SortOrder.ASC);
//        String str = "CVE_num,issue_id";
//        builder.fetchSource(str.split(","), new String[]{});
        builder.query(QueryBuilders.matchAllQuery());

        if (pageSize <= 0 || pageSize > MAXPAGESIZE) {
            pageSize = MAXPAGESIZE;
        }
        builder.size(pageSize);

        if (lastCursor != null && !lastCursor.isEmpty()) {
            builder.size(pageSize + 1);
            String sortValueStr = new String(Base64.getDecoder().decode(lastCursor));
            builder.searchAfter(sortValueStr.split(","));
        }
        request.source(builder);

        ArrayList<Object> list = new ArrayList<>();
        String endCursor = "";

        long totalCount = 0;
        try {
            SearchResponse response = client.search(request, RequestOptions.DEFAULT);
            totalCount = response.getHits().getTotalHits().value;
            for (SearchHit hit : response.getHits().getHits()) {
                String s = Arrays.toString(hit.getSortValues()).replace("[", "").replace("]", "");
                endCursor = Base64.getEncoder().encodeToString(s.getBytes());
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                list.add(sourceAsMap);
            }
        } catch (Exception ex) {
            list.clear();
            String s = objectMapper.valueToTree(list).toString();
            return "{\"code\":200,\"data\":" + s + ",\"cursor\":\"" + endCursor + "\",\"msg\":\"query error\"}";
        }

        if (endCursor.equals(lastCursor)) {
            list.clear();
        }
        if (list.size() > pageSize) {
            list.remove(0);
        }
        String s = objectMapper.valueToTree(list).toString();
        return "{\"code\":200,\"data\":" + s + ",\"cursor\":\"" + endCursor + "\",\"totalCount\":" + totalCount + ",\"msg\":\"ok\"}";
    }


    public String esUserCountFromId(RestHighLevelClient client, String lastCursor, int pageSize, String indexname,
            String user, String sig, ArrayList<Object> params) {
        SearchRequest request = new SearchRequest(indexname);
        SearchSourceBuilder builder = new SearchSourceBuilder();

        builder.sort("created_at", SortOrder.ASC);
        builder.sort("_id", SortOrder.ASC);

        BoolQueryBuilder boolQueryBuilder = new BoolQueryBuilder();
        String type = params.get(0).toString();
        long start = Long.valueOf(params.get(1).toString());
        long end = Long.valueOf(params.get(2).toString());
        String feild = params.get(3).toString();
        String type_info = params.get(4).toString();
        String type_url = params.get(5).toString();
        String type_no = params.get(6).toString();
        sig = sig == null ? "*" : sig;
        boolQueryBuilder.must(QueryBuilders.rangeQuery("created_at").from(start).to(end));
        boolQueryBuilder.mustNot(QueryBuilders.matchQuery("is_removed", 1));
        boolQueryBuilder.must(QueryBuilders.termQuery("user_login.keyword", user));
        boolQueryBuilder.must(QueryBuilders.wildcardQuery("sig_names.keyword", sig));
        boolQueryBuilder.must(QueryBuilders.matchQuery(feild, 1));
        builder.query(boolQueryBuilder);

        if (pageSize <= 0 || pageSize > MAXPAGESIZE) {
            pageSize = MAXPAGESIZE;
        }
        builder.size(pageSize);

        if (lastCursor != null && !lastCursor.isEmpty()) {
            builder.size(pageSize + 1);
            String sortValueStr = new String(Base64.getDecoder().decode(lastCursor));
            builder.searchAfter(sortValueStr.split(","));
        }
        request.source(builder);

        ArrayList<Object> list = new ArrayList<>();
        String endCursor = "";

        long totalCount = 0;
        try {
            SearchResponse response = client.search(request, RequestOptions.DEFAULT);
            totalCount = response.getHits().getTotalHits().value;
            ArrayList<HashMap<String, Object>> res = parseResponse(response, type, type_no, type_info, type_url);
            list.addAll(res);
        } catch (Exception ex) {
            list.clear();
            String s = objectMapper.valueToTree(list).toString();
            return "{\"code\":200,\"data\":" + s + ",\"cursor\":\"" + endCursor + "\",\"msg\":\"query error\"}";
        }
        if (endCursor.equals(lastCursor)) {
            list.clear();
        }
        if (list.size() > pageSize) {
            list.remove(0);
        }
        String s = objectMapper.valueToTree(list).toString();
        return "{\"code\":200,\"data\":" + s + ",\"cursor\":\"" + endCursor + "\",\"totalCount\":" + totalCount
                + ",\"msg\":\"ok\"}";
    }

    public String esUserCount(String community, RestHighLevelClient client, String indexname, String user, String sig,
            ArrayList<Object> params, String comment_type, String filter, String query) {
        SearchRequest request = new SearchRequest(indexname);
        SearchSourceBuilder builder = new SearchSourceBuilder();
        request.scroll(TimeValue.timeValueMinutes(1));
        builder.sort("created_at", SortOrder.DESC);
        builder.sort("_id", SortOrder.ASC);

        BoolQueryBuilder boolQueryBuilder = new BoolQueryBuilder();
        String type = params.get(0).toString();
        long start = Long.valueOf(params.get(1).toString());
        long end = Long.valueOf(params.get(2).toString());
        String feild = params.get(3).toString();
        String type_info = params.get(4).toString();
        String type_url = params.get(5).toString();
        String type_no = params.get(6).toString();
        sig = sig == null ? "*" : sig;
        boolQueryBuilder.must(QueryBuilders.rangeQuery("created_at").from(start).to(end));
        boolQueryBuilder.mustNot(QueryBuilders.matchQuery("is_removed", 1));
        boolQueryBuilder.must(QueryBuilders.wildcardQuery("user_login.keyword", user));
        boolQueryBuilder.must(QueryBuilders.matchQuery(feild, 1));
        switch (community.toLowerCase()) {
            case "openeuler":
                boolQueryBuilder.must(QueryBuilders.wildcardQuery("sig_names.keyword", sig));
                break;
            case "opengauss":
                boolQueryBuilder.mustNot(QueryBuilders.wildcardQuery("gitee_repo.keyword", "https://gitee.com/opengauss/practice-course"));
                boolQueryBuilder.must(QueryBuilders.queryStringQuery(query));
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + type + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        if (type.equals("comment") && comment_type != null) {
            switch (comment_type.toLowerCase()) {
                case "command":
                    boolQueryBuilder.must(QueryBuilders.matchQuery("is_invalid_comment", 1));
                    break;
                case "normal":
                    boolQueryBuilder.mustNot(QueryBuilders.matchQuery("is_invalid_comment", 1));
                    break;
                case "nonetype":
                    return "{\"code\":200,\"data\": {},\"totalCount\":0,\"msg\":\"ok\"}";
                default:
            }
        }
        // if (filter != null) {
        //     boolQueryBuilder.must(QueryBuilders.matchPhraseQuery(type_info, filter));
        // }
        builder.query(boolQueryBuilder);
        builder.size(MAXSIZE);
        request.source(builder);

        ArrayList<HashMap<String, Object>> list = new ArrayList<>();
        HashMap<String, ArrayList<HashMap<String, Object>>> data = new HashMap<>();
        long totalCount = 0;
        String scrollId = null;
        try {
            SearchResponse response = client.search(request, RequestOptions.DEFAULT);
            totalCount = response.getHits().getTotalHits().value;
            scrollId = response.getScrollId();
            ArrayList<HashMap<String, Object>> res = parseResponse(response, type, type_no, type_info, type_url);
            list.addAll(res);
            while (true) {
                SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
                scrollRequest.scroll(TimeValue.timeValueMinutes(1));
                SearchResponse scroll = client.scroll(scrollRequest, RequestOptions.DEFAULT);
                SearchHit[] hits = scroll.getHits().getHits();
                if (hits == null || hits.length < 1) {
                    break;
                }
                ArrayList<HashMap<String, Object>> res_next = parseResponse(scroll, type, type_no, type_info, type_url);
                list.addAll(res_next);
            }
        } catch (Exception ex) {
            ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
            clearScrollRequest.addScrollId(scrollId);
            try {
                ClearScrollResponse clearScrollResponse = client.clearScroll(clearScrollRequest, RequestOptions.DEFAULT);
                System.out.println("failed to get data.");
                if (clearScrollResponse == null) {
                    System.out.println("failed to clear scrollId.");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        data.put(user, list);
        String s = objectMapper.valueToTree(data).toString();
        return "{\"code\":200,\"data\":" + s + ",\"totalCount\":" + totalCount + ",\"msg\":\"ok\"}";
    }

    public ArrayList<HashMap<String, Object>> parseResponse(SearchResponse response, String type, String type_no, String type_info, String type_url){
        ArrayList<HashMap<String, Object>> list = new ArrayList<>();
        for (SearchHit hit : response.getHits().getHits()) {
            Map<String, Object> sourceAsMap = hit.getSourceAsMap();
            String no = sourceAsMap.get(type_no).toString();
            String info = sourceAsMap.get(type_info) != null ? sourceAsMap.get(type_info).toString(): "*";
            String time = sourceAsMap.get("created_at").toString();
            String repo = sourceAsMap.get("gitee_repo").toString().substring(18);
            String user = sourceAsMap.get("user_login").toString();

            HashMap<String, Object> datamap = new HashMap<>();
            datamap.put("no", no);
            datamap.put("info", info);
            datamap.put("time", time);
            datamap.put("repo", repo);

            String url = sourceAsMap.get(type_url).toString();
            switch (type.toLowerCase()) {
                case "comment":
                    if (url.equals("issue_comment")) {
                        url = sourceAsMap.get("issue_url").toString() + "#note_" + sourceAsMap.get("id").toString()
                                + "_link";
                    } else {
                        url = sourceAsMap.get("comment_url").toString();
                    }
                    Object invalid = sourceAsMap.get("is_invalid_comment");
                    if (invalid != null) {
                        datamap.put("is_invalid_comment", 1);
                    } else {
                        datamap.put("is_invalid_comment", 0);
                    }
                case "pr":
                    String is_main_feature;
                    datamap.put("is_main_feature", 0);
                default:
            }
            datamap.put("url", url);
            HashMap<String, Object> res = new HashMap<>();
            list.add(datamap);
        }
        return list;
    }

    public HashMap<String, ArrayList<Object>> MapCombine(ArrayList<HashMap<String, Object>> list){
        HashMap<String, ArrayList<Object>> res = new HashMap<>();
        for (HashMap<String, Object> map:list){
            String user = map.get("user").toString();
            if(!res.containsKey(user)){
                ArrayList<Object> newlist = new ArrayList<>();
                newlist.add(map.get("details"));
                res.put(user, newlist);
            }else{
                res.get(user).add(map.get("details"));
            }
        }
        return res;
    }

    public HashMap<String, UserTagInfo> QueryPrReviewerByInter(RestHighLevelClient restHighLevelClient, PrReviewerVo input, String indexName, List<String> robotUsers) throws Exception {
        // 1、matchPhraseQuery
        QueryBuilder queryBuilder = QueryBuilders.matchPhraseQuery("pull_title", input.getPrTitle())
                .slop(3)
//                .boost(1)
                .analyzer("standard");
        SearchSourceBuilder builder = new SearchSourceBuilder();
        builder.size(10);
        builder.query(queryBuilder);
        builder.fetchSource(new String[]{"pull_title", "pull_url"}, new String[]{});
        SearchRequest request = new SearchRequest(indexName);
        request.source(builder);
        SearchResponse search = restHighLevelClient.search(request, RequestOptions.DEFAULT);
        SearchHits hits = search.getHits();

        // 2、matchPhraseQuery查询不到使用matchQuery
        if (hits.getHits().length == 0) {
            MoreLikeThisQueryBuilder moreLikeThisQueryBuilder = QueryBuilders.moreLikeThisQuery(new String[]{"pull_title"}, new String[]{input.getPrTitle()}, null);
//            queryBuilder = QueryBuilders.matchQuery("pull_title", input.getPrTitle());
            builder.query(moreLikeThisQueryBuilder);
            request.source(builder);
            search = restHighLevelClient.search(request, RequestOptions.DEFAULT);
            hits = search.getHits();
        }

        // 3、根据pr_url，查询评论的人
        HashMap<String, Float> user2score = new HashMap<>();
        for (SearchHit hit : hits) {
            Map<String, Object> sourceAsMap = hit.getSourceAsMap();
            float score = hit.getScore();
            String pr_url = (String) sourceAsMap.get("pull_url");

            queryBuilder = QueryBuilders.boolQuery()
                    .must(QueryBuilders.termQuery("pull_url.keyword", pr_url))
                    .must(QueryBuilders.termQuery("is_gitee_comment", 1))
                    .mustNot(QueryBuilders.termsQuery("user_login.keyword", robotUsers));
            builder.size(1000);
            builder.query(queryBuilder);
            builder.fetchSource(new String[]{"user_login"}, new String[]{});
            request.source(builder);
            search = restHighLevelClient.search(request, RequestOptions.DEFAULT);
            SearchHits hits1 = search.getHits();
            for (SearchHit hits1Hit : hits1.getHits()) {
                Map<String, Object> sourceAsMap1 = hits1Hit.getSourceAsMap();
                String userLogin = (String) sourceAsMap1.get("user_login");
                float scoreTemp = user2score.getOrDefault(userLogin, 0.0f);
                user2score.put(userLogin, Math.max(scoreTemp, score));

                UserTagInfo userTagInfo = new UserTagInfo();
                userTagInfo.setGiteeId((String) sourceAsMap1.get("user_login"));
                userTagInfo.setCorrelation(score);
            }
        }

        HashMap<String, UserTagInfo> user2info = new HashMap<>();
        for (Map.Entry<String, Float> entry : user2score.entrySet()) {
            UserTagInfo userTagInfo = new UserTagInfo();
            userTagInfo.setGiteeId(entry.getKey());
            userTagInfo.setCorrelation(entry.getValue());
            user2info.put(entry.getKey(), userTagInfo);
        }

        return user2info;

    }

    public Map<String, Map<String, Object>> QueryPrReviewerByRepo(RestHighLevelClient restHighLevelClient, PrReviewerVo input, String indexName, HashMap<String, UserTagInfo> user2Info) throws Exception {
        Set<String> users = user2Info.keySet();
        Stream<String> stringStream = users.stream().map(it -> String.format("\"%s\"", it));
        List<String> collect = stringStream.collect(Collectors.toList());
        String join = StringUtils.join(collect, ",");
        String repoName = input.getPrUrl().split("/pulls/")[0];
        String str = String.format("repo_comments.repo.keyword:\"%s\" OR user_login.keyword:(%s)", repoName, join);
        QueryStringQueryBuilder queryBuilder = QueryBuilders.queryStringQuery(str);
        SearchSourceBuilder builder = new SearchSourceBuilder();
        builder.size(10);
        builder.query(queryBuilder);
        SearchRequest request = new SearchRequest(indexName);
        request.source(builder);
        SearchResponse search = restHighLevelClient.search(request, RequestOptions.DEFAULT);
        SearchHits hits = search.getHits();
        Map<String, Map<String, Object>> res = new HashMap<>();
        for (SearchHit hit : hits) {
            Map<String, Object> sourceAsMap = hit.getSourceAsMap();
            String userLogin = (String) sourceAsMap.get("user_login");
            List<String> openPr = (List<String>) sourceAsMap.get("open_pr");
            List<HashMap<String, Object>> repoComments = (List<HashMap<String, Object>>) sourceAsMap.get("repo_comments");
            double activity = (double) sourceAsMap.get("activity");
            double willingness = (double) sourceAsMap.get("willingness");

            double commentCount = calcUserComment(repoComments);



            UserTagInfo userInfo = user2Info.getOrDefault(userLogin, new UserTagInfo());
            userInfo.setGiteeId(userLogin);

            res.put(userLogin, sourceAsMap);
        }

        return res;
    }

    private double calcUserComment(List<HashMap<String, Object>> repoComments) {

        return 0.0d;
    }
}


