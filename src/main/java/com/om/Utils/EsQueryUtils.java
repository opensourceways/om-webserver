package com.om.Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.elasticsearch.action.search.*;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.MatchQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.SortOrder;

import java.io.IOException;
import java.util.*;

public class EsQueryUtils {
    private static final int MAXSIZE = 10000;
    private static final int MAXPAGESIZE = 5000;
    private static final ObjectMapper objectMapper = new ObjectMapper();

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
            ArrayList<Object> params, String comment_type, String filter) {
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
                boolQueryBuilder.must(QueryBuilders.wildcardQuery("tag_sig_names.keyword", sig));
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
        HashMap<String, ArrayList<Object>> data = new HashMap<>();
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
        data = MapCombine(list);
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
            res.put("user", user);
            res.put("details", datamap);
            list.add(res);          
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
}


