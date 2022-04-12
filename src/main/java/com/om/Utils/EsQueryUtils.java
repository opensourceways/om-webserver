package com.om.Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.elasticsearch.action.search.*;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.SortOrder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

public class EsQueryUtils {
    private static final int MAXSIZE = 10000;
    private static final int MAXPAGESIZE = 5000;
    private static final ObjectMapper objectMapper = new ObjectMapper();


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
            System.out.println(scrollId);

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                list.add(sourceAsMap);
            }
            while (true) {
                SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
                scrollRequest.scroll(TimeValue.timeValueMinutes(1));
                SearchResponse scroll = client.scroll(scrollRequest, RequestOptions.DEFAULT);
                System.out.println(scroll.getScrollId());
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
            System.out.println("clear scrollId success: " + clearScrollResponse.isSucceeded());
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
            System.out.println(scrollId);

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
                    System.out.println("clear scrollId success: " + clearScrollResponse.isSucceeded());
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
}


