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

package com.om.Dao;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Modules.openEuler;
import com.om.Modules.openLookeng;
import com.om.Modules.meetup.MeetupApplyForm;
import com.om.Modules.meetup.MeetupTranscript;
import com.om.Modules.meetup.MeetupVenueInfo;
import com.om.Modules.meetup.SurveyAnswer;
import com.om.Utils.AsyncHttpUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import com.om.Utils.StringValidationUtil;
import com.om.Vo.BugQuestionnaireVo;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.*;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Repository;


import static com.om.Dao.QueryDao.objectMapper;

@Repository
public class AddDao {

    @Autowired
    AsyncHttpUtil asyncHttpUtil;

    @Value("${esurl}")
    String url;

    @Autowired
    private Environment env;

    @Autowired
    protected openEuler openEuler;

    @Autowired
    protected openLookeng openLookeng;

    public String putBugQuestionnaire(String community, String item, String lang, BugQuestionnaireVo bugQuestionnaireVo) {
        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        String indexName = null;
        String res = null;

        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getBug_questionnaire_index();
                break;
            case "opengauss":
            case "openlookeng":
                indexName = openLookeng.getBug_questionnaire_index();
                break;
            case "mindspore":
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg\":\"community error\"}";
        }
        if (indexName == null) {
            return "{\"code\":400,\"data\":\"write error\"},\"msg\":\"indexname is null\"}";
        }
        indexName = indexName.substring(1);

        String nowStr = ZonedDateTime.now().toOffsetDateTime().toString();
        nowStr = nowStr.replaceAll("\\.\\d{3}", "");

        bugQuestionnaireVo.setCreated_at(nowStr);

        ArrayList<String> validationMesseages = checkoutFieldValidate(bugQuestionnaireVo, community, lang);
        if (validationMesseages.size() != 0) {
            return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg:" + validationMesseages + "\"}";
        }

        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        BulkRequest request = new BulkRequest();
        Map bugQuestionnaireMap = objectMapper.convertValue(bugQuestionnaireVo, Map.class);
        if (lang.equals("en")) {
            bugQuestionnaireMap.put("is_en", 1);
        }
        request.add(new IndexRequest(indexName, "_doc").source(bugQuestionnaireMap));

        if (request.requests().size() != 0) {
            try {
                BulkResponse bulk = restHighLevelClient.bulk(request, RequestOptions.DEFAULT);
                int status_code = bulk.status().getStatus();
                if (status_code == 200) {
                    res = "{\"code\":200,\"data\":{\"questionnaire_count\":\"1\"},\"msg\":\"add success\"}";
                } else {
                    res = String.format(
                            "{\"code\":%i,\"data\":{\"questionnaire_count\":\"0\"},\"msg\":\"add bug questionnaire failed\"}",
                            status_code);
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    restHighLevelClient.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return res;
    }

    public ArrayList<String> checkoutFieldValidate(BugQuestionnaireVo bugQuestionnaireVo, String community, String lang) {
        List<String> existProblemTemplate;
        switch (community.toLowerCase()) {
            case "openeuler":
                if (lang.equals("en")) {
                    existProblemTemplate = Arrays.asList("Specifications and Common Mistakes", "Correctness",
                            "Risk Warnings", "Usability", "Content Compliance");
                } else {
                    existProblemTemplate = Arrays.asList("规范和低错类", "易用性", "正确性", "风险提示", "内容合规");
                }                   
                break;
            case "opengauss":
            case "openlookeng":
                existProblemTemplate = Arrays.asList("文档存在风险与错误", "内容描述不清晰", "内容获取有困难", "示例代码错误", "内容有缺失");
                break;
            case "mindspore":
            default:
                return null;
        }
        
        List<String> participateReasonTemplate = Arrays.asList("本职工作", "求职", "技术兴趣", "学习");
        List<Integer> comprehensiveSatisficationTemplate = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

        String bugDocFragment = bugQuestionnaireVo.getBugDocFragment();
        ArrayList<String> existProblem = bugQuestionnaireVo.getExistProblem();
        String problemDetail = bugQuestionnaireVo.getProblemDetail();
        Integer comprehensiveSatisfication = bugQuestionnaireVo.getComprehensiveSatisfication();
        String participateReason = bugQuestionnaireVo.getParticipateReason();
        String email = bugQuestionnaireVo.getEmail();

        boolean existProblemValidation = existProblemTemplate.containsAll(existProblem);
        boolean participateReasonValidation = participateReasonTemplate.contains(participateReason);
        boolean comprehensiveSatisficationValidation = comprehensiveSatisficationTemplate
                .contains(comprehensiveSatisfication);
        boolean emailValidation = StringValidationUtil.isEmail(email);

        if (bugDocFragment != null && bugDocFragment.contains("\\")) {
            String cleanBugDocFragment = bugDocFragment.replace("\\", "/");
            bugQuestionnaireVo.setBugDocFragment(cleanBugDocFragment);
        }
        if (problemDetail != null && problemDetail.contains("\\")) {
            String cleanProblemDetail = problemDetail.replace("\\", "/");
            bugQuestionnaireVo.setBugDocFragment(cleanProblemDetail);
        }

        ArrayList<String> errorMesseges = new ArrayList<>();

        if (!existProblemValidation) {
            errorMesseges.add("existProblem validate failure");
        }
        // if (!participateReasonValidation) {
        //     errorMesseges.add("participateReason validate failure");
        // }
        if (!comprehensiveSatisficationValidation) {
            errorMesseges.add("comprehensiveSatisfication validate failure");
        }
        if (!emailValidation) {
            errorMesseges.add("email validate failure");
        }

        return errorMesseges;
    }

    public String putMeetupApplyForm(String community, String item, MeetupApplyForm meetupApplyForm, String token) {
        String indexName = null;
        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getMeetupApplyFormIndex();
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg\":\"community error\"}";
        }
        ArrayList<String> errorMesseages = checkoutMeetupApplyFormField(meetupApplyForm);
        if (errorMesseages.size() > 0) {
            return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg:" + errorMesseages + "\"}";
        }
        indexName = indexName.substring(1);
        Map meetupApplyFormMap = objectMapper.convertValue(meetupApplyForm, Map.class);
        return putDataSource(indexName, meetupApplyFormMap, token);
    }

    public String putMeetupVenueInfo(String community, String item, MeetupVenueInfo meetupVenueInfo, String token) {
        String indexName = null;
        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getMeetupVenueInfoIndex();
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg\":\"community error\"}";
        }
        ArrayList<String> errorMesseages = checkoutMeetupVenueInfoField(meetupVenueInfo);
        if (errorMesseages.size() > 0) {
            return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg:" + errorMesseages + "\"}";
        }
        indexName = indexName.substring(1);
        Map meetupVenueInfoMap = objectMapper.convertValue(meetupVenueInfo, Map.class);
        return putDataSource(indexName, meetupVenueInfoMap, token);
    }

    public String putMeetupTranscript(String community, String item, MeetupTranscript meetupTranscript, String token) {
        String indexName = null;
        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getMeetupTranscriptIndex();
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg\":\"community error\"}";
        }
        ArrayList<String> errorMesseages = checkoutMeetupTranscriptField(meetupTranscript);
        if (errorMesseages.size() > 0) {
            return "{\"code\":400,\"data\":{\"" + item + "\":\"write error\"},\"msg:" + errorMesseages + "\"}";
        }
        indexName = indexName.substring(1);
        Map meetupTranscriptMap = objectMapper.convertValue(meetupTranscript, Map.class);
        return putDataSource(indexName, meetupTranscriptMap, token);
    }

    public String getUserId(String token){
        String userId = null;
        try {
            RSAPrivateKey privateKey = RSAUtil.getPrivateKey(env.getProperty("rsa.authing.privateKey"));
            DecodedJWT decode = JWT.decode(RSAUtil.privateDecrypt(token, privateKey));
            userId = decode.getAudience().get(0);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return userId;
    }

    public String putDataSource(String indexName, Map dataSource, String token) {
        String userId = getUserId(token);
        if (userId == null) return "{\"code\":400,\"data\":\"user failed\",\"msg\":\"user failed\"}";
        LocalDateTime now = LocalDateTime.now();
        String nowStr = now.toString().split("\\.")[0] + "+08:00";
        dataSource.put("created_at", nowStr);
        dataSource.put("user_id", userId);
       
        BulkRequest request = new BulkRequest();
        request.add(new IndexRequest(indexName, "_doc", userId).source(dataSource));       

        String res = "{\"code\":400,\"data\":\"failed\",\"msg\":\"failed\"}";
        RestHighLevelClient restHighLevelClient = getRestHighLevelClient();
        if (request.requests().size() != 0) {
            try {
                BulkResponse bulk = restHighLevelClient.bulk(request, RequestOptions.DEFAULT);
                int status_code = bulk.status().getStatus();
                if (status_code == 200) {
                    res = "{\"code\":200,\"data\":\"success\",\"msg\":\"success\"}";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try {
            restHighLevelClient.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return res;
    }

    public RestHighLevelClient getRestHighLevelClient(){
        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        return HttpClientUtils.restClient(host, port, scheme, esUser, password);
    }

    private Boolean validDuration(SurveyAnswer value){
        List<String> valueList = Arrays.asList("半天", "全天", "其他");
        String duration = value.getOptional();
        if (valueList.contains(duration)) {
            return true;
        }
        return false;
    }

    private Boolean validMeetupFormat(SurveyAnswer value){
        List<String> valueList = Arrays.asList("线上活动", "线下活动", "线上+线下", "其他");
        String format = value.getOptional();
        if (valueList.contains(format)) {
            return true;
        }
        return false;
    }

    private Boolean validSatisfaction(String value){
        List<String> valueList = Arrays.asList("非常不满意", "1", "2", "3", "2", "4", "5", "6", "7", "8", "9", "非常满意");
        if (valueList.contains(value)) {
            return true;
        }
        return false;
    }

    private Boolean validItems(ArrayList<SurveyAnswer> value){
        List<String> valueList = Arrays.asList("音响", "投影", "桌椅", "饮用水", "其他");
        for (SurveyAnswer sa : value) {
            if (!valueList.contains(sa.getOptional())) {
                return false;
            }
        }
        return true;
    }

    private Boolean validHasNewUser(String value){
        List<String> valueList = Arrays.asList("有", "无");
        if (valueList.contains(value)) {
            return true;
        }
        return false;
    }

    private Boolean validHasUserCase(String value){
        List<String> valueList = Arrays.asList("有，可投稿用户案例", "无");
        if (valueList.contains(value)) {
            return true;
        }
        return false;
    }

    public ArrayList<String> checkoutMeetupApplyFormField(MeetupApplyForm meetupApplyForm) {
        ArrayList<String> errorMesseges = new ArrayList<>();
        if (!validDuration(meetupApplyForm.getDuration())) {
            errorMesseges.add("duration error");
        }
        if (!validMeetupFormat(meetupApplyForm.getMeetupFormat())) {
            errorMesseges.add("meetup format error");
        }
        return errorMesseges;
    }

    public ArrayList<String> checkoutMeetupVenueInfoField(MeetupVenueInfo meetupVenueInfo) {
        ArrayList<String> errorMesseges = new ArrayList<>();
        if (!validItems(meetupVenueInfo.getItems())) {
            errorMesseges.add("items error");
        }
        return errorMesseges;
    }

    public ArrayList<String> checkoutMeetupTranscriptField(MeetupTranscript meetupTranscript) {
        ArrayList<String> errorMesseges = new ArrayList<>();
        if (!validHasNewUser(meetupTranscript.getHasNewUser())) {
            errorMesseges.add("hasNewUser error");
        }
        if (!validSatisfaction(meetupTranscript.getSatisfaction())) {
            errorMesseges.add("satisfaction error");
        }
        if (!validHasUserCase(meetupTranscript.getHasUserCase())) {
            errorMesseges.add("hasUserCase error");
        }
        return errorMesseges;
    }

}
