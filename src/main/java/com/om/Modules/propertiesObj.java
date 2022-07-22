package com.om.Modules;

import com.om.Service.ContributionDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Repository;
import org.springframework.util.DigestUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author zhxia
 * @date 2020/11/5 16:24
 */
@DependsOn(value = {"openEuler", "openGauss", "openLookeng"})
@Repository
public class propertiesObj {
    static Properties properties = new Properties();

    String openEulerConfMd5;
    String openGaussConfMd5;
    String openLookengConfMd5;
    String mindSporeConfMd5;
    String blueZoneConfMd5;
    String starForkConfMd5;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    ContributionDataService conservice;

    static ScheduledExecutorService service = Executors
            .newSingleThreadScheduledExecutor();

    propertiesObj(ApplicationContext applicationContext) {

        // 间，第三个参数为定时执行的间隔第二个参数为首次执行的延时时时间
        service.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                updateCycle();
                conservice.allCondata.clear();
                conservice.allCondatasortbypr.clear();
                conservice.allCondatasortbyissue.clear();
                conservice.allCondatasorybycomments.clear();

            }
        }, 5, 15, TimeUnit.SECONDS);
    }

    private void updateCycle() {
        FileInputStream openEneulerfilein = null;
        FileInputStream openGaussfileIn = null;
        FileInputStream openLookengfileIn = null;
        FileInputStream mindSporefileIn = null;
        FileInputStream blueZonefileIn = null;
        FileInputStream starForkfileIn = null;
        try {

//            System.getProperty("user.dir") value: D:\Work\Projects\IdeaProjects\om-webserver
//            System.getProperty("user.dir"): 获取得到当前工程目录下的绝对路径名
            String openEneuler_conf_path = System.getProperty("user.dir") + "/openEuler.properties";
            openEneulerfilein = new FileInputStream(openEneuler_conf_path);
            String eumd5 = DigestUtils.md5DigestAsHex(openEneulerfilein);
            if (!eumd5.equals(this.openEulerConfMd5)) {
                this.openEulerConfMd5 = eumd5;
                Properties openEneulerConf = readProperties(openEneuler_conf_path);
                setPropertiesValue(openEneulerConf, "openEuler");
            }


            String openGauss_conf_path = System.getProperty("user.dir") + "/openGauss.properties";
            openGaussfileIn = new FileInputStream(openGauss_conf_path);
            String gaussmd5 = DigestUtils.md5DigestAsHex(openGaussfileIn);
            if (!gaussmd5.equals(this.openGaussConfMd5)) {
                this.openGaussConfMd5 = gaussmd5;
                Properties openGaussConf = readProperties(openGauss_conf_path);
                setPropertiesValue(openGaussConf, "openGauss");
            }

            String openLookeng_conf_path = System.getProperty("user.dir") + "/openLookeng.properties";
            openLookengfileIn = new FileInputStream(openLookeng_conf_path);
            String lookengmd5 = DigestUtils.md5DigestAsHex(openLookengfileIn);
            if (!lookengmd5.equals(this.openLookengConfMd5)) {
                Properties openLookengConf = readProperties(openLookeng_conf_path);
                setPropertiesValue(openLookengConf, "openLookeng");
            }

            String mindSpore_conf_path = System.getProperty("user.dir") + "/mindSpore.properties";
            mindSporefileIn = new FileInputStream(mindSpore_conf_path);
            String mindSporemd5 = DigestUtils.md5DigestAsHex(mindSporefileIn);
            if (!mindSporemd5.equals(this.mindSporeConfMd5)) {
                Properties mindSporeConf = readProperties(mindSpore_conf_path);
                setPropertiesValue(mindSporeConf, "mindSpore");
            }

            String blueZone_conf_path = System.getProperty("user.dir") + "/blueZone.properties";
            blueZonefileIn = new FileInputStream(blueZone_conf_path);
            String blueZonemd5 = DigestUtils.md5DigestAsHex(blueZonefileIn);
            if (!blueZonemd5.equals(this.blueZoneConfMd5)) {
                Properties blueZoneConf = readProperties(blueZone_conf_path);
                setPropertiesValue(blueZoneConf, "blueZone");
            }

            String star_fork_conf_path = System.getProperty("user.dir") + "/starFork.properties";
            starForkfileIn = new FileInputStream(star_fork_conf_path);
            String starForkmd5 = DigestUtils.md5DigestAsHex(starForkfileIn);
            if (!starForkmd5.equals(this.starForkConfMd5)) {
                Properties starForkConf = readProperties(star_fork_conf_path);
                setPropertiesValue(starForkConf, "starFork");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (openEneulerfilein != null) {
                try {
                    openEneulerfilein.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (openGaussfileIn != null) {
                try {
                    openGaussfileIn.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (openLookengfileIn != null) {
                try {
                    openLookengfileIn.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (mindSporefileIn != null) {
                try {
                    mindSporefileIn.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (blueZonefileIn != null) {
                try {
                    blueZonefileIn.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }


    }

    private void setPropertiesValue(Properties openconf, String object) {
        openComObject bean = (openComObject) this.applicationContext.getBean(object);
        bean.setExtOs_index(openconf.get(IndexQueryEnum.EXTOS.getIndex()).toString());
        bean.setExtOs_queryStr(openconf.get(IndexQueryEnum.EXTOS.getQueryString()).toString());
        bean.setBusinessOsv_index(openconf.get(IndexQueryEnum.BUSINESSOSV.getIndex()).toString());
        bean.setBusinessOsv_queryStr(openconf.get(IndexQueryEnum.BUSINESSOSV.getQueryString()).toString());
        bean.setSigs_index(openconf.get(IndexQueryEnum.SIGS.getIndex()).toString());
        bean.setSigs_queryStr(openconf.get(IndexQueryEnum.SIGS.getQueryString()).toString());
        bean.setUsers_index(openconf.get(IndexQueryEnum.USERS.getIndex()).toString());
        bean.setUsers_queryStr(openconf.get(IndexQueryEnum.USERS.getQueryString()).toString());
        bean.setContributors_index(openconf.get(IndexQueryEnum.CONTRIUTORS.getIndex()).toString());
        bean.setContributors_queryStr(openconf.get(IndexQueryEnum.CONTRIUTORS.getQueryString()).toString());
        bean.setNoticeusers_index(openconf.get(IndexQueryEnum.NOTICEUSERS.getIndex()).toString());
        bean.setNoticeusers_queryStr(openconf.get(IndexQueryEnum.NOTICEUSERS.getQueryString()).toString());
        bean.setCommunitymembers_index(openconf.get(IndexQueryEnum.COMMUNITYMEMBERS.getIndex()).toString());
        bean.setCommunitymembers_queryStr(openconf.get(IndexQueryEnum.COMMUNITYMEMBERS.getQueryString()).toString());
        bean.setTokenUserName(openconf.getProperty("token.user.name"));
        bean.setTokenUserPassword(openconf.getProperty("token.user.password"));
        bean.setTokenBasePassword(openconf.getProperty("token.base.password"));
        bean.setTokenExpireSeconds(openconf.getProperty("token.expire.seconds"));
        bean.setGiteeAllIndex(openconf.getProperty("giteeall_index"));
        bean.setGiteeAll_qIssueStrBymil(openconf.getProperty("giteeall_qIssueStrBymil"));
        bean.setGiteeAllQueryAllstr(openconf.getProperty("giteeall_queryallddpirstr"));
        bean.setGiteeStarCountQueryStr(openconf.getProperty("gitee_star_count_queryStr"));
        bean.setGiteeIssueCountQueryStr(openconf.getProperty("gitee_issue_count_queryStr"));
        bean.setGiteePrCountQueryStr(openconf.getProperty("gitee_pr_count_queryStr"));
        bean.setGiteeAggCompanyQueryStr(openconf.getProperty("gitee_agg_company_queryStr"));
        bean.setGiteeAggUserQueryStr(openconf.getProperty("gitee_agg_user_queryStr"));
        bean.setGiteeContributesQueryStr(openconf.getProperty("gitee_contributes_queryStr"));
        bean.setDownloadQueryIndex(openconf.getProperty("download_query_index"));
        bean.setDownloadQueryStr(openconf.getProperty("download_queryStr"));
        bean.setDownloadDockerHubQueryStr(openconf.getProperty("download_docker_hub_queryStr"));
        bean.setBlueZoneContributesIndex(openconf.getProperty("blue_zone_user_contributes_index"));
        bean.setBlueZoneUsersIndex(openconf.getProperty("blue_zone_user_index"));
        bean.setStar_fork_index(openconf.getProperty("star_fork_index"));
        bean.setStar_fork_queryStr(openconf.getProperty("star_fork_queryStr"));
        bean.setCveDetailsQueryIndex(openconf.getProperty("cve_details_index"));
        bean.setDurationAggIndex(openconf.getProperty("durationAggIndex"));
        bean.setDurationAggQueryStr(openconf.getProperty("durationAggQueryStr"));
        bean.setBug_questionnaire_index(openconf.getProperty("bug_questionnaire_index"));
        bean.setBug_questionnaire_queryAllStr(openconf.getProperty("bug_questionnaire_queryAllStr"));
        bean.setObsDetailsIndex(openconf.getProperty("obs_details_index"));
        bean.setObsDetailsIndexQueryStr(openconf.getProperty("obs_details_index_queryStr"));
        bean.setObsPackageQueryStr(openconf.getProperty("obs_package_queryStr"));
        bean.setIsoBuildIndex(openconf.getProperty("iso_build_index"));
        bean.setIsoBuildIndexQueryStr(openconf.getProperty("iso_build_index_queryStr"));
        bean.setSigDetailsIndex(openconf.getProperty("sig_details_index"));
        bean.setSigDetailsIndexQueryStr(openconf.getProperty("sig_details_index_queryStr"));
        bean.setClaCorporationIndex(openconf.getProperty("cla_corporation_index"));
        bean.setIssueScoreIndex(openconf.getProperty("issuescore_index"));
        bean.setIssueScoreQueryStr(openconf.getProperty("issuescore_queryStr"));
        bean.setBuildCheckResultIndex(openconf.getProperty("buildCheck_result_index"));
        bean.setBuildCheckMistakeIndex(openconf.getProperty("buildCheck_mistake_index"));
        bean.setSigRepoQueryStr(openconf.getProperty("sig_repo_queryStr"));
        bean.setSigNameQueryStr(openconf.getProperty("sig_name_queryStr"));
        bean.setMeetingsIndex(openconf.getProperty("meetings_index"));
        bean.setCompanyUserQueryStr(openconf.getProperty("company_user_queryStr"));
        bean.setCompanySigsQueryStr(openconf.getProperty("company_sigs_queryStr"));
        bean.setCompanyContributeQueryStr(openconf.getProperty("company_contribute_queryStr"));
        bean.setCompanyMeetingsQueryStr(openconf.getProperty("company_meetings_queryStr"));
        bean.setCompanyMaintainersQueryStr(openconf.getProperty("company_maintainers_queryStr"));
        bean.setSigOwnerType(openconf.getProperty("sig_owner_type"));
        bean.setSigAggUserQueryStr(openconf.getProperty("sig_agg_user_queryStr"));
        bean.setCompanyAggUserQueryStr(openconf.getProperty("company_agg_user_queryStr"));
        bean.setAllSigsOwnerType(openconf.getProperty("all_sigs_owner_type"));
        bean.setSigsFeature(openconf.getProperty("sigs_feature_url"));
        bean.setComapnyUsers(openconf.getProperty("company_users"));
        bean.setCommunityRepoQueryStr(openconf.getProperty("community_repo_queryStr"));
        bean.setsig_score_queryStr(openconf.getProperty("sig_score_queryStr"));
        bean.setsig_score_index(openconf.getProperty("sig_score_index"));
        bean.setsig_radar_score_index(openconf.getProperty("sig_radar_score_index"));
        bean.setTracker_index(openconf.getProperty("Tracker_index"));
        bean.setAllCompanySigsQueryStr(openconf.getProperty("AllCompanySigsQueryStr"));
        bean.setall_sig_score_queryStr(openconf.getProperty("all_sig_score_queryStr"));
        bean.setSigInfoQueryStr(openconf.getProperty("sig_info_queryStr"));
        bean.setuser_owns_sigs_Str(openconf.getProperty("user_owns_sigs_Str"));
        bean.settc_owner_url(openconf.getProperty("tc_owner_url"));
        bean.setUserCountDetailsQueryStr(openconf.getProperty("UserCountDetailsQueryStr"));
        bean.setcompany_agg_sig_queryStr(openconf.getProperty("company_agg_sig_queryStr"));
    }

    private static Properties readProperties(String path) throws IOException {
        // 使用ClassLoader加载properties配置文件生成对应的输入流
        InputStream in = new FileInputStream(path);
        try {
            // 使用properties对象加载输入流
            properties.load(in);
        } finally {
            in.close();
        }

        return properties;
    }


}
