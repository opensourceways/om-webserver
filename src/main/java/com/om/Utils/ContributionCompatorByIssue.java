package com.om.Utils;

import com.om.Vo.ContributionResultVo;

import java.util.Comparator;

/**
 * @author xiazhonghai
 * @date 2021/2/3 13:54
 * @description:
 */
public class ContributionCompatorByIssue implements Comparator {
    @Override
    public int compare(Object o1, Object o2) {
        ContributionResultVo contributionResultVo1 = (ContributionResultVo) o1;
        ContributionResultVo contributionResultVo2 = (ContributionResultVo) o2;
        int i = ((Double) (contributionResultVo1.getIssue() - contributionResultVo2.getIssue())).intValue();
        if(i<0){
            return -1;
        }else {
            return 1;
        }
}}
