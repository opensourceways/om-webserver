package com.om.Vo;

/**
 * @author xiazhonghai
 * @date 2021/2/3 9:56
 * @description:
 */
public class ContributionVo {

    String community;
    String type;
    String individualSearchKey;
    String organizationSearchKey;
    String currentPage;
    String pageSize;
    String sortKey;
    String sortValue;

    public String getCommunity() {
        return community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getIndividualSearchKey() {
        return individualSearchKey;
    }

    public void setIndividualSearchKey(String individualSearchKey) {
        this.individualSearchKey = individualSearchKey;
    }

    public String getOrganizationSearchKey() {
        return organizationSearchKey;
    }

    public void setOrganizationSearchKey(String organizationSearchKey) {
        this.organizationSearchKey = organizationSearchKey;
    }

    public String getCurrentPage() {
        return currentPage;
    }

    public void setCurrentPage(String currentPage) {
        this.currentPage = currentPage;
    }

    public String getPageSize() {
        return pageSize;
    }

    public void setPageSize(String pageSize) {
        this.pageSize = pageSize;
    }

    public String getSortKey() {
        return sortKey;
    }

    public void setSortKey(String sortKey) {
        this.sortKey = sortKey;
    }

    public String getSortValue() {
        return sortValue;
    }

    public void setSortValue(String sortValue) {
        this.sortValue = sortValue;
    }
}
