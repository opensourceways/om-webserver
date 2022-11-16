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

import com.om.Vo.ContributionResultVo;
import java.util.Comparator;


/**
 * @author xiazhonghai
 * @date 2021/2/3 13:54
 * @description:
 */
public class ContributionCompatorByPr implements Comparator {
    @Override
    public int compare(Object o1, Object o2) {
        ContributionResultVo contributionResultVo1 = (ContributionResultVo) o1;
        ContributionResultVo contributionResultVo2 = (ContributionResultVo) o2;
        int i = ((Double) (contributionResultVo1.getPr() - contributionResultVo2.getPr())).intValue();
        if(i<0){
            return -1;
        }else {
            return 1;
        }
    }
}
