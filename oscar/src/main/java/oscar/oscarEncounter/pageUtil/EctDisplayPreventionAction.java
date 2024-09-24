/**
 * Copyright (c) 2001-2002. Department of Family Medicine, McMaster University. All Rights Reserved.
 * This software is published under the GPL GNU General Public License.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version. 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * This software was written for the
 * Department of Family Medicine
 * McMaster University
 * Hamilton
 * Ontario, Canada
 */


package oscar.oscarEncounter.pageUtil;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.struts.util.MessageResources;
import org.oscarehr.caisi_integrator.ws.CachedDemographicPrevention;
import org.oscarehr.common.dao.BillingONItemDao;
import org.oscarehr.util.LoggedInInfo;
import org.oscarehr.util.SpringUtils;

import oscar.oscarPrevention.Prevention;
import oscar.oscarPrevention.PreventionDS;
import oscar.oscarPrevention.PreventionData;
import oscar.oscarPrevention.PreventionDisplayConfig;
import oscar.util.StringUtils;

/**
 *  Creates DAO for left navbar of encounter form
 *
 */
public class EctDisplayPreventionAction extends EctDisplayAction {
    	private static final String cmd = "preventions";

    	public boolean getInfo(EctSessionBean bean, HttpServletRequest request, NavBarDisplayDAO Dao, MessageResources messages) {

		LoggedInInfo loggedInInfo=LoggedInInfo.getLoggedInInfoFromSession(request);

                if (!securityInfoManager.hasPrivilege(loggedInInfo, "_prevention", "r", null)) {
                	return true; //Prevention link won't show up on new CME screen.
        	} else {

        		//set lefthand module heading and link
        		String winName = "prevention" + bean.demographicNo;
			int demographicNumber = Integer.valueOf(bean.demographicNo);
        		String url = "popupPage(700,960,'" + winName + "', '" + request.getContextPath() + "/oscarPrevention/index.jsp?demographic_no=" + bean.demographicNo + "')";
        		Dao.setLeftHeading(messages.getMessage(request.getLocale(), "oscarEncounter.LeftNavBar.Prevent"));
        		Dao.setLeftURL(url);

        		//set righthand link to same as left so we have visual consistency with other modules
        		url += ";return false;";
        		Dao.setRightURL(url);
        		Dao.setRightHeadingID(cmd);  //no menu so set div id to unique id for this action
			List<String> exclusions = Collections.<String>emptyList(); 

        		//list warnings first as module items
        		Prevention p = PreventionData.getPrevention(loggedInInfo, Integer.valueOf(bean.demographicNo));
        		PreventionDS pf = SpringUtils.getBean(PreventionDS.class);//PreventionDS.getInstance();

        		try {
            			pf.getMessages(p);
        		} catch (Exception dsException) {
            			return false;
        		}	

        		//now we list prevention modules as items
        		PreventionDisplayConfig pdc = PreventionDisplayConfig.getInstance();
        		ArrayList<HashMap<String,String>> prevList = pdc.getPreventions();
        		Map warningTable = p.getWarningMsgs();
			
			// error catching for if not in Ontario, as this will fail
			try {
        			BillingONItemDao billingONItemDao = SpringUtils.getBean(BillingONItemDao.class);
        			exclusions = billingONItemDao.getPreventionExclusionsByDemographicNo(Integer.valueOf(bean.demographicNo));
			}
			catch (Exception e) {
				// no action needed; a quiet fail is acceptable if not in Ontario the above will not work
			}

        		String abnormalColour = "#EE5F5B";	// dark red
        		String highliteColour = "#FF0000";	// red
        		String inelligibleColour = "#E6AC00"; 	// dark yellow
        		String pendingColour = "#FF00FF";	// purple
        		String refusedColour = "#EAACAC";       //light pink
        		Date date = null;

        		url += "; return false;";
        		ArrayList<NavBarDisplayDAO.Item> warnings = new ArrayList<NavBarDisplayDAO.Item>();
        		ArrayList<NavBarDisplayDAO.Item> items = new ArrayList<NavBarDisplayDAO.Item>();
        		String result;
        		Date demographicDateOfBirth=PreventionData.getDemographicDateOfBirth(loggedInInfo, Integer.valueOf(bean.demographicNo));

        		// fetch and cache any remote integrated preventions.
        		List<CachedDemographicPrevention> integratedPreventions = null;
        		List<CachedDemographicPrevention> remotePreventions = PreventionData.getRemotePreventions(loggedInInfo, demographicNumber);

			if(remotePreventions.size() > 0)
        		{
                		integratedPreventions = new ArrayList<CachedDemographicPrevention>();
                		integratedPreventions.addAll(remotePreventions);
        		}

        		for (int i = 0 ; i < prevList.size(); i++){
            			boolean flagPrevention = false; 
				NavBarDisplayDAO.Item item = NavBarDisplayDAO.Item();
            			HashMap<String,String> h = prevList.get(i);
            			String prevName = h.get("name");
            			String displayName = h.get("displayName") != null ? h.get("displayName") : prevName;
            			ArrayList<Map<String,Object>> alist = PreventionData.getPreventionData(loggedInInfo, prevName, Integer.valueOf(bean.demographicNo));
            			PreventionData.addRemotePreventions(loggedInInfo, alist, Integer.valueOf(bean.demographicNo),prevName,demographicDateOfBirth);
            			boolean show = pdc.display(loggedInInfo, h, bean.demographicNo,alist.size());
            			winName = "addPreventionData";
            			url = "popupPage(700,960,'" + winName + "', '" + request.getContextPath() + "" + "/oscarPrevention/AddPreventionData.jsp?prevention="+ prevName +"&displayName="+ displayName +"&demographic_no=" + bean.demographicNo + "'); return false;";
            			if( show ) {
                			if( alist.size() > 0 ) {
                    				Map<String,Object> hdata = alist.get(alist.size()-1);
                    				Map<String,String> hExt = PreventionData.getPreventionKeyValues((String)hdata.get("id"));
                    				result = hExt.get("result");

                    				Object dateObj = hdata.get("prevention_date_asDate");
                    				if (dateObj instanceof Date){
                        				date = (Date) dateObj;
                    				} else if(dateObj instanceof java.util.GregorianCalendar){
                        				Calendar cal = (Calendar) dateObj;
                        				date = cal.getTime();
                    				}

                    				item.setDate(date);

                    				if( hdata.get("refused") != null && hdata.get("refused").equals("2") ) {
                        				item.setColour(inelligibleColour);
							flagPrevention=true;
                    				}
                    				else if( result != null && result.equalsIgnoreCase("pending") && !hdata.get("refused").equals("1")) {
                        				item.setColour(pendingColour);
							flagPrevention=true;
                    				}
                    				else if (hdata.get("refused") != null && hdata.get("refused").equals("1")){
                        				item.setColour(refusedColour);
							flagPrevention=true;
                    				}
                    				else if (result != null && result.equalsIgnoreCase("abnormal") && !hdata.get("refused").equals("1"))
                    				{
                        				item.setColour(abnormalColour);
							flagPrevention=true;
                    				}

                    				if ( hdata.get("id") != null ) {
                        				url = "popupPage(700,960,'" + winName + "', '" + request.getContextPath() + "" + "/oscarPrevention/AddPreventionData.jsp?prevention="+ prevName +"&displayName="+ displayName +"&demographic_no=" + bean.demographicNo + "&id=" + hdata.get("id") + "'); return false;";
                    				}	
                			}			
                			else {
                    				item.setDate(null);
                			}

                			String title = StringUtils.maxLenString(displayName,  MAX_LEN_TITLE, CROP_LEN_TITLE, ELLIPSES);
                			item.setTitle(title);
                			item.setLinkTitle(h.get("desc"));
                			item.setURL(url);

                			//if there's a warning associated with this prevention set item apart
                			if( warningTable.containsKey(prevName) && !exclusions.contains(prevName)){
                    				item.setColour(highliteColour);
						warnings.add(item);
					}
                			else {
                    				items.add(item);
                			}
            			}
        		}

        		//sort items without warnings chronologically
        		Dao.sortItems(items, NavBarDisplayDAO.DATESORT_ASC);

                        //add warnings to Dao array first so they will be at top of list
                        for(int idx = 0; idx < warnings.size(); ++idx )
                              Dao.addItem(warnings.get(idx));
   			//now copy remaining sorted items
                        for(int idx = 0; idx < items.size(); ++idx)
                               Dao.addItem(items.get(idx));

        		return true;
    		}
	}

    	public String getCmd() {
      		return cmd;
    	}

}

