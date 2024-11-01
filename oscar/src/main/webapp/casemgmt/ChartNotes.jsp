<%--

    Copyright (c) 2001-2002. Department of Family Medicine, McMaster University. All Rights Reserved.
    This software is published under the GPL GNU General Public License.
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    This software was written for the
    Department of Family Medicine
    McMaster University
    Hamilton
    Ontario, Canada

--%>

<%@page import="org.oscarehr.util.LoggedInInfo"%>
<%@page import="oscar.Misc"%>
<%@page import="oscar.util.UtilMisc"%>
<%@include file="/casemgmt/taglibs.jsp"%>
<%@taglib uri="/WEB-INF/caisi-tag.tld" prefix="caisi"%>
<%@page import="java.util.Enumeration"%>
<%@page import="oscar.oscarEncounter.pageUtil.NavBarDisplayDAO"%>
<%@page	import="java.util.Arrays,java.util.Properties,java.util.List,java.util.Set,java.util.ArrayList,java.util.Enumeration,java.util.HashSet,java.util.Iterator,java.text.SimpleDateFormat,java.util.Calendar,java.util.Date,java.text.ParseException"%>
<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@page import="org.oscarehr.common.model.UserProperty,org.oscarehr.casemgmt.model.*,org.oscarehr.casemgmt.service.* "%>
<%@page import="org.oscarehr.casemgmt.web.formbeans.*"%>
<%@page import="org.oscarehr.PMmodule.model.*"%>
<%@page import="org.oscarehr.common.model.*"%>
<%@page import="org.oscarehr.common.dao.EFormDao"%>
<%@page import="oscar.util.DateUtils"%>
<%@page import="oscar.dms.EDocUtil"%>
<%@page import="org.springframework.web.context.WebApplicationContext"%>
<%@page import="org.springframework.web.context.support.WebApplicationContextUtils"%>
<%@page import="org.oscarehr.casemgmt.common.Colour"%>
<%@page import="oscar.dms.EDoc"%>
<%@page import="org.springframework.web.context.support.WebApplicationContextUtils"%>
<%@page import="com.quatro.dao.security.*,com.quatro.model.security.Secrole"%>
<%@page import="org.oscarehr.util.EncounterUtil"%>
<%@page import="org.apache.cxf.common.i18n.UncheckedException"%>
<%@page import="org.oscarehr.casemgmt.web.NoteDisplay"%>
<%@page import="org.oscarehr.casemgmt.web.CaseManagementViewAction"%>
<%@page import="org.oscarehr.util.SpringUtils"%>
<%@page import="oscar.oscarRx.data.RxPrescriptionData"%>
<%@page import="org.oscarehr.casemgmt.dao.CaseManagementNoteLinkDAO"%>
<%@page import="oscar.OscarProperties"%>
<%@page import="org.oscarehr.util.MiscUtils"%>
<%@page import="org.oscarehr.PMmodule.model.Program"%>
<%@page import="org.oscarehr.PMmodule.dao.ProgramDao"%>
<%@page import="org.oscarehr.util.SpringUtils"%>
<%@page import="oscar.util.UtilDateUtilities"%>
<%@page import="org.oscarehr.casemgmt.web.NoteDisplayNonNote"%>
<%@page import="org.oscarehr.common.dao.EncounterTemplateDao"%>
<%@page import="org.oscarehr.casemgmt.web.CheckBoxBean"%>
<%@page import="org.oscarehr.common.dao.DemographicExtDao" %>
<%@page import="org.oscarehr.managers.ProgramManager2" %>
<%@page import="org.oscarehr.common.dao.SystemPreferencesDao" %>
<%@page import="java.util.HashMap" %>

<c:set var="ctx" value="${pageContext.request.contextPath}" scope="request" />


<%
    String roleName$ = (String)session.getAttribute("userrole") + "," + (String) session.getAttribute("user");
    boolean authed=true;
%>
<security:oscarSec roleName="<%=roleName$%>" objectName="_casemgmt.notes" rights="r" reverse="<%=true%>">
	<%authed=false; %>
	<%response.sendRedirect(request.getContextPath() + "/securityError.jsp?type=_casemgmt.notes");%>
</security:oscarSec>
<%
	if(!authed) {
		return;
	}
%>


<%
LoggedInInfo loggedInInfo=LoggedInInfo.getLoggedInInfoFromSession(request);


String demoNo = request.getParameter("demographicNo");
String privateConsentEnabledProperty = OscarProperties.getInstance().getProperty("privateConsentEnabled");
boolean privateConsentEnabled = privateConsentEnabledProperty != null && privateConsentEnabledProperty.equals("true");
DemographicExtDao demographicExtDao = SpringUtils.getBean(DemographicExtDao.class);
DemographicExt infoExt = demographicExtDao.getDemographicExt(Integer.parseInt(demoNo), "informedConsent");
boolean showPopup = false;
if(infoExt == null || !"yes".equalsIgnoreCase(infoExt.getValue())) {
	showPopup=true;
}

ProgramManager2 programManager2 = SpringUtils.getBean(ProgramManager2.class);

boolean showConsentsThisTime=false;
String[] privateConsentPrograms = OscarProperties.getInstance().getProperty("privateConsentPrograms","").split(",");
ProgramProvider pp = programManager2.getCurrentProgramInDomain(loggedInInfo,loggedInInfo.getLoggedInProviderNo());
if(pp != null) {
	for(int x=0;x<privateConsentPrograms.length;x++) {
		if(privateConsentPrograms[x].equals(pp.getProgramId().toString())) {
			showConsentsThisTime=true;
		}
	}
}


try
{
	Facility facility = loggedInInfo.getCurrentFacility();

    String pId = (String)session.getAttribute("case_program_id");
    if (pId == null) {
        pId = "";
    }

	String demographicNo = request.getParameter("demographicNo");
	oscar.oscarEncounter.pageUtil.EctSessionBean bean = null;
	String strBeanName = "casemgmt_oscar_bean" + demographicNo;
	if ((bean = (oscar.oscarEncounter.pageUtil.EctSessionBean)request.getSession().getAttribute(strBeanName)) == null)
	{
		response.sendRedirect("error.jsp");
		return;
	}

	String provNo = bean.providerNo;

	String dateFormat = "dd-MMM-yyyy H:mm";

	SimpleDateFormat jsfmt = new SimpleDateFormat("MMM dd, yyyy");
	Date dToday = new Date();
	String strToday = jsfmt.format(dToday);

	String frmName = "caseManagementEntryForm" + demographicNo;
	CaseManagementEntryFormBean cform = (CaseManagementEntryFormBean)session.getAttribute(frmName);

	if (request.getParameter("caseManagementEntryForm") == null)
	{
		request.setAttribute("caseManagementEntryForm", cform);
	}
	
	HashMap<String, Boolean> echartPreferencesMap = new HashMap<String, Boolean>();

	SystemPreferencesDao systemPreferencesDao = SpringUtils.getBean(SystemPreferencesDao.class);

	List<SystemPreferences> schedulePreferences = systemPreferencesDao.findPreferencesByNames(SystemPreferences.ECHART_PREFERENCE_KEYS);
	for (SystemPreferences preference : schedulePreferences) {
		echartPreferencesMap.put(preference.getName(), Boolean.parseBoolean(preference.getValue()));
	}
%>

<link rel="stylesheet" href="../css/font-awesome.min.css">

<script type="text/javascript">
    ctx = "<c:out value="${ctx}"/>";
    imgPrintgreen.src = ctx + "/oscarEncounter/graphics/printerGreen.png"; //preload green print image so firefox will update properly
    providerNo = "<%=provNo%>";
    demographicNo = "<%=demographicNo%>";
    case_program_id = "<%=pId%>";

    <caisi:isModuleLoad moduleName="caisi">
        caisiEnabled = true;
    </caisi:isModuleLoad>

    <%
    oscar.OscarProperties props = oscar.OscarProperties.getInstance();
    String requireIssue = props.getProperty("caisi.require_issue","true");
    if(requireIssue != null && requireIssue.equals("false")) {
    //require issue is false%>
    	requireIssue = false;
    <% } %>

<%
    String requireObsDate = props.getProperty("caisi.require_observation_date","true");
    if(requireObsDate != null && requireObsDate.equals("false")) {
    //do not need observation date%>
    	requireObsDate = false;
    <% } %>

    
    strToday = "<%=strToday%>";

	notesIncrement = parseInt("<%=OscarProperties.getInstance().getProperty("num_loaded_notes", "20") %>");

    jQuery(document).ready(function(){
    	notesLoader(0, notesIncrement, demographicNo);
    	notesScrollCheckInterval = setInterval('notesIncrementAndLoadMore()', 2000);
    });

    <% if( request.getAttribute("NoteLockError") != null ) { %>
		alert("<%=request.getAttribute("NoteLockError")%>");
	<%}%>
	
</script>

 <html:form action="/CaseManagementView" method="post">
	<html:hidden property="demographicNo" value="<%=demographicNo%>" />
	<html:hidden property="providerNo" value="<%=provNo%>" />
	<html:hidden property="tab" value="Current Issues" />
	<html:hidden property="hideActiveIssue" />
	<html:hidden property="ectWin.rowOneSize" styleId="rowOneSize" />
	<html:hidden property="ectWin.rowTwoSize" styleId="rowTwoSize" />
	<input type="hidden" name="chain" value="list" >
	<input type="hidden" name="method" value="view" >
	<input type="hidden" id="check_issue" name="check_issue">
	<input type="hidden" id="serverDate" value="<%=strToday%>">
	<input type="hidden" id="resetFilter" name="resetFilter" value="false">
	<div id="topContent" style="float: left; width: 100%; margin-right: -2px; padding-bottom: 1px; background-color: #CCCCFF; font-size: 10px;">
    		<nested:notEmpty name="caseManagementViewForm" property="filter_providers">
			<div style="float: left; margin-left: 10px; margin-top: 0px;"><u><bean:message key="oscarEncounter.providers.title" />:</u><br>
				<nested:iterate type="String" id="filter_provider" property="filter_providers">
					<c:choose>
						<c:when test="${filter_provider == 'a'}">All</c:when>
						<c:otherwise>
							<nested:iterate id="provider" name="providers">
								<c:if test="${filter_provider==provider.providerNo}">
									<nested:write name="provider" property="formattedName" />
									<br>
								</c:if>
							</nested:iterate>
						</c:otherwise>
					</c:choose>
				</nested:iterate>
			</div>
		</nested:notEmpty>

		<nested:notEmpty name="caseManagementViewForm" property="filter_roles">
		<div style="float: left; margin-left: 10px; margin-top: 0px;"><u><bean:message key="oscarEncounter.roles.title" />:</u><br>
			<nested:iterate type="String" id="filter_role" property="filter_roles">
				<c:choose>
					<c:when test="${filter_role == 'a'}">All</c:when>
					<c:otherwise>
						<nested:iterate id="role" name="roles">
							<c:if test="${filter_role==role.id}">
								<nested:write name="role" property="name" />
								<br>
							</c:if>
						</nested:iterate>
					</c:otherwise>
				</c:choose>
			</nested:iterate>
		</div>
		</nested:notEmpty>

		<nested:notEmpty name="caseManagementViewForm" property="note_sort">
			<div style="float: left; margin-left: 10px; margin-top: 0px;"><u><bean:message key="oscarEncounter.sort.title" />:</u><br>
			<nested:write property="note_sort" /><br>
			</div>
		</nested:notEmpty>

		<nested:notEmpty name="caseManagementViewForm" property="issues">
		<div style="float: left; margin-left: 10px; margin-top: 0px;"><u><bean:message key="oscarEncounter.issues.title" />:</u><br>
			<nested:iterate type="String" id="filter_issue" property="issues">
				<c:choose>
					<c:when test="${filter_issue == 'a'}">All</c:when>
					<c:when test="${filter_issue == 'n'}">None</c:when>
					<c:otherwise>
						<nested:iterate id="issue" name="cme_issues">
							<c:if test="${filter_issue==issue.issue.id}">
								<nested:write name="issue" property="issueDisplay.description" />
								<br>
							</c:if>
						</nested:iterate>
					</c:otherwise>
				</c:choose>
			</nested:iterate>
		</div>
		</nested:notEmpty>
		<div id="filter" style="display:none;background-color:#ddddff;padding:8px">
			<input type="button" value="<bean:message key="oscarEncounter.showView.title" />" onclick="return filter(false);" />
			<input type="button" value="<bean:message key="oscarEncounter.resetFilter.title" />" onclick="return filter(true);" />

			<table style="border-collapse:collapse;width:100%;margin-left:auto;margin-right:auto">
				<tr>
					<td style="font-size:inherit;background-color:#bbbbff;font-weight:bold">
						<bean:message key="oscarEncounter.providers.title" />
					</td>
					<td style="font-size:inherit;background-color:#bbbbff;border-left:solid #ddddff 4px;border-right:solid #ddddff 4px;font-weight:bold">
						Role
					</td>
					<td style="font-size:inherit;background-color:#bbbbff;font-weight:bold">
						<bean:message key="oscarEncounter.sort.title" />
					</td>
					<td style="font-size:inherit;background-color:#bbbbff;font-weight:bold">
						<bean:message key="oscarEncounter.issues.title" />
					</td>
					
				</tr>
				<tr>
					<td style="font-size:inherit;background-color:#ccccff">
						<div style="height:150px;overflow:auto">
							<ul style="padding:0px;margin:0px;list-style:none inside none">
								<li><html:multibox property="filter_providers" value="a" onclick="filterCheckBox(this)"></html:multibox><bean:message key="oscarEncounter.sortAll.title" /></li>
								<%
									@SuppressWarnings("unchecked")
										Set<Provider> providers = (Set<Provider>)request.getAttribute("providers");

										String providerNo;
										Provider prov;
										Iterator<Provider> iter = providers.iterator();
										while (iter.hasNext())
										{
											prov = iter.next();
											providerNo = prov.getProviderNo();
								%>
								<li><html:multibox property="filter_providers" value="<%=providerNo%>" onclick="filterCheckBox(this)"></html:multibox><%=prov.getFormattedName()%></li>
								<%
									}
								%>
							</ul>
						</div>
					</td>
					<td style="font-size:inherit;background-color:#ccccff;border-left:solid #ddddff 4px;border-right:solid #ddddff 4px">
						<div style="height:150px;overflow:auto">
							<ul style="padding:0px;margin:0px;list-style:none inside none">
								<li><html:multibox property="filter_roles" value="a" onclick="filterCheckBox(this)"></html:multibox><bean:message key="oscarEncounter.sortAll.title" /></li>
								<%
									@SuppressWarnings("unchecked")
										List roles = (List)request.getAttribute("roles");
										for (int num = 0; num < roles.size(); ++num)
										{
											Secrole role = (Secrole)roles.get(num);
								%>
								<li><html:multibox property="filter_roles" value="<%=String.valueOf(role.getId())%>" onclick="filterCheckBox(this)"></html:multibox><%=role.getName()%></li>
								<%
									}
								%>
							</ul>
						</div>
					</td>
					
					<td style="font-size:inherit;background-color:#ccccff">
						<div style="height:150px;overflow:auto">
							<ul style="padding:0px;margin:0px;list-style:none inside none">
								<li><html:radio property="note_sort" value="observation_date_asc">
									<bean:message key="oscarEncounter.sortDateAsc.title" />
								</html:radio></li>
								<li><html:radio property="note_sort" value="observation_date_desc">
									<bean:message key="oscarEncounter.sortDateDesc.title" />
								</html:radio></li>
								<li><html:radio property="note_sort" value="providerName">
									<bean:message key="oscarEncounter.provider.title" />
								</html:radio></li>
								<li><html:radio property="note_sort" value="programName">
									<bean:message key="oscarEncounter.program.title" />
								</html:radio></li>
								<li><html:radio property="note_sort" value="roleName">
									<bean:message key="oscarEncounter.role.title" />
								</html:radio></li>
							</ul>
						</div>
					</td>
					<td style="font-size:inherit;background-color:#ccccff;border-left:solid #ddddff 4px;border-right:solid #ddddff 4px">
						<div style="height:150px;overflow:auto">
							<ul style="padding:0px;margin:0px;list-style:none inside none">
								<li><html:multibox property="issues" value="a" onclick="filterCheckBox(this)"></html:multibox><bean:message key="oscarEncounter.sortAll.title" /></li>
								<li><html:multibox property="issues" value="n" onclick="filterCheckBox(this)"></html:multibox>None</li>
								
								<%
									@SuppressWarnings("unchecked")
										List issues = (List)request.getAttribute("cme_issues");
										for (int num = 0; num < issues.size(); ++num)
										{
											CheckBoxBean issue_checkBoxBean = (CheckBoxBean)issues.get(num);
								%>
								<li><html:multibox property="issues" value="<%=String.valueOf(issue_checkBoxBean.getIssue().getId())%>" onclick="filterCheckBox(this)"></html:multibox><%=issue_checkBoxBean.getIssueDisplay().getResolved().equals("resolved")?"* ":""%> <%=issue_checkBoxBean.getIssueDisplay().getDescription()%></li>
								<%
									}
								%>
							</ul>
						</div>
					</td>
				</tr>
			</table>
		</div>

		<div style="float: left; clear: both; margin-top: 5px; margin-bottom: 3px; width: 100%; text-align: center;">
			<div style="display:inline-block">
				
				<input id="enTemplate" tabindex="6" style="width:160px" placeholder='<bean:message key="global.search" />!' type="text" value="" onkeypress="return grabEnterGetTemplate(event)">

				<div class="enTemplate_name_auto_complete" id="enTemplate_list" style="z-index: 1; display: none">&nbsp;</div>						

				<!-- <input type="text" id="keyword" name="keyword" value="" style="width: 10px; text-align: center;" onkeypress="return grabEnter('searchButton',event)">-->
				<button id="searchButton" name="button" alt="<bean:message key="oscarEncounter.msgFind"/>" onClick="popupPage(600,800,'<bean:message key="oscarEncounter.Index.popupSearchPageWindow"/>' ,$('channel').options[$('channel').selectedIndex].value+urlencode($F('enTemplate')) ); return false;"><i class="icon-search"></i></button>

				<div style="display:inline-block; text-align: left;">
					<%
						if (privateConsentEnabled && showPopup && showConsentsThisTime) {
					%>				
					<div id="informedConsentDiv" style="background-color: orange; padding: 5px; font-weight: bold;">
						<input type="checkbox" value="ic" name="informedConsentCheck" id="informedConsentCheck" onClick="return doInformedConsent('<%=demoNo%>');"/>&nbsp;Please ensure that Informed Consent has been obtained!
					</div>
					<%
						}
					%>
					
					<!-- channel -->
					<select id="channel">
                    <%
                        String customSearchNameProperty = OscarProperties.getInstance().getProperty("customSearchName");
                        String customSearchUrlProperty = OscarProperties.getInstance().getProperty("customSearchUrl");
                        if (customSearchNameProperty != null && customSearchNameProperty !="" && customSearchUrlProperty!="" ) {
					%>
                    <option value="<%=customSearchUrlProperty%>"><%=customSearchNameProperty%></option>
					<%
						}
					%>
                    <%
                        String customSearchNameProperty2 = OscarProperties.getInstance().getProperty("customSearchName2");
                        String customSearchUrlProperty2 = OscarProperties.getInstance().getProperty("customSearchUrl2");
                        if (customSearchNameProperty2 != null && customSearchNameProperty2 !="" && customSearchUrlProperty2!="" ) {
					%>
                    <option value="<%=customSearchUrlProperty2%>"><%=customSearchNameProperty2%></option>
					<%
						}
					%>
                    <%
                        String customSearchNameProperty3 = OscarProperties.getInstance().getProperty("customSearchName3");
                        String customSearchUrlProperty3 = OscarProperties.getInstance().getProperty("customSearchUrl3");
                        if (customSearchNameProperty3 != null && customSearchNameProperty2 !="" && customSearchUrlProperty3!="" ) {
					%>
                    <option value="<%=customSearchUrlProperty3%>"><%=customSearchNameProperty3%></option>
					<%
						}
					%>
					<!-- <option value="http://resource.oscarmcmaster.org/oscarResource/OSCAR_search?query="><bean:message key="oscarEncounter.Index.oscarSearch" /> -->
					<option value="http://www.google.com/search?q="><bean:message key="global.google" /></option>
					<option value="http://www.ncbi.nlm.nih.gov/entrez/query.fcgi?SUBMIT=y&amp;CDM=Search&amp;DB=PubMed&amp;term="><bean:message key="global.pubmed" /></option>				
					<option value="http://search.nlm.nih.gov/medlineplus/query?DISAMBIGUATION=true&amp;FUNCTION=search&amp;SERVER2=server2&amp;SERVER1=server1&amp;PARAMETER="><bean:message key="global.medlineplus" /></option>
                    <option value="tripsearch.jsp?searchterm=">Trip Database</option>
                    <option value="macplussearch.jsp?searchterm=">MacPlus Database</option>
                    <option value="https://empendium.com/mcmtextbook/search?type=textbook&q=">McMaster Text Book</option>
    	        </select>
				</div>				

			</div>
			&nbsp;
			<!-- <div style="display:inline-block;text-align: left;background-color:#ccccff" id="toolbar">-->
				<button type="button" onclick="showFilter();" /><bean:message key="oscarEncounter.Filter.title"/></button> 
				<%
					String roleName = (String)session.getAttribute("userrole") + "," + (String) session.getAttribute("user");
					String pAge = Integer.toString(UtilDateUtilities.calcAge(bean.yearOfBirth,bean.monthOfBirth,bean.dateOfBirth));
				%>
				<security:oscarSec roleName="<%=roleName%>" objectName="_newCasemgmt.calculators" rights="r" reverse="false">
					<%@include file="calculatorsSelectList.jspf" %>
				</security:oscarSec>
				<%--<security:oscarSec roleName="<%=roleName%>" objectName="_admin.templates" rights="r"> --%>
				<security:oscarSec roleName="<%=roleName%>" objectName="_newCasemgmt.templates" rights="r">
					<select style="width:100px;" onchange="javascript:popupPage(700,700,'Templates',this.value);">
						<option value="-1"><bean:message key="oscarEncounter.Header.Templates"/></option>
						<option value="-1">------------------</option>
						<security:oscarSec roleName="<%=roleName%>" objectName="_newCasemgmt.templates" rights="w">
						<option value="<%=request.getContextPath()%>/admin/providertemplate.jsp">New / Edit Template</option>
						<option value="-1">------------------</option>
						</security:oscarSec>
						<%
							EncounterTemplateDao encounterTemplateDao=(EncounterTemplateDao)SpringUtils.getBean("encounterTemplateDao");
							List<EncounterTemplate> allTemplates=encounterTemplateDao.findAll();

							for (EncounterTemplate encounterTemplate : allTemplates)
							{
								String templateName=StringEscapeUtils.escapeHtml(encounterTemplate.getEncounterTemplateName());
								%>
									<option value="<%=request.getContextPath()+"/admin/providertemplate.jsp?dboperation=Edit&name="+templateName%>"><%=templateName%></option>
								<%
							}
						%>
					</select>
				</security:oscarSec>
				
				<span id="phrButtonArea">
				</span>
				<script>
				function updateMYOSCAR(){
					jQuery.getScript('phrLinks.jsp?demographicNo=<%=demographicNo%>');
				}
				updateMYOSCAR();
				
				jQuery(document).ready(function(){
		    			jQuery.ajax({
			  			type: "GET",
		    		        url: "<%=request.getContextPath()%>/ws/rs/app/providerChartLaunchItems",
				        dataType: 'json',
				        success: function (data,textStatus,jqXHR) {
                        console.log("PHR status="+jqXHR.status);
                            if (data  && jqXHR.status == "200") {
                                for (i = 0; i < data.length; i++) {
                                    d = data[i];
                                    jQuery("#phrButtonArea").append(
                                        jQuery("<button/>")
                                            .text(d.heading)
                                            .click(function () {
                                                window.open('../ws/rs/app/openProviderPHRWindow/' + d.link + '<%=demographicNo%>');
                                            }));
                                }
                            }
                        }
					});
			    });
				
				</script>
				
			<!-- </div> -->	
		</div>
	</div>
</html:form>
        <%
            String oscarMsgType = (String)request.getParameter("msgType");   
            String OscarMsgTypeLink = (String)request.getParameter("OscarMsgTypeLink");
         %>
<nested:form action="/CaseManagementEntry" style="display:inline; margin-top:0; margin-bottom:0; position: relative;">
	<html:hidden property="demographicNo" value="<%=demographicNo%>" />
	<html:hidden property="includeIssue" value="off" />
        <input type="hidden" name="OscarMsgType" value="<%=oscarMsgType%>"/>        
        <input type="hidden" name="OscarMsgTypeLink" value="<%=OscarMsgTypeLink%>"/>
	<%
		String apptNo = request.getParameter("appointmentNo");
		if (apptNo == null || apptNo.equals("") || apptNo.equals("null"))
		{
			apptNo = "0";
		}

		String apptDate = request.getParameter("appointmentDate");
		if (apptDate == null || apptDate.equals("") || apptDate.equals("null"))
		{
			apptDate = oscar.util.UtilDateUtilities.getToday("yyyy-MM-dd");
		}

		String startTime = request.getParameter("start_time");
		if (startTime == null || startTime.equals("") || startTime.equals("null"))
		{
			startTime = "00:00:00";
		}

		String apptProv = request.getParameter("apptProvider");
		if (apptProv == null || apptProv.equals("") || apptProv.equals("null"))
		{
			apptProv = "none";
		}

		String provView = request.getParameter("providerview");
		if (provView == null || provView.equals("") || provView.equals("null"))
		{
			provView = provNo;
		}
	%>
        
	<html:hidden property="appointmentNo" value="<%=apptNo%>" />
	<html:hidden property="appointmentDate" value="<%=apptDate%>" />
	<html:hidden property="start_time" value="<%=startTime%>" />
	<html:hidden property="billRegion" value="<%=(OscarProperties.getInstance().getProperty(\"billregion\",\"\")).trim().toUpperCase()%>" />
	<html:hidden property="apptProvider" value="<%=apptProv%>" />
	<html:hidden property="providerview" value="<%=provView%>" />
	<input type="hidden" name="toBill" id="toBill" value="false">
	<input type="hidden" name="deleteId" value="0">
	<input type="hidden" name="lineId" value="0">
	<input type="hidden" name="from" value="casemgmt">
	<input type="hidden" name="method" value="save">
	<input type="hidden" name="change_diagnosis" value="<c:out value="${change_diagnosis}"/>">
	<input type="hidden" name="change_diagnosis_id" value="<c:out value="${change_diagnosis_id}"/>">
	<input type="hidden" name="newIssueId" id="newIssueId">
	<input type="hidden" name="newIssueName" id="newIssueName">
	<input type="hidden" name="ajax" value="false">
	<input type="hidden" name="chain" value="">
	<input type="hidden" name="caseNote.program_no" value="<%=pId%>">
	<input type="hidden" name="noteId" value="0">
	<input type="hidden" name="note_edit" value="">
	<input type="hidden" name="sign" value="off">
	<input type="hidden" name="verify" value="off">
	<input type="hidden" name="forceNote" value="false">
	<input type="hidden" name="newNoteIdx" value="">
	<input type="hidden" name="notes2print" id="notes2print" value="">
	<input type="hidden" name="printCPP" id="printCPP" value="false">
	<input type="hidden" name="printRx" id="printRx" value="false">
	<input type="hidden" name="pType" id="pType" value="">   
	<input type="hidden" name="printLabs" id="printLabs" value="false">
	<input type="hidden" name="printMeasurements" id="printMeasurements" value="false">
	<input type="hidden" name="printNotes" id="printNotes" value="true">
	<input type="hidden" name="printPreventions" id="printPreventions" value="false">
	<input type="hidden" name="printDocuments" id="printDocuments" value="false">
	<input type="hidden" name="printHrms" id="printHrms" value="false">
	<input type="hidden" name="encType" id="encType" value="">
	<input type="hidden" name="pStartDate" id="pStartDate" value="">
	<input type="hidden" name="pEndDate" id="pEndDate" value="">
	<input type="hidden" name="selectedSiteIdForPrint" id="selectedSiteIdForPrint" value="">
	<input type="hidden" id="annotation_attribname" name="annotation_attribname" value="">	
	
	<%
 	if (OscarProperties.getInstance().getBooleanProperty("note_program_ui_enabled", "true")) {
 	%>
 		<input type="hidden" name="_note_program_no" value="" />
 		<input type="hidden" name="_note_role_id" value="" />
 	<% } %>
 	
	<span id="notesLoading">
		<img src="<c:out value="${ctx}/images/DMSLoader.gif" />">Loading Notes...
	</span>

	<div id="mainContent" style="background-color: #FFFFFF; width: 100%; margin-right: -2px; display: inline; float: left;">
	<div id="issueList" style="background-color: #FFFFFF; height: 440px; width: 350px; position: absolute; z-index: 1; display: none; overflow: auto;">
	<table id="issueTable" class="enTemplate_name_auto_complete" style="position: relative; left: 0px; display: none;">
		<tr>
			<td style="height: 430px; vertical-align: bottom;">
				<div class="enTemplate_name_auto_complete" id="issueAutocompleteList" style="position: relative; left: 0px; display: none;"></div>
			</td>
		</tr>
	</table>
	</div>
	<div id="encMainDiv" style="width: 99%; border-top: thin groove #000000; border-right: thin groove #000000; border-left: thin groove #000000; background-color: #FFFFFF; height: 410px; overflow: auto; margin-left: 2px;">

	</div>
	<script type="text/javascript">

		if (parseInt(navigator.appVersion)>3) {
			var windowHeight=750;
			if (navigator.appName=="Netscape") {
				windowHeight = window.innerHeight;
			}
			if (navigator.appName.indexOf("Microsoft")!=-1) {
				windowHeight = document.body.offsetHeight;
			}

			var divHeight=windowHeight-280;
			$("encMainDiv").style.height = divHeight+'px';
		}
	</script>

	<div id='save' style="width: 99%; background-color: #CCCCFF; padding-top: 5px; margin-left: 2px; border-left: thin solid #000000; border-right: thin solid #000000; border-bottom: thin solid #000000;">
		<span style="float: right; margin-right: 5px;">
<style>
.btn {
color:#4a4a4a ;
text-decoration:none;
font-size: 17px;	
padding: 2px;
}
</style>

    <% boolean renderMarkdown = OscarProperties.getInstance().getBooleanProperty("encounter.render_markdown", "true");
       if (renderMarkdown){ %>
          <a class="btn" id="bold" href="#" onclick="addBold();return false;" title='<bean:message key="global.bold"/>'><i class="icon-bold icon-large"></i></a> 
          <a class="btn" id="italic" href="#" onclick="addItalic();return false;" title='<bean:message key="global.italic"/>'><i class="icon-italic icon-large"></i></a>
          <a class="btn" id="ul" href="#" onclick="addHandler();addUnorderedList();return false;" title='<bean:message key="global.ul"/>'><i class="icon-list-ul icon-large"></i></a>
          <a class="btn" id="ol" href="#" onclick="addHandler();addOrderedList();return false;" title='<bean:message key="global.ol"/>'><i class="icon-list-ol icon-large"></i></a>
          <a class="btn" id="h2" href="#" onclick="addHeading(2);return false;" title='<bean:message key="global.heading"/>'><i class="icon-h-sign icon-large"></i></a>
          <a class="btn" id="link" href="#" onclick="addLink();return false;" title='<bean:message key="global.link"/>'><i class="icon-link icon-large"></i></a>

    <% } %>

		<% if (echartPreferencesMap.getOrDefault("echart_show_timer", true)) { %>
			<button type="button" onclick="pasteTimer()" id="aTimer" title="<bean:message key="oscarEncounter.Index.pasteTimer"/>">00:00</button>
			<button type="button" id="toggleTimer" onclick="toggleATimer()"  title='<bean:message key="oscarEncounter.Index.toggleTimer"/>'>&#8741;</button>
		<% } %>





  <a tabindex="17" class="btn" id="saveImg" href="#" onclick="Event.stop(event);" title='<bean:message key="oscarEncounter.Index.btnSave"/>'><i class="icon-save icon-large"></i></a> 
		
		<%
			if(facility.isEnableGroupNotes()) {
		%>
			<a class="btn" href="#" tabindex="16" id="groupNoteImg" onclick="Event.stop(event);return selectGroup(document.forms['caseManagementEntryForm'].elements['caseNote.program_no'].value,document.forms['caseManagementEntryForm'].elements['demographicNo'].value);" title='<bean:message key="oscarEncounter.Index.btnGroupNote"/>'><i class="icon-group icon-large"></i></a>
		<%  }
			if(facility.isEnablePhoneEncounter()) {
		%>
			<a class="btn" tabindex="25" id="attachNoteImg"  href="#" onclick="Event.stop(event);return assign(document.forms['caseManagementEntryForm'].elements['caseNote.program_no'].value,document.forms['caseManagementEntryForm'].elements['demographicNo'].value);" title='<bean:message key="oscarEncounter.Index.btnAttachNote"/>'><i class="icon-paper-clip icon-large"></i></a>
		<%  } %>

			<a tabindex="18" class="btn" href="#" id="newNoteImg" onclick="newNote(event); return false;" title='<bean:message key="oscarEncounter.Index.btnNew"/>'><i class="icon-file-text icon-large"></i></a>

			<a tabindex="19" class="btn" href="#" id="signSaveImg" onclick="document.forms['caseManagementEntryForm'].sign.value='on';Event.stop(event);return savePage('saveAndExit', '');" title='<bean:message key="oscarEncounter.Index.btnSignSave"/>'><i class="icon-edit icon-large"></i></a>
			<a tabindex="20" class="btn" href="#" id="signVerifyImg" onclick="document.forms['caseManagementEntryForm'].sign.value='on';document.forms['caseManagementEntryForm'].verify.value='on';Event.stop(event);return savePage('saveAndExit', '');" title='<bean:message key="oscarEncounter.Index.btnSign"/>'><i class="icon-thumbs-up icon-large"></i></a>

			<%
				if(bean.source == null)  {
				%>
					<a tabindex="21" class="btn" href="#" onclick="document.forms['caseManagementEntryForm'].sign.value='on';document.forms['caseManagementEntryForm'].toBill.value='true';Event.stop(event);return savePage('saveAndExit', '');" title='<bean:message key="oscarEncounter.Index.btnBill"/>'><i class="icon-money icon-large"></i></a>

				<%
				}
			%>

	    	<a tabindex="23" class="btn" href="#"  onclick='closeEnc(event);return false;' title='<bean:message key="global.btnExit"/>'><i class="icon-share icon-large"></i></a>
	    	<a tabindex="24" class="btn" href="#" onclick="return printSetup(event);" title='<bean:message key="oscarEncounter.Index.btnPrint"/>' id="imgPrintEncounter"><i class="icon-print icon-large"></i></a>	&nbsp;		

	    	

    	</span>
    	<div id="assignIssueSection">
	    	<!-- input type='image' id='toggleIssue' onclick="return showIssues(event);" src="<c:out value="${ctx}/oscarEncounter/graphics/issues.png"/>" title='<bean:message key="oscarEncounter.Index.btnDisplayIssues"/>'>&nbsp; -->
	    	<input tabindex="8" type="text" id="issueAutocomplete" name="issueSearch" style="z-index: 2;" onkeypress="return submitIssue(event);" size="25">&nbsp; <button tabindex="9" type="button" id="asgnIssues" ><bean:message key="oscarEncounter.assign.title"/></button>
	    	<span id="busy" style="display: none">
	    		<img style="position: absolute;" src="<c:out value="${ctx}/oscarEncounter/graphics/busy.gif"/>" alt="<bean:message key="oscarEncounter.Index.btnWorking" />">
	    	</span>
    	</div>
    	<div style="padding-top: 3px;">
    		<button type="button" onclick="return showHideIssues(event, 'noteIssues-resolved');"><bean:message key="oscarEncounter.Index.btnDisplayResolvedIssues"/></button> &nbsp;
    		<button type="button" onclick="return showHideIssues(event, 'noteIssues-unresolved');"><bean:message key="oscarEncounter.Index.btnDisplayUnresolvedIssues"/></button> &nbsp;
    		<button type="button" onclick="javascript:spellCheck();">Spell Check</button> &nbsp;
    		<button type="button" onclick="javascript:toggleFullViewForAll(this.form);"><bean:message key="eFormGenerator.expandAll"/> <bean:message key="Appointment.formNotes"/></button>
                <button type="button" onclick="javascript:popupPage(500,200,'noteBrowser<%=bean.demographicNo%>','noteBrowser.jsp?demographic_no=<%=bean.demographicNo%>&FirstTime=1');"><bean:message key="oscarEncounter.Index.BrowseNotes"/></button> &nbsp;
    	</div>
    </div>

</div>
</nested:form>



<%
}
catch (Exception e)
{
	MiscUtils.getLogger().error("Unexpected error.", e);
}
%>