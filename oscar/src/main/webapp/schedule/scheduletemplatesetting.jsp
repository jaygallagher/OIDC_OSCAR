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
<!DOCTYPE html>
<%

%>
<%@ page import="java.util.*, java.sql.*, oscar.*, java.text.*, java.lang.*" errorPage="../appointment/errorpage.jsp"%>
<%@ page import="org.oscarehr.common.model.Provider" %>
<%@ page import="org.oscarehr.PMmodule.dao.ProviderDao" %>
<%@ page import="org.oscarehr.util.SpringUtils" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ taglib uri="/WEB-INF/struts-bean.tld" prefix="bean"%>
<%@ taglib uri="/WEB-INF/struts-html.tld" prefix="html"%>
<%@ taglib uri="/WEB-INF/security.tld" prefix="security"%>


<%
    String curProvider_no = (String) session.getAttribute("user");
	String roleName$ = (String)session.getAttribute("userrole") + "," + (String) session.getAttribute("user");
%>

<%
  GregorianCalendar now=new GregorianCalendar();
  int year = now.get(Calendar.YEAR);
  int month = (now.get(Calendar.MONTH)+1);
  int day = now.get(Calendar.DAY_OF_MONTH);

%>

<%
    boolean isSiteAccessPrivacy=false;
    boolean isTeamAccessPrivacy=false;

    boolean grantOnlyCurProviderScheduleData = false;
%>
<security:oscarSec objectName="_site_access_privacy" roleName="<%=roleName$%>" rights="r" reverse="false">
	<%
		isSiteAccessPrivacy=true;

	%>
</security:oscarSec>
<security:oscarSec objectName="_team_access_privacy" roleName="<%=roleName$%>" rights="r" reverse="false">
	<%
		isTeamAccessPrivacy=true;

	%>
</security:oscarSec>

<security:oscarSec roleName="<%=roleName$%>" objectName="_admin.schedule.curprovider_only" rights="r" reverse="<%=false%>">
	<%
		grantOnlyCurProviderScheduleData = true;
	%>
</security:oscarSec>

<html:html locale="true">
<head>
<script type="text/javascript" src="<%= request.getContextPath() %>/js/global.js"></script>
<title><bean:message
	key="schedule.scheduletemplatesetting.title" /></title>
<link href="${pageContext.request.contextPath}/css/bootstrap.css" rel="stylesheet" type="text/css"> <!-- Bootstrap 2.3.1 -->

<script language="JavaScript">
<!--
function setfocus() {
  this.focus();
}

function selectprovider(s) {
	self.location.href = "scheduletemplateapplying.jsp?provider_no="+s.options[s.selectedIndex].value+"&provider_name="+urlencode(s.options[s.selectedIndex].text);
}
function urlencode(str) {
	var ns = (navigator.appName=="Netscape") ? 1 : 0;
	if (ns) { return escape(str); }
	var ms = "%25#23 20+2B?3F<3C>3E{7B}7D[5B]5D|7C^5E~7E`60";
	var msi = 0;
	var i,c,rs,ts ;
	while (msi < ms.length) {
		c = ms.charAt(msi);
		rs = ms.substring(++msi, msi +2);
		msi += 2;
		i = 0;
		while (true)	{
			i = str.indexOf(c, i);
			if (i == -1) break;
			ts = str.substring(0, i);
			str = ts + "%" + rs + str.substring(++i, str.length);
		}
	}
	return str;
}

function go() {
  var s = document.schedule.providerid.value ;
  var u = 'scheduleedittemplate.jsp?providerid=' + s +'&providername='+urlencode(document.schedule.providerid.options[document.schedule.providerid.selectedIndex].text);
	popupPage(700,800,u);
}
//-->
</script>
</head>
<body onLoad="setfocus()">
<form method="post" name="schedule" action="schedulecreatedate.jsp">

<h4><bean:message key="schedule.scheduletemplatesetting.msgMainLabel" /></h4>

<div class="alert">
<bean:message key="schedule.scheduletemplatesetting.msgStepOne" />
<br>
<bean:message key="schedule.scheduletemplatesetting.msgStepTwo" />
</div>
<div class="well">
		<table style="width:95%">
			<tr>
				<td><bean:message
					key="schedule.scheduletemplatesetting.formSelectProvider" />:&nbsp;&nbsp;<select name="provider_no"
					onChange="selectprovider(this)">
					<option value=""><bean:message
						key="schedule.scheduletemplatesetting.msgNoProvider" /></option>

						<%
							ProviderDao providerDao = SpringUtils.getBean(ProviderDao.class);

							List<Provider> providers = null;

							if (grantOnlyCurProviderScheduleData)
							{
								//only the allow the user to manipulate their own schedule
								providers = new ArrayList<Provider>();

								Provider curProvider = providerDao.getProvider(curProvider_no);

								if (curProvider != null)
								{
									providers.add(curProvider);
								}
							}
							else
							{
								providers = providerDao.getActiveProviders();
							}
							//TODO: filter by site/team if necessary

							for(Provider p:providers) {
						%>
							<option value="<%=p.getProviderNo()%>"><%=Encode.forHtmlContent(p.getFormattedName())%></option>

						<% } %>

				</select></td>
			</tr>
			<tr>
				<td>&nbsp;</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
			</tr>
			<tr>
				<td>
				<p><bean:message key="schedule.scheduletemplatesetting.formOrDo" />:</p>
				</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
			</tr>
		<%if (!( isSiteAccessPrivacy  || isTeamAccessPrivacy || grantOnlyCurProviderScheduleData)) {%>
			<tr>
				<td nowrap style="background-color:#CCFFCC">&nbsp; <a HREF="#"
					ONCLICK="popupPage(540,530,'scheduleholidaysetting.jsp?year=<%=year%>&month=<%=month%>&day=<%=day%>')"
					TITLE='<bean:message key="schedule.scheduletemplatesetting.msgHolidaySettingTip"/>;return true'><bean:message
					key="schedule.scheduletemplatesetting.btnHolidaySetting" /></a></td>
			</tr>
			<tr>
				<td>&nbsp;</td>
			</tr>
			<tr>

				<td nowrap style="background-color:#CCFFCC">&nbsp; <a HREF="#"
					ONCLICK="popupPage(600,700,'scheduletemplatecodesetting.jsp')"><bean:message
					key="schedule.scheduletemplatesetting.btnTemplateCodeSetting" /></a></td>


			</tr>
		<%} %>
			<tr>
				<td nowrap style="background-color:#CCFFCC">&nbsp; <a HREF="#" onClick="go()"><bean:message
					key="schedule.scheduletemplatesetting.btnTemplateSetting" /></a>&nbsp;<bean:message
					key="schedule.scheduletemplatesetting.msgForProvider" />&nbsp; <select
					name="providerid">
					<option value="Public"><bean:message
						key="schedule.scheduletemplatesetting.msgPublic" /></option>
<%
							for(Provider p:providers) {
						%>
							<option value="<%=p.getProviderNo()%>"><%=Encode.forHtmlContent(p.getFormattedName())%></option>

						<% } %>

				</select></td>
			</tr>
			<tr>
				<td>
				<div align="left"></div>
				</td>
			</tr>
			<tr>
				<td>
				<div align="right"></div>
				</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
			</tr>
		</table>
</div>

</form>
</body>
</html:html>