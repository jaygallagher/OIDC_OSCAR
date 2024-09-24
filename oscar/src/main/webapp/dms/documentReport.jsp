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
<%@page import="org.oscarehr.util.SpringUtils"%>
<%@page import="org.oscarehr.sharingcenter.SharingCenterUtil"%>
<%@page import="org.oscarehr.sharingcenter.dao.AffinityDomainDao"%>
<%@page import="org.oscarehr.sharingcenter.model.AffinityDomainDataObject"%>
<%@page import="org.oscarehr.myoscar.utils.MyOscarLoggedInInfo"%>
<%@page import="org.oscarehr.util.LocaleUtils"%>
<%@page import="org.oscarehr.phr.util.MyOscarUtils"%>
<%@page import="org.oscarehr.util.MiscUtils"%>
<%@page import="org.oscarehr.util.LoggedInInfo"%>
<%@page import="org.oscarehr.common.dao.UserPropertyDAO, org.oscarehr.common.model.UserProperty, org.springframework.web.context.support.WebApplicationContextUtils" %>
<%@ page import="org.owasp.encoder.Encode" %>

<%
LoggedInInfo loggedInInfo=LoggedInInfo.getLoggedInInfoFromSession(request);
if(session.getValue("user") == null) response.sendRedirect("${ pageContext.request.contextPath }/logout.htm");
if(session.getAttribute("userrole") == null )  response.sendRedirect("${ pageContext.request.contextPath }/logout.jsp");
String roleName$ = (String)session.getAttribute("userrole") + "," + (String) session.getAttribute("user");
String user_no = (String) session.getAttribute("user");
String demographicNo=(String)session.getAttribute("casemgmt_DemoNo");
String userfirstname = (String) session.getAttribute("userfirstname");
String userlastname = (String) session.getAttribute("userlastname");

String annotation_display = org.oscarehr.casemgmt.model.CaseManagementNoteLink.DISP_DOCUMENT;
String appointment = request.getParameter("appointmentNo");
int appointmentNo = 0;
if(appointment != null && appointment.length()>0) {
  appointmentNo = Integer.parseInt(appointment);
}

// MARC-HI's Sharing Center
boolean isSharingCenterEnabled = SharingCenterUtil.isEnabled();

// get all installed affinity domains
AffinityDomainDao affDao = SpringUtils.getBean(AffinityDomainDao.class);
List<AffinityDomainDataObject> affinityDomains = affDao.getAllAffinityDomains();

%>

<%@ taglib uri="/WEB-INF/struts-bean.tld" prefix="bean"%>
<%@ taglib uri="/WEB-INF/struts-html.tld" prefix="html"%>
<%@ taglib uri="/WEB-INF/rewrite-tag.tld" prefix="rewrite"%>
<%@ taglib uri="/WEB-INF/oscarProperties-tag.tld" prefix="oscarProp"%>
<%@ taglib uri="/WEB-INF/indivo-tag.tld" prefix="indivo"%>
<%@ taglib uri="/WEB-INF/security.tld" prefix="security"%>
<%@ taglib uri="/WEB-INF/oscar-tag.tld" prefix="oscar" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<%@ page import="java.math.*, java.util.*, java.io.*, java.sql.*, oscar.*, oscar.util.*, java.net.*,oscar.MyDateFormat, oscar.dms.*, oscar.dms.data.*, oscar.oscarProvider.data.ProviderMyOscarIdData, oscar.oscarDemographic.data.DemographicData"%>
<%@ page import="org.oscarehr.common.dao.CtlDocClassDao"%>

<%@ page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@page import="org.oscarehr.util.SessionConstants"%>
<c:set var="ctx" value="${pageContext.request.contextPath}" scope="request" />


<%
    boolean authed=true;
%>
<security:oscarSec roleName="<%=roleName$%>" objectName="_edoc,_admin,_admin.edocdelete" rights="r" reverse="<%=true%>">
	<%authed=false; %>
	<%response.sendRedirect("${ pageContext.request.contextPath }/securityError.jsp?type=_edoc&type=_admin&type=_admin.edocdelete");%>
</security:oscarSec>
<%
	if(!authed) {
		return;
	}
%>

<%@ page import="oscar.OscarProperties" %>

<%
UserPropertyDAO userPropertyDao = SpringUtils.getBean(UserPropertyDAO.class);
Properties oscarVariables = OscarProperties.getInstance();
String help_url = (oscarVariables.getProperty("HELP_SEARCH_URL","https://oscargalaxy.org/knowledge-base/")).trim();

//if delete request is made
if (request.getParameter("delDocumentNo") != null) {
    EDocUtil.deleteDocument(request.getParameter("delDocumentNo"));
}

//if undelete request is made
if (request.getParameter("undelDocumentNo") != null) {
    EDocUtil.undeleteDocument(request.getParameter("undelDocumentNo"));
}

//view  - tabs
String view = "all";
if (request.getParameter("view") != null) {
    view = request.getParameter("view");
} else if (request.getAttribute("view") != null) {
    view = (String) request.getAttribute("view");
}
//preliminary JSP code

// "Module" and "function" is the same thing (old dms module)
String module = "";
String moduleid = "";
if (request.getParameter("function") != null) {
    module = request.getParameter("function");
    moduleid = request.getParameter("functionid");
} else if (request.getAttribute("function") != null) {
    module = (String) request.getAttribute("function");
    moduleid = (String) request.getAttribute("functionid");
}

if( !"".equalsIgnoreCase(moduleid) && (demographicNo == null || demographicNo.equalsIgnoreCase("null")) ) {
  demographicNo = moduleid;
}

//module can be either demographic or provider from what i can tell

String moduleName = "";
if(module.equals("demographic")) {
  moduleName = EDocUtil.getDemographicName(loggedInInfo, moduleid);
} else if(module.equals("provider")) {
  moduleName = EDocUtil.getProviderName(moduleid);
}


String curUser = LoggedInInfo.getLoggedInInfoFromSession(request).getLoggedInProviderNo();

//sorting
EDocUtil.EDocSort sort = EDocUtil.EDocSort.OBSERVATIONDATE;
String sortRequest = request.getParameter("sort");
if (sortRequest != null) {
    if (sortRequest.equals("description")) sort = EDocUtil.EDocSort.DESCRIPTION;
    else if (sortRequest.equals("type")) sort = EDocUtil.EDocSort.DOCTYPE;
    else if (sortRequest.equals("contenttype")) sort = EDocUtil.EDocSort.CONTENTTYPE;
    else if (sortRequest.equals("creator")) sort = EDocUtil.EDocSort.CREATOR;
    else if (sortRequest.equals("uploaddate")) sort = EDocUtil.EDocSort.DATE;
    else if (sortRequest.equals("observationdate")) sort = EDocUtil.EDocSort.OBSERVATIONDATE;
    else if (sortRequest.equals("reviewer")) sort = EDocUtil.EDocSort.REVIEWER;
}

ArrayList doctypes = EDocUtil.getActiveDocTypes(module);

//Retrieve encounter id for updating encounter navbar if info this page changes anything
String parentAjaxId;
if( request.getParameter("parentAjaxId") != null )
    parentAjaxId = request.getParameter("parentAjaxId");
else if( request.getAttribute("parentAjaxId") != null )
    parentAjaxId = (String)request.getAttribute("parentAjaxId");
else
    parentAjaxId = "";


String updateParent;
if( request.getParameter("updateParent") != null )
    updateParent = request.getParameter("updateParent");
else
    updateParent = "false";

String viewstatus = request.getParameter("viewstatus");
if( viewstatus == null ) {
    viewstatus = "active";
}

UserPropertyDAO pref = (UserPropertyDAO) WebApplicationContextUtils.getWebApplicationContext(pageContext.getServletContext()).getBean("UserPropertyDAO");
UserProperty up = pref.getProp(user_no, UserProperty.EDOC_BROWSER_IN_DOCUMENT_REPORT);
Boolean DocumentBrowserLink=false;

if ( up != null && up.getValue() != null && up.getValue().equals("yes")){
   DocumentBrowserLink = true;
                            }
%>
<html:html locale="true">
<head>

<title><bean:message key="dms.documentReport.title" /></title>

<script src="${ pageContext.request.contextPath }/share/javascript/Oscar.js"></script>


<link href="${ pageContext.request.contextPath }/css/datepicker.css" rel="stylesheet" type="text/css">
<link href="${ pageContext.request.contextPath }/css/bootstrap-responsive.css" rel="stylesheet" type="text/css">
<link href="${ pageContext.request.contextPath }/css/font-awesome.min.css" rel="stylesheet" type="text/css">

    <link href="${ pageContext.request.contextPath }/css/bootstrap.css" rel="stylesheet" type="text/css"> <!-- Bootstrap 2.3.1 -->
    <link href="${ pageContext.request.contextPath }/css/DT_bootstrap.css" rel="stylesheet" type="text/css">
    <link href="${ pageContext.request.contextPath }/library/DataTables-1.10.12/media/css/jquery.dataTables.min.css" rel="stylesheet" >
    <script src="${ pageContext.request.contextPath }/library/jquery/jquery-3.6.4.min.js"></script>

<script src="${ pageContext.request.contextPath }/library/jquery/jquery-ui-1.12.1.min.js"></script>
<!--
<script src="${ pageContext.request.contextPath }/share/javascript/prototype.js"></script>
-->
    <script src="${ pageContext.request.contextPath }/js/global.js"></script>
    <script src="${ pageContext.request.contextPath }/library/DataTables/datatables.min.js"></script> <!-- DataTables 1.13.4 -->
<%
CtlDocClassDao docClassDao = (CtlDocClassDao)SpringUtils.getBean("ctlDocClassDao");
List<String> reportClasses = docClassDao.findUniqueReportClasses();
ArrayList<String> subClasses = new ArrayList<String>();
ArrayList<String> consultA = new ArrayList<String>();
ArrayList<String> consultB = new ArrayList<String>();
for (String reportClass : reportClasses) {
    List<String> subClassList = docClassDao.findSubClassesByReportClass(reportClass);
    if (reportClass.equals("Consultant ReportA")) consultA.addAll(subClassList);
    else if (reportClass.equals("Consultant ReportB")) consultB.addAll(subClassList);
    else subClasses.addAll(subClassList);

    if (!consultA.isEmpty() && !consultB.isEmpty()) {
        for (String partA : consultA) {
            for (String partB : consultB) {
                subClasses.add(partA+" "+partB);
            }
        }
    }
}
%>

<script>
  $( function() {
    var docSubClassList = [
        <% for (int i=0; i<subClasses.size(); i++) { %>
"<%=subClasses.get(i)%>"<%=(i<subClasses.size()-1)?",":""%>
        <% } %>
    ];
    $( "#docSubClass" ).autocomplete({
      source: docSubClassList
    });
  } );
</script>

<script type="text/javascript">


var awnd=null;
function popPage(url) {
  awnd=rs('',url ,400,200,1);
  awnd.focus();
}


function checkDelete(url, docDescription){
// revision Apr 05 2004 - we now allow anyone to delete documents
  if(confirm("<bean:message key="dms.documentReport.msgDelete"/> " + docDescription)) {
    window.location = url;
  }
}

function showhide(hideelement, button) {
    var plus = '<i class="icon-plus"></i>';
    var minus = '<i class="icon-minus"></i>';
    if (document.getElementById) { // DOM3 = IE5, NS6
        if (document.getElementById(hideelement).style.display == 'none') {
              document.getElementById(hideelement).style.display = 'block';
              document.getElementById(button).innerHTML = document.getElementById(button).innerHTML.replace(plus, minus);
        }
        else {
              document.getElementById(hideelement).style.display = 'none';
              document.getElementById(button).innerHTML = document.getElementById(button).innerHTML.replace(minus, plus);;
        }
    }
}


function selectAll(checkboxId,parentEle, className){
   var f = document.getElementById(checkboxId);
   var val = f.checked;
   var chkList = document.getElementsByClassName(className, parentEle);
   for (i =0; i < chkList.length; i++){
      chkList[i].checked = val;
   }
}

function submitForm(actionPath) {

    var form = document.forms[2];
    if(verifyChecks(form)) {
        form.action = actionPath;
        form.submit();
        return true;
    }
    else
        return false;
}

function submitPhrForm(actionPath, windowName) {

    var form = document.forms[2];
    if(verifyChecks(form)) {
        form.onsubmit = phrActionPopup(actionPath, windowName);
        form.target = windowName;
        form.action = actionPath;
        form.submit();
        return true;
    }
    else
        return false;
}

function verifyChecks(t){

   if ( t.docNo == null ){
         alert("No documents selected");
         return false;
   }else{
      var oneChecked = 0;
      if( t.docNo.length ) {
        for ( i=0; i < t.docNo.length; i++){
            if(t.docNo[i].checked){
                ++oneChecked;
                break;
            }
        }
      }
      else
        oneChecked = t.docNo.checked ? 1 : 0;

      if ( oneChecked == 0 ){
         alert("No documents selected");
         return false;
      }
   }
   return true;
}

function popup1(height, width, url, windowName){
  var page = url;
  windowprops = "height="+height+",width="+width+",location=no,scrollbars=yes,menubars=no,toolbars=no,resizable=yes,screenX=0,screenY=0,top=0,left=0";
  var popup=window.open(url, windowName, windowprops);
  if (popup != null){
    if (popup.opener == null){
      popup.opener = self;
    }
  }
  popup.focus()

}


  function setup() {
    var update = "<%=updateParent%>";
    var parentId = "<%=parentAjaxId%>";
    var Url = window.opener.URLs;

    if( update == "true" && !window.opener.closed )
        window.opener.popLeftColumn(Url[parentId], parentId, parentId);
  }
</script>


</head>
<body>


		<table class="TopStatusBar" style="width:100%">
			<tr>
				<td><h4><i class="icon-book" style="margin-left:10px;"></i>&nbsp;<bean:message key="dms.documentReport.msgDocuments"/> &nbsp;
				<% if(module.equals("demographic")) { %>
					<oscar:nameage demographicNo="<%=moduleid%>"/> &nbsp; <oscar:phrverification demographicNo="<%=moduleid%>"><bean:message key="phr.verification.link"/></oscar:phrverification>
				<%} %>
				</h4></td>
				<td>&nbsp;</td>
				<td style="text-align: right;">


<div class="row-fluid hidden-print" style="text-align:right">
<i class=" icon-question-sign"></i>
<a href="<%=help_url%>patient-document-management/" target="_blank"><bean:message key="app.top1"/></a>

<i class=" icon-info-sign" style="margin-left:10px;"></i> <a href="javascript:void(0)"  onClick="window.open('<%=request.getContextPath()%>/oscarEncounter/About.jsp','About OSCAR','scrollbars=1,resizable=1,width=800,height=600,left=0,top=0')" ><bean:message key="global.about" /></a>
</div><!-- hidden print -->


				</td>
			</tr>
		</table>
			<jsp:include page="addDocument.jsp">
				<jsp:param name="appointmentNo" value="<%=appointmentNo%>"/>
			</jsp:include>


      <html:form action="/dms/combinePDFs">
      <input type="hidden" name="curUser" value="<%=curUser%>">
      <input type="hidden" name="demoId" value="<%=moduleid%>">
      <div class="documentLists"><%-- STUFF TO DISPLAY --%> <%
                ArrayList categories = new ArrayList();
                ArrayList categoryKeys = new ArrayList();
                ArrayList privatedocs = new ArrayList();

                MiscUtils.getLogger().debug("module="+module+", moduleid="+moduleid+", view="+view+", EDocUtil.PRIVATE="+EDocUtil.PRIVATE+", sort="+sort+", viewstatus="+viewstatus);
                privatedocs = EDocUtil.listDocs(loggedInInfo, module, moduleid, view, EDocUtil.PRIVATE, sort, viewstatus);
                MiscUtils.getLogger().debug("privatedocs:"+privatedocs.size());

                categories.add(privatedocs);
                categoryKeys.add(moduleName + "'s Private Documents");
                if (module.equals("provider")) {
                    ArrayList publicdocs = new ArrayList();
                    publicdocs = EDocUtil.listDocs(loggedInInfo, module, moduleid, view, EDocUtil.PUBLIC, sort, viewstatus);
                    categories.add(publicdocs);
                    categoryKeys.add("Public Documents");
                }

                //--- get remote documents ---
                if (loggedInInfo.getCurrentFacility().isIntegratorEnabled())
                {
                  List<EDoc> remoteDocuments=EDocUtil.getRemoteDocuments(loggedInInfo, Integer.parseInt(moduleid));
                  categories.add(remoteDocuments);
                    categoryKeys.add("Remote Documents");
                }

                for (int i=0; i<categories.size();i++) {
                    String currentkey = (String) categoryKeys.get(i);
                    ArrayList category = (ArrayList) categories.get(i);
             %>
    <script>
	    jQuery(document).ready( function () {
	        jQuery('#tblDocs<%=i%>').DataTable({
            "lengthMenu": [ [15, 30, 90, -1], [15, 30, 90, "<bean:message key="oscarEncounter.LeftNavBar.AllLabs"/>"] ],
            "order": [],
            "language": {
                        "url": "<%=request.getContextPath() %>/library/DataTables/i18n/<bean:message key="global.i18nLanguagecode"/>.json"
                    }
            });
	    });
    </script>
      <div class="doclist">
      <div class="headerline" style="background-color: silver;">
      <div class="docHeading" style="padding:8px;">
      <% if( i == 0 ) {
                         %> <span class="tabs" style="float: right">
      <bean:message key="dms.documentReport.msgViewStatus"/> <select class="input-medium" id="viewstatus" name="viewstatus"
        style="margin-bottom: -4px;"
        onchange="window.location.href='?function=<%=module%>&functionid=<%=moduleid%>&view=<%=view%>&viewstatus='+this.options[this.selectedIndex].value;">
        <option value="all"
          <%=viewstatus.equalsIgnoreCase("all") ? "selected":""%>><bean:message key="dms.documentReport.msgAll"/></option>
        <option value="deleted"
          <%=viewstatus.equalsIgnoreCase("deleted") ? "selected":""%>><bean:message key="dms.documentReport.msgDeleted"/></option>
        <option value="active"
          <%=viewstatus.equalsIgnoreCase("active") ? "selected":""%>><bean:message key="dms.documentReport.msgPublished"/></option>
      </select> </span> <%
                          }
                          %> <a id="plusminus<%=i%>"
        href="javascript: showhide('documentsInnerDiv<%=i%>', 'plusminus<%=i%>');">
      <i class="icon-minus"></i>&nbsp;</a><%= currentkey%>
      <!-- Enter the deleted code here -->

      &nbsp;&nbsp;
      <span class="tabs"> <bean:message key="dms.documentReport.msgView"/>:
      <select id="viewdoctype<%=i%>" name="view" class="input-medium"
        style="margin-bottom: -4px;"
        onchange="window.location.href='?function=<%=module%>&functionid=<%=moduleid%>&view='+this.options[this.selectedIndex].value;">
          <option value="">All</option>
        <%
                 for (int i3=0; i3<doctypes.size(); i3++) {
                           String doctype = (String) doctypes.get(i3); %>
        <option value="<%= doctype%>"
        <%=(view.equalsIgnoreCase(doctype))? "selected":""%>><%= doctype%></option>
        <%}%>

      </select>
        <%if(DocumentBrowserLink) {%>&nbsp;&nbsp;<a class="btn" href="${ pageContext.request.contextPath }/dms/documentBrowser.jsp?function=<%=module%>&functionid=<%=moduleid%>&categorykey=<%=Encode.forUri(currentkey)%>"><bean:message key="dms.documentReport.msgBrowser"/></a><%}%>
      </span>
      </div>
      </div>
      <div id="documentsInnerDiv<%=i%>" >
      <table id="tblDocs<%=i%>" class="compact display">
        <thead>
        <tr>
          <th>
            <input class="tightCheckbox" type="checkbox" id="pdfCheck<%=i%>" onclick="selectAll('pdfCheck<%=i%>','privateDocsDiv', 'tightCheckbox<%=i%>');" />
          </th>
          <th style="width:30%"><bean:message
            key="dms.documentReport.msgDocDesc" /></th>
          <th style="width:8%">
                <bean:message key="dms.documentReport.msgContent"/></th>
          <th style="width:8%">
                <bean:message key="dms.documentReport.msgType"/></th>
          <th style="width:12%"><bean:message
            key="dms.documentReport.msgCreator" /></th>
          <th style="width:12%">
            <bean:message key="dms.documentReport.msgResponsible"/></th>
          <th style="width:80px;">
            <bean:message key="dms.documentReport.msgDate"/></th>
          <th style="width:12%">
            <bean:message key="dms.documentReport.msgReviewer"/></th>
          <th style="width:50px;">&nbsp;</th>
        </tr>
        </thead>
        <%
                for (int i2=0; i2<category.size(); i2++) {
                    EDoc curdoc = (EDoc) category.get(i2);
                    //content type (take everything following '/')
                    int slash = 0;
                    String contentType = "";
                    if( curdoc.getContentType() == null ) {
                    contentType = "N/A";
                    }else if ((slash = curdoc.getContentType().indexOf('/')) != -1) {
                        contentType = curdoc.getContentType().substring(slash+1);
                    } else {
            contentType = curdoc.getContentType();
            }
                    String dStatus = "";
                    if ((curdoc.getStatus() + "").compareTo("H") == 0)
                        dStatus="html";
                    else
                        dStatus="active";
        String reviewerName = curdoc.getReviewerName();
        if (reviewerName.equals("")) reviewerName = "- - -";
            %>
        <tr>
          <td>
          <% if (curdoc.isPDF()){%> <input class="tightCheckbox<%=i%>"
            type="checkbox" name="docNo" id="docNo<%=curdoc.getDocId()%>"
            value="<%=curdoc.getDocId()%>" style="margin: 0px; padding: 0px;" />
          <%}else{%> &nbsp; <%}%>
          </td>
          <td>
          <%

                              String url = "ManageDocument.do?method=display&doc_no="+curdoc.getDocId()+"&providerNo="+user_no+(curdoc.getRemoteFacilityId()!=null?"&remoteFacilityId="+curdoc.getRemoteFacilityId():"");
                              //String url = "documentGetFile.jsp?document=" + StringEscapeUtils.escapeJavaScript(curdoc.getFileName()) + "&type=" + dStatus + "&doc_no=" + curdoc.getDocId();

          %>  <a <%=curdoc.getStatus() == 'D' ? "style='text-decoration:line-through'" : ""%>
            href="javascript:void(0);" onclick="popupFocusPage(500,700,'<%=url%>','demographic_document');"> <%=Encode.forHtml(curdoc.getDescription())%></a></td>
          <td><div style="width: 70px; overflow:hidden; text-overflow: ellipsis;" title="<%=contentType%>"><%=contentType%></div></td>
          <td><%=curdoc.getType()==null ? "N/A" : Encode.forHtml(curdoc.getType())%></td>
          <td><%=Encode.forHtml(curdoc.getCreatorName())%></td>
          <td><%=Encode.forHtml(curdoc.getResponsibleName())%></td>
          <td><%=Encode.forHtml(curdoc.getObservationDate())%></td>
          <td><%=Encode.forHtml(reviewerName)%></td>
         <td style="width:50px; vertical-align:top">
<div class="btn-group">
            <%
              if (curdoc.getRemoteFacilityId()==null)
              {
                if( curdoc.getCreatorId().equalsIgnoreCase(user_no)) {
                  if( curdoc.getStatus() == 'D' ) { %>
                    <a href="documentReport.jsp?undelDocumentNo=<%=curdoc.getDocId()%>&function=<%=module%>&functionid=<%=moduleid%>&viewstatus=<%=viewstatus%>" class="btn btn-link"
                  title="<bean:message key="dms.documentReport.btnUnDelete"/>"><i class="icon-retweet"></i></a>
                  <%
                  } else {
                  %>
                    <a href="javascript: checkDelete('documentReport.jsp?delDocumentNo=<%=curdoc.getDocId()%>&function=<%=module%>&functionid=<%=moduleid%>&viewstatus=<%=viewstatus%>','<%=StringEscapeUtils.escapeJavaScript(curdoc.getDescription())%>')" class="btn btn-link" title="Delete"><i class="icon-trash"></i></a>
                  <%
                  }
              } else {
              %>
                <security:oscarSec roleName="<%=roleName$%>" objectName="_admin,_admin.edocdelete" rights="r">
                  <%
                  if( curdoc.getStatus() == 'D' ) {%>
                    <a href="documentReport.jsp?undelDocumentNo=<%=curdoc.getDocId()%>&function=<%=module%>&functionid=<%=moduleid%>&viewstatus=<%=viewstatus%>"
                  title="<bean:message key="dms.documentReport.btnUnDelete"/>"><i class="icon-retweet"></i></a>
                  <%
                  } else {
                  %>
                    <a href="javascript: checkDelete('documentReport.jsp?delDocumentNo=<%=curdoc.getDocId()%>&function=<%=module%>&functionid=<%=moduleid%>&viewstatus=<%=viewstatus%>','<%=StringEscapeUtils.escapeJavaScript(curdoc.getDescription())%>')" class="btn btn-link" title="Delete"><i class="icon-trash"></i></a>
                  <%
                  }
                  %>
                </security:oscarSec>
                <%
                }

                if( curdoc.getStatus() != 'D' ) {
                  if (curdoc.getStatus() == 'H') { %>
                  <a href="#" onclick="popup(450, 600, 'addedithtmldocument.jsp?editDocumentNo=<%=curdoc.getDocId()%>&function=<%=module%>&functionid=<%=moduleid%>', 'EditDoc')" title="<bean:message key="dms.documentReport.btnEdit"/>" class="btn btn-link">
                  <%
                  } else {
                  %>
                  <a href="#" onclick="popup(350, 500, 'editDocument.jsp?editDocumentNo=<%=curdoc.getDocId()%>&function=<%=module%>&functionid=<%=moduleid%>', 'EditDoc')" class="btn btn-link" title="<bean:message key="dms.documentReport.btnEdit"/>" class="btn btn-link">
                  <%
                  }
                  %>
            <i class="icon-pencil"></i></a>
                  <%
                }

                if(module.equals("demographic")){%>
                  <a href="#" title="Annotation" onclick="window.open('${ pageContext.request.contextPath }/annotation/annotation.jsp?display=<%=annotation_display%>&table_id=<%=curdoc.getDocId()%>&demo=<%=moduleid%>','anwin','width=400,height=500');"  class="btn btn-link">
                    <i class="icon-quote-right"></i></a>
                           <%
                           }

                 if(!(moduleid.equals(session.getAttribute("user"))&& module.equals("demographic"))) {

                                String tickler_url;
                              if( org.oscarehr.common.IsPropertiesOn.isTicklerPlusEnable() ) {
                                tickler_url = request.getContextPath()+"/Tickler.do?method=edit&tickler.demographic_webName="+moduleName+"&tickler.demographic_no="+moduleid;
                              } else {
                                tickler_url = request.getContextPath()+"/tickler/ForwardDemographicTickler.do?docType=DOC&docId="+curdoc.getDocId()+"&demographic_no="+moduleid;
                              }

                              %>

                              &nbsp;<a href="javascript:void(0);" title="Tickler" class="btn btn-link" onclick="popup(450,600,'<%=tickler_url%>','tickler')"><i class="icon-star"></i></a>

                           <%
                           }
               }
              else
              {
                %>
                Remote Document
                <%
              }
                         %>
</div><!-- button grouping -->
                     </td>

        </tr>

        <%}
            if (category.size() == 0) {%>

        <%}%>
      </table>

      </div>
      </div>
      <%}%>
      </div>
      <div><input type="button" name="Button" class="btn btn-primary"
        value="<bean:message key="dms.documentReport.btnDoneClose"/>"
        onclick=self.close();> <input type="button" name="print" class="btn"
        value='<bean:message key="dms.documentReport.btnPrintThisPageList"/>'
        onClick="window.print()"> <input type="button"
        value="<bean:message key="dms.documentReport.btnCombinePDF"/>" class="btn"
        onclick="return submitForm('<rewrite:reWrite jspPage="combinePDFs.do"/>');" />
        <%
                    if( module.equals("demographic") ) {

                      if (MyOscarUtils.isMyOscarEnabled(curUser))
                      {
                  String onclickString="alert('"+LocaleUtils.getMessage(request, "LoginToPHRFirst")+"')";

                  MyOscarLoggedInInfo myOscarLoggedInInfo=MyOscarLoggedInInfo.getLoggedInInfo(session);
                  if (myOscarLoggedInInfo!=null && myOscarLoggedInInfo.isLoggedIn()) onclickString="return submitPhrForm('SendDocToPhr.do', 'sendDocToPhr');";

                  %>
                  <input type="button" <%=MyOscarUtils.getDisabledStringForMyOscarSendButton(myOscarLoggedInInfo, Integer.parseInt(demographicNo))%> value="<%=LocaleUtils.getMessage(request, "SendToPHR")%>" onclick="<%=onclickString%>" />
              <%
                      }

                      if (isSharingCenterEnabled) {
                      %>
                        <span style="float: right;">
                          <select name="affinityDomain"
                            style="margin-bottom: -4px;" class="input-medium">

                            <% for(AffinityDomainDataObject domain : affinityDomains) { %>
                              <option value="<%=domain.getId()%>"><%=domain.getName()%></option>
                            <% } %>

                          </select>
                          <input type="button" id="SendToAffinityDomain" name="SendToAffinityDomain" value="Share" onclick="return submitForm('<rewrite:reWrite jspPage="${ pageContext.request.contextPath }/sharingcenter/documents/shareDocumentsAction.jsp?type=edocs"/>');">
                        </span>
                      <%
                      }
                    }
              %>
      </div>
    </html:form>



</body>
</html:html>