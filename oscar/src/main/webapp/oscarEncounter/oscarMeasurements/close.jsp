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

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
<%@ page import="oscar.OscarProperties"%>
<head>
<script type="text/javascript" src="<%= request.getContextPath() %>/js/global.js"></script>
<title>close</title>
<script src="<%=request.getContextPath()%>/JavaScriptServlet" type="text/javascript"></script>
<script type="text/javascript">
function closeWin() {
    <%if (request.getAttribute("textOnEncounter")!=null && !OscarProperties.getInstance().isPropertyActive("measurements_create_new_note")) {%>
    if(opener.opener!=null || opener!=null){
        if(opener.opener.document.forms["caseManagementEntryForm"] != undefined) {
            //from Templateflowsheet
            opener.opener.pasteToEncounterNote('<%=request.getAttribute("textOnEncounter")%>');
            self.close();
        }
        else if(opener.document.forms["caseManagementEntryForm"] != undefined) {
            opener.pasteToEncounterNote('<%=request.getAttribute("textOnEncounter")%>');
            self.close();
        }
    }
    <% }
    if (request.getAttribute("refreshOpenerOnAdd") != null && (Boolean) request.getAttribute("refreshOpenerOnAdd")) { %>
        window.opener.location.reload();
    <% } %>
    if (window.opener.autoSave) {
        window.opener.autoSave(true);
    }
   self.close();
}
</script>

</head>
<body onload="closeWin();">

</body>
</html>