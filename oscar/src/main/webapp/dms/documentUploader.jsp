<%--

    Copyright (c) 2007 Peter Hutten-Czapski based on OSCAR general requirements
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
<%@page contentType="text/html"%>

<%@page import="org.oscarehr.common.dao.QueueDao" %>
<%@page import="org.oscarehr.common.dao.UserPropertyDAO"%>
<%@page import="org.oscarehr.common.model.Provider" %>
<%@page import="org.oscarehr.common.model.UserProperty"%>
<%@page import="org.oscarehr.PMmodule.dao.ProviderDao" %>
<%@page import="org.oscarehr.util.SpringUtils" %>

<%@page import="oscar.dms.data.*" %>
<%@page import="oscar.oscarLab.ca.on.CommonLabResultData" %>
<%@page import="oscar.oscarMDS.data.ProviderData" %>
<%@page import="oscar.OscarProperties"%>

<%@page import="java.util.*" %>
<%@page import="org.owasp.encoder.Encode" %>

<%@ taglib uri="/WEB-INF/struts-bean.tld" prefix="bean"%>
<%@ taglib uri="/WEB-INF/security.tld" prefix="security"%>
<%
    String roleName$ = (String)session.getAttribute("userrole") + "," + (String) session.getAttribute("user");
    boolean authed=true;
%>
<security:oscarSec roleName="<%=roleName$%>" objectName="_edoc" rights="w" reverse="<%=true%>">
	<%authed=false; %>
	<%response.sendRedirect("../securityError.jsp?type=_edoc");%>
</security:oscarSec>
<%
	if(!authed) {
		return;
	}
%>

<%

ProviderDao providerDao = (ProviderDao) SpringUtils.getBean("providerDao");
ArrayList<Provider> providers = new ArrayList<Provider>(providerDao.getActiveProviders());
String provider = CommonLabResultData.NOT_ASSIGNED_PROVIDER_NO;

QueueDao queueDao = (QueueDao) SpringUtils.getBean("queueDao");
HashMap<Integer,String> queues = queueDao.getHashMapOfQueues();
String queueIdStr = (String) request.getSession().getAttribute("preferredQueue");
int queueId = 1;
if (queueIdStr != null) {
    queueIdStr = queueIdStr.trim();
    queueId = Integer.parseInt(queueIdStr);
}

    String user_no = (String) session.getAttribute("user");
    UserPropertyDAO userPropertyDAO = (UserPropertyDAO)SpringUtils.getBean("UserPropertyDAO");

    UserProperty uProp = userPropertyDAO.getProp(user_no, UserProperty.UPLOAD_DOCUMENT_DESTINATION);
    String destination=UserProperty.PENDINGDOCS;
    if( uProp != null && uProp.getValue().equals(UserProperty.INCOMINGDOCS)) {
        destination=UserProperty.INCOMINGDOCS;
    }

    uProp = userPropertyDAO.getProp(user_no, UserProperty.UPLOAD_INCOMING_DOCUMENT_FOLDER);
    String destFolder="Mail";
    if( uProp != null) {
        destFolder=uProp.getValue();
    }

String context = request.getContextPath();
String resourcePath = context + "/share/documentUploader/";


%>
<!DOCTYPE HTML>
<html lang="en" class="no-js">
<head>
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<title><bean:message key="inboxmanager.document.title" /></title>
	<link rel="stylesheet" href="${pageContext.request.contextPath}/share/css/OscarStandardLayout.css" />

     <!-- tested with Bootstrap 2.3.1 and Bootstrap 3.0.0 -->
    <link href="${pageContext.request.contextPath}/library/bootstrap/3.0.0/css/bootstrap.css" rel="stylesheet" type="text/css">

    <!-- styles to alter add files button and adjust bootstrap 3 progress bar -->
	<link rel="stylesheet" href="${pageContext.request.contextPath}/share/documentUploader/style.css">

    <!-- tested with jQuery 1.12.3 and jQuery 3.6.4 -->
    <script src="<%=request.getContextPath() %>/library/jquery/jquery-3.6.4.min.js"></script>

    <!-- jQuery ui OR just the jQuery ui widget factory to match the jQuery above -->
    <script src="${pageContext.request.contextPath}/js/jquery.ui.widget.js"></script> <!-- 1.12.1 -->

    <!-- The Templates plugin is included to render the upload/download listings -->
    <script src="${pageContext.request.contextPath}/share/documentUploader/jquery.tmpl.min.js"></script>

    <!-- The Iframe Transport only needed to provide support for 10 year old browsers for XHR file uploads via file input selection-->
    <script src="${pageContext.request.contextPath}/share/documentUploader/jquery.iframe-transport.js"></script>

    <!-- The basic File Upload plugin -->
    <script src="${pageContext.request.contextPath}/share/documentUploader/jquery.fileupload.js"></script>

    <!-- The File Upload processing plugin -->
    <script src="${pageContext.request.contextPath}/share/documentUploader/jquery.fileupload-process.js"></script>

    <!-- The File Upload validation plugin -->
    <script src="${pageContext.request.contextPath}/share/documentUploader/jquery.fileupload-validate.js"></script>

    <!-- The File Upload user interface plugin modified from stock for OSCAR -->
    <script src="${pageContext.request.contextPath}/share/documentUploader/jquery.fileupload-ui.js"></script>

	<script>
	function setProvider(select){
		document.getElementById("provider").value = select.options[select.selectedIndex].value;
	}

	function setQueue(select){
		document.getElementById("queue").value = select.options[select.selectedIndex].value;
	}

    function setDestination(select){
        var destination=select.options[select.selectedIndex].value;
		document.getElementById("destination").value = destination;
        setDropList();
        jQuery.ajax({url:'${pageContext.request.contextPath}/dms/documentUpload.do?method=setUploadDestination&destination='+destination,async:false, success:function(data) {}});
	}

    function setDestFolder(select){
        var destFolder=select.options[select.selectedIndex].value;
		document.getElementById("destFolder").value = destFolder;
        jQuery.ajax({url:'${pageContext.request.contextPath}/dms/documentUpload.do?method=setUploadIncomingDocumentFolder&destFolder='+destFolder,async:false, success:function(data) {}});
	}

    function setDropList(){
        if(document.getElementById('destinationDrop').options[document.getElementById('destinationDrop').selectedIndex].value=="incomingDocs"){
            document.getElementById('providerDropDiv').style.display = 'none';
            document.getElementById('destFolderDiv').style.display = 'block';
        } else {
            document.getElementById('providerDropDiv').style.display = 'block';
            document.getElementById('destFolderDiv').style.display = 'none';
        }
     }
	</script>


    <!-- Generic page styles -->
    <style>
      #navigation {
        margin: 10px 0;
      }
      @media (max-width: 767px) {
        #title,
        #description {
          display: none;
        }
      }
    </style>

    <!-- CSS to style the file input field as button -->
    <style>
    .fileinput-button {
      position: relative;
      overflow: hidden;
      display: inline-block;
    }
    .fileinput-button input {
      position: absolute;
      top: 0;
      right: 0;
      margin: 0;
      height: 100%;
      opacity: 0;
      filter: alpha(opacity=0);
      font-size: 200px !important;
      direction: ltr;
      cursor: pointer;
    }

    #drop-area {
      border: 2px dashed #ccc;
      border-radius: 20px;
      width: 100%;
      font-family: sans-serif;
      margin: 20px auto;
      padding: 10px;
    }

    .progress {
        margin-bottom:10px;
    }
    </style>


</head>
<body onload="setDropList();">
    <div class="container">
      <div class="panel panel-default">
        <div class="panel-heading">
          <h3 class="panel-title"><bean:message key="dms.addDocument.msgManageUploadDocument" /></h3>
        </div>
        <div class="panel-body">
            <ul>
                <li><bean:message key="inboxmanager.document.title" /></li>
                <li><bean:message key="dms.documentUpload.onlyPdf" /></li>
            </ul>
        </div>
       </div>
      <!-- The file upload form used as target for the file upload widget.  Enabled drag and drop anywhere here -->
      <form
        id="fileupload"
        action="<%=context%>/dms/documentUpload.do?method=executeUpload"
        method="POST"
        enctype="multipart/form-data"
      >
            <input type="hidden" id="destination" name="destination" value="<%=destination%>"/>
            <input type="hidden" id="destFolder" name="destFolder" value="<%=destFolder%>"/>
			<input type="hidden" id="provider" name="provider" value="<%=provider%>" />
		    <input type="hidden" id="queue" name="queue" value="<%=queueId%>"/>

             <div class="form-group">
                <label for="destinationDrop"><bean:message key="dms.documentUploader.destination" />:</label>
                    <select onchange="javascript:setDestination(this);"  id="destinationDrop"  name="destinationDrop" class="form-control input-block-level">
                        <option value="pendingDocs" <%=( destination.equals("pendingDocs") ? " selected" : "")%> ><bean:message key="inboxmanager.document.pendingDocs" /></option>
                        <option value="incomingDocs" <%=( destination.equals("incomingDocs") ? " selected" : "")%> ><bean:message key="inboxmanager.document.incomingDocs" /></option>
                    </select>
             </div>
             <div class="form-group" id="providerDropDiv">
                <label for="providerDrop" class="fields">Send to Provider:</label>
				<select onchange="javascript:setProvider(this);" id="providerDrop" name="providerDrop" class="form-control input-block-level">
					<option value="0" <%=("0".equals(provider) ? " selected" : "")%>>None</option>
					<%
					for (int i = 0; i < providers.size(); i++) {
	                	Provider h = providers.get(i);
	                %>
					<option value="<%= h.getProviderNo()%>" <%= (h.getProviderNo().equals(provider) ? " selected" : "")%>><%= Encode.forHtml(h.getLastName())%> <%= Encode.forHtml(h.getFirstName())%></option>
					<%
					}
					%>
				</select>
             </div>
             <div class="form-group">
				<label for="queueDrop" class="fields">Queue:</label>
				<select onchange="javascript:setQueue(this);" id="queueDrop" name="queueDrop" class="form-control input-block-level">
					<%
					for (Map.Entry<Integer,String> entry : queues.entrySet()) {
					    int key = entry.getKey();
					    String value = entry.getValue();

	                %>
					<option value="<%=key%>" <%=( (key == queueId) ? " selected" : "")%>><%= Encode.forHtml(value)%></option>
					<%
					}
					%>
				</select>
             </div>
             <div class="form-group" id="destFolderDiv">
                <label for="destinationDrop" class="fields"><bean:message key="dms.documentUploader.folder" />:</label>
                    <select onchange="javascript:setDestFolder(this);"  id="destFolderDrop"  name="destFolderDrop" class="form-control input-block-level">
                        <option value="Fax" <%=( destFolder.equals("Fax") ? " selected" : "")%> ><bean:message key="dms.incomingDocs.fax" /></option>
                        <option value="Mail" <%=( destFolder.equals("Mail") ? " selected" : "")%> ><bean:message key="dms.incomingDocs.mail" /></option>
                        <option value="File" <%=( destFolder.equals("File") ? " selected" : "")%> ><bean:message key="dms.incomingDocs.file" /></option>
                        <option value="Refile" <%=( destFolder.equals("Refile") ? " selected" : "")%> ><bean:message key="dms.incomingDocs.refile" /></option>
                    </select>
              </div>

        <!-- The fileupload-buttonbar contains buttons to add/delete files and start/cancel the upload -->
        <div class="row fileupload-buttonbar">
          <div class="col-lg-7">
            <!-- The fileinput-button span is used to style the file input field as button -->
            <span class="btn fileinput-button btn-default">
              <i class="glyphicon glyphicon-plus"></i>
              <span><bean:message key="global.btnAdd" />...</span>
              <input type="file" name="filedata" multiple />
            </span>
            <button type="submit" class="btn btn-primary start">
              <i class="glyphicon glyphicon-upload"></i>
              <span><bean:message key="dms.zadddocument.btnUpload" /></span>
            </button>
            <button type="reset" class="btn cancel">
              <i class="glyphicon glyphicon-ban-circle"></i>
              <span><bean:message key="global.reset" /></span>
            </button>
            <p>
            <!-- The global file processing state -->
            <span class="fileupload-process"></span>
          </div>
          <!-- The global progress state -->
          <div class="col-lg-5 fileupload-progress fade">
            <!-- The global progress bar -->
            <div
              class="progress progress-striped active"
              role="progressbar"
              aria-valuemin="0"
              aria-valuemax="100"
            >
              <div
                class="progress-bar progress-bar-success"
                style="width: 0%;"
              ></div>
            </div>
            <p>
            <!-- The extended global progress state -->
            <div class="progress-extended">&nbsp;</div>
          </div>
        </div>
        <div id="drop-area" > <span style="font-size:40px; color:lightblue;"><i class="glyphicon glyphicon-cloud-upload"></i></span>
        <!-- The table listing the files available for upload/download -->
            <table role="presentation" class="table table-striped table-compact">
              <tbody id="tbodyid" class="files"></tbody>
            </table>
        </div>
            <ul id="msg" class="alert alert-danger" style="display:none;"></ul>
            <ul id="msgU" class="alert alert-success" style="display:none;"></ul>
      </form>
</div> <!-- end container-->

    <!-- The template to display files available for upload -->
    <script id="template-upload" type="text/x-tmpl">
      {% for (var i=0, file; file=o.files[i]; i++) { %}
          <tr class="template-upload fade">
              <td>
                  <span class="preview"></span>
              </td>
              <td>
                  <p class="name">{%=file.name%}</p>
                  <strong class="error text-danger"></strong>
              </td>
              <td>
                  <p class="size"><bean:message key="eform.uploadimages.processing" />...</p>
                  <div class="progress progress-striped active" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="progress-bar progress-bar-success" style="width:0%;"></div></div>
              </td>
              <td>
                  {% if (!o.options.autoUpload && o.options.edit ) { %}
                    <button class="btn btn-success edit btn-small btn-sm" data-index="{%=i%}" disabled>
                        <i class="glyphicon glyphicon-edit"></i>
                        <span><bean:message key="global.update" /></span>
                    </button>
                  {% } %}
                  {% if (!i && !o.options.autoUpload) { %}
                      <button class="btn btn-primary start btn-small btn-sm" disabled>
                          <i class="glyphicon glyphicon-upload"></i>
                          <span><bean:message key="dms.zadddocument.btnUpload" /></span>
                      </button>
                  {% } %}
                  {% if (!i) { %}
                      <button class="btn cancel btn-small btn-sm">
                          <i class="glyphicon glyphicon-ban-circle"></i>
                          <span><bean:message key="global.btnCancel" /></span>
                      </button>
                  {% } %}
              </td>
          </tr>
      {% } %}
    </script>
    <!-- The template to display files available for download.  !IMPORTANT the template needs to exist even if we are not using it -->
    <script id="template-download" type="text/x-tmpl">
      {% for (var i=0, file; file=o.files[i]; i++) { %}
          <tr class="template-download fade{%=file.thumbnailUrl?' image':''%}">
              <td>
                  <span class="preview">
                      {% if (file.thumbnailUrl) { %}
                          <a href="{%=file.url%}" title="{%=file.name%}" download="{%=file.name%}" data-gallery><img src="{%=file.thumbnailUrl%}"></a>
                      {% } %}
                  </span>
              </td>
              <td>
                  <p class="name">
                      {% if (file.url) { %}
                          <a href="{%=file.url%}" title="{%=file.name%}" download="{%=file.name%}" {%=file.thumbnailUrl?'data-gallery':''%}>{%=file.name%}</a>
                      {% } else { %}
                          <span>{%=file.name%}</span>
                      {% } %}
                  </p>
                  {% if (file.error) { %}
                      <div><span class="label label-danger">Error</span> {%=file.error%}</div>
                  {% } %}
              </td>
              <td>
                  <span class="size">{%=o.formatFileSize(file.size)%}</span>
              </td>
              <td>
                  {% if (file.deleteUrl) { %}
                      <button class="btn btn-danger delete" data-type="{%=file.deleteType%}" data-url="{%=file.deleteUrl%}"{% if (file.deleteWithCredentials) { %} data-xhr-fields='{"withCredentials":true}'{% } %}>
                          <i class="glyphicon glyphicon-trash"></i>
                          <span>Delete</span>
                      </button>
                      <input type="checkbox" name="delete" value="1" class="toggle">
                  {% } else { %}
                      <!--<button class="btn btn-warning cancel">
                          <i class="glyphicon glyphicon-ban-circle"></i>
                          <span>Cancel</span>
                      </button> -->
                  {% } %}
              </td>
          </tr>
      {% } %}
    </script>
   <script>
    // Initialize the plugin
    jQuery(function () {
        'use strict';
        jQuery('#fileupload').fileupload({
        	sequentialUploads: true
        });
        $('#fileupload').fileupload('option', {
          acceptFileTypes: /(\.|\/)(pdf)$/i
        });
    // Load existing files:
        $('#fileupload').addClass('fileupload-processing');
        $.ajax({
          url: $('#fileupload').fileupload('option', 'url'),
          dataType: 'json',
          context: $('#fileupload')[0]
        })
          .always(function () {
            $(this).removeClass('fileupload-processing');
          })
          .done(function (result) {
            $(this)
              .fileupload('option', 'done')
              // eslint-disable-next-line new-cap
              .call(this, $.Event('done'), { result: result });
          });
    });

    // display errors and clear used tr
    jQuery('#fileupload')
        .on('fileuploadalways', function (e, data) {
           if(data.result){
                if(data.result[0].error){
                    data.files.error = true;
                    $('#msg').show();
                    let li = document.createElement('li');
                    li.innerHTML = data.result[0].error;
                    $('#msg').append(li);
                } else {
                    if (data.textStatus == 'error') {
                        let error = "Server error";
                        let li = document.createElement('li');
                        li.innerHTML = error;
                        $('#msg').append(li);
                        $('#msg').show();
                    } else {
                        let li = document.createElement('li');
                        li.innerHTML = data.result[0].name;
                        $('#msgU').append(li);
                        $('#msgU').show();
                        console.log(data.textStatus);
                    }
                }
            }
            $("tr:first-child").remove();
            })
        .on('fileuploadadd', function (e, data) {
            $('#msg').hide();
            $('#msgU').hide();
            });

        jQuery('.alert').on('click', function () {
            $(this).hide();
        });
    </script>
</body>
</html>