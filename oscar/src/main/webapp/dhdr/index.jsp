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
<%@page import="org.oscarehr.integration.OneIdGatewayData,org.oscarehr.util.LoggedInInfo,java.net.URLEncoder"%>
<%@page import="org.oscarehr.integration.OneIDTokenUtils,org.oscarehr.integration.TokenExpiredException"%>
<%@page import="org.oscarehr.util.SessionConstants,org.oscarehr.util.LoggedInUserFilter"%>
<%@ taglib uri="/WEB-INF/security.tld" prefix="security"%>
<%@ taglib uri="/WEB-INF/struts-bean.tld" prefix="bean"%><%
    String roleName$ = (String)session.getAttribute("userrole") + "," + (String) session.getAttribute("user");
	boolean authed=true;
%><security:oscarSec roleName="<%=roleName$%>" objectName="_rx" rights="r" reverse="<%=true%>">
	<%authed=false; %>
	<%response.sendRedirect("../securityError.jsp?type=_admin&type=_admin.misc");%>
</security:oscarSec><%
	if(!authed) {
		return;
	}
LoggedInInfo loggedInInfo = LoggedInInfo.getLoggedInInfoFromSession(request);
OneIdGatewayData oneIdGatewayData= loggedInInfo.getOneIdGatewayData();
try  { 
	OneIDTokenUtils.verifyAccessTokenIsValid(loggedInInfo,oneIdGatewayData);
	
	
	
	////user/Immunization.read user/Immunization.write user/Patient.read
	boolean hasNeededScope = oneIdGatewayData.hasScope(oneIdGatewayData.fullScope);//"openid", "user/MedicationDispense.read", "toolbar", "user/Context.read", "user/Context.write",  "user/Consent.write");
	//http://ehealthontario.ca/StructureDefinition/ca-on-dhir-profile-Immunization http://ehealthontario.ca/StructureDefinition/ca-on-dhir-profile-Patient
	boolean hasNeededProfile = oneIdGatewayData.hasProfile(oneIdGatewayData.fullProfile);//"http://ehealthontario.ca/StructureDefinition/ca-on-dhdr-profile-MedicationDispense","http://ehealthontario.ca/fhir/StructureDefinition/ca-on-consent-pcoi-profile-Consent");
	if(hasNeededScope && hasNeededProfile && oneIdGatewayData.howLongSinceRefreshTokenWasIssued() < 2){
		//All good
	}else{
		
		response.sendRedirect(request.getContextPath() + "/eho/login2.jsp?alreadyLoggedIn=true&forwardURL=" + URLEncoder.encode(OneIDTokenUtils.getCompleteURL(request),"UTF-8") );
		return;
	}
	
	
} catch(TokenExpiredException e) {
	if(oneIdGatewayData == null){
		oneIdGatewayData = new OneIdGatewayData();
		session.setAttribute(SessionConstants.OH_GATEWAY_DATA,oneIdGatewayData);
		loggedInInfo = LoggedInUserFilter.generateLoggedInInfoFromSession(request);
	}
	loggedInInfo = LoggedInUserFilter.generateLoggedInInfoFromSession(request);
	oneIdGatewayData.hasScope(oneIdGatewayData.fullScope);
	oneIdGatewayData.hasProfile(oneIdGatewayData.fullProfile);
	response.sendRedirect(request.getContextPath() + "/eho/login2.jsp?alreadyLoggedIn=true&forwardURL=" + URLEncoder.encode(OneIDTokenUtils.getCompleteURL(request),"UTF-8") );
	return;
} catch(NullPointerException e2) {
	if(oneIdGatewayData == null){
		oneIdGatewayData = new OneIdGatewayData();
		session.setAttribute(SessionConstants.OH_GATEWAY_DATA,oneIdGatewayData);
		loggedInInfo = LoggedInUserFilter.generateLoggedInInfoFromSession(request);
	}
	oneIdGatewayData.hasScope(oneIdGatewayData.fullScope);
	oneIdGatewayData.hasProfile(oneIdGatewayData.fullProfile);
	response.sendRedirect(request.getContextPath() + "/eho/login2.jsp?alreadyLoggedIn=true&forwardURL=" + URLEncoder.encode(OneIDTokenUtils.getCompleteURL(request),"UTF-8") );
	return;
}




%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html ng-app="dhdrView">
<head>
	<title>DHDR Search</title>
	<link href="<%=request.getContextPath() %>/library/bootstrap/3.0.0/css/bootstrap.css" rel="stylesheet">
	<link rel="stylesheet" href="<%=request.getContextPath() %>/css/font-awesome.min.css">
	<script type="text/javascript" src="<%=request.getContextPath() %>/library/angular.min.js"></script>	
	<script type="text/javascript" src="<%=request.getContextPath() %>/library/ui-bootstrap-tpls-0.11.0.js"></script>
	<script src="<%=request.getContextPath() %>/web/common/demographicServices.js"></script>	
	<script src="<%=request.getContextPath() %>/web/common/providerServices.js"></script>	
	<script src="<%=request.getContextPath() %>/web/common/dhdrServices.js"></script>	
	<script src="<%=request.getContextPath() %>/web/common/rxServices.js"></script>	
	<script src="<%=request.getContextPath() %>/web/filters.js"></script>
	<style>
		.modal-lg{ 
			width:1100px;
		}
	</style>
</head>

<body vlink="#0000FF" class="BodyStyle">
	<div ng-controller="dhdrView">
	<div class="page-header" style="margin-top: 0px; margin-bottom: 0px;">
		<h1 class="patientHeaderName" style="margin-top: 0px;" ng-cloak>
			<b>{{demographic.lastName}}, {{demographic.firstName}}</b>  <span ng-show="demographic.hin">({{demographic.hin}})</span> 
			
			<small class="patientHeaderExt pull-right"> 
				<i><bean:message key="demographic.patient.context.born"/>: </i>
				<b>{{demographic.dobYear}}-{{demographic.dobMonth}}-{{demographic.dobDay}}</b> (<b>{{demographic.age | age}}</b>) &nbsp;&nbsp; <i><bean:message key="demographic.patient.context.sex"/>:</i> <b>{{demographic.sex}}</b>
				<i> &nbsp;&nbsp; <bean:message key="Appointment.msgTelephone"/>:</i> <b>{{demographic.phone}}</b> 
				<!-- <span class="glyphicon glyphicon-new-window"></span>-->
			</small>
		</h1>
	</div>
	<div class="container">
		<div class="row">
		 	<div class="col-xs-12" >
		 		<form class="form-inline">
				  <div class="form-group">
				    <label for="exampleInputName2">Start Date</label>
				    <input type="date" class="form-control" id="exampleInputName2" placeholder="2020-01-01" ng-model="searchConfig.startDate">
				  </div>
				  <div class="form-group">
				    <label for="exampleInputEmail2">End Date</label>
				    <input type="date" class="form-control" id="exampleInputEmail2" placeholder="2020-03-31" ng-model="searchConfig.endDate" >
				  </div>
				 
				  <button type="submit" class="btn btn-default" ng-click="callSearch();" style="vertical-align: bottom;">Search</button>
				  <button type="submit" class="btn btn-default" ng-click="setSearchDateToAll();" style="vertical-align: bottom;">Search All</button>
				</form>
		 		
		 	</div>
		 </div>
		 <div class="row" style="margin-bottom:2px;">
		 	<div class="col-xs-12" >
		 	<i>DHDR is being search with HIN: {{demographic.hin}}  Sex: {{demographic.sex}}   DOB: {{demographic.dobYear}}-{{demographic.dobMonth}}-{{demographic.dobDay}}</i>
		 	</div>
		 </div>
		 
		 <div class="row" style="margin-bottom:10px;">
		 	<div class="col-xs-12" >
		 		<div class="alert alert-info" role="alert" ng-show="showDHDRDisclaimer">
		 				<button type="button" class="close" data-dismiss="alert" aria-label="Close" ng-click="closeWarning()"><span aria-hidden="true">&times;</span></button>
		 				<i>Warning: Limited to Drug and Pharmacy Service Information available in the Digital Health Drug Repository (DHDR) EHR Service. 
		 					To ensure a Best Possible Medication History, please review this information with the patient/family and use other available sources of medication 
		 					information in addition to the DHDR EHR Service. For more details on the information available in the DHDR EHR Service, 
		 					please  <a class="alert-link" href="http://www.forms.ssb.gov.on.ca/mbs/ssb/forms/ssbforms.nsf/FormDetail?OpenForm&ACT=RDR&TAB=PROFILE&SRCH=&ENV=WWE&TIT=5056-87E&NO=014-5056-87E" target="_blank">click here</a></i>
		 				<button ng-if="issue.code === 'suppressed'" type="button" class="btn btn-danger" ng-click="callConsentBlock();">Temporary Consent Unblock</button>
		 		</div>
		 		
		 		<div ng-show="searching">
					Searching...  
				</div>
		 		
		 		<div ng-repeat="outs in outcomes" >
		 			<div ng-repeat="issue in outs.issues"  class="alert" ng-class="issueClass(issue)" role="alert">
		 				{{issue.details.text}}
		 				<span ng-if="issue.code === 'suppressed'"> 
		 					<button type="button" class="btn btn-danger" ng-click="callConsentBlock();">Temporary Consent Unblock</button>
		 					<button type="button" class="btn btn-default" ng-click="cancelBlock();">Cancel</button>
		 					<button type="button" class="btn btn-default" ng-click="refusedBlock();">Refused</button>
		 				</span>
		 			</div>
		 		</div>
				
				<ul class="nav nav-pills nav-justified">
				  <li role="presentation" ng-class="currentView('summary')"><a ng-click="showSummary()">Summary</a></li>
				  <li role="presentation" ng-class="currentView('comp')"><a href="#" ng-click="showComp()">Comparative</a></li>  
				</ul>
		</div>
		<div class="row" ng-show="viewWhen('summary')">		
				<h6>Drug Products <small><a ng-click="showHideFilter()">Filter</a></small></h6>
				<div ng-show="showFilter()" >
					<form class="form-horizontal">
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Generic name</label>
					    <div class="col-sm-10">
					      <input ng-model="searchtxt.genericName" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Brand name</label>
					    <div class="col-sm-10">
					      <input ng-model="searchtxt.brandName.display" type="text" placeholder="type to filter" class="form-control"/>
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Dispensed date</label>
					    <div class="col-sm-10">
					      <input ng-model="searchtxt.whenPrepared" type="text" placeholder="type to filter" class="form-control"/>
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Pharmacy Name</label>
					    <div class="col-sm-10">
					      <input ng-model="searchtxt.dispensingPharmacy" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Prescriber Name</label>
					    <div class="col-sm-10">
					      <input ng-model="searchtxt.prescriberLastname" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Therapeutic Class</label>
					    <div class="col-sm-10">
					      <input ng-model="searchtxt.ahfsClass.display" type="text" placeholder="type to filter" class="form-control"/>
					    </div>
					  </div>
					  
					</form>
				</div>
		 		<table class="table table-condensed table-striped table-bordered" ng-show="meds.length > 0"> 		 			
		 			<thead> 
		 				<tr> 
		 					<th>
		 						<a ng-click="orderByField='whenPrepared'; reverseSort = !reverseSort">Dispense Date <span ng-show="orderByField == 'whenPrepared'"><span ng-show="!reverseSort">^</span><span ng-show="reverseSort">v</span></span></a>
		 					</th> 
		 					<th>
		 						<a ng-click="orderByField='genericName'; reverseSort = !reverseSort">Generic<span ng-show="orderByField == 'genericName'"><span ng-show="!reverseSort">^</span><span ng-show="reverseSort">v</span></span></a> 
		 					</th> 
		 					<th>
		 						<a ng-click="orderByField='brandName.display'; reverseSort = !reverseSort">Brand<span ng-show="orderByField == 'brandName.display'"><span ng-show="!reverseSort">^</span><span ng-show="reverseSort">v</span></span></a>
		 					</th> 
		 					<th>Strength</th>
		 					<th>Dosage Form</th>
		 					<th>Quantity</th>
		 					<th>Est Days Supply</th>
		 					<th>Refills Remaining</th>
							<th>Quantity Remaining</th>
		 					<th>
		 						<a ng-click="orderByField='prescriberLastname'; reverseSort = !reverseSort">Prescriber<span ng-show="orderByField == 'prescriberLastname'"><span ng-show="!reverseSort">^</span><span ng-show="reverseSort">v</span></span></a>
		 					</th>
		 					<th>Prescriber Tel#</th>
		 					<th>
		 						<a ng-click="orderByField='dispensingPharmacy'; reverseSort = !reverseSort">Pharmacy<span ng-show="orderByField == 'dispensingPharmacy'"><span ng-show="!reverseSort">^</span><span ng-show="reverseSort">v</span></span></a>
		 					</th>
		 					<th>Pharmacy Fax</th>
		 					<th>Rx Count</th> 
						</tr> 
					</thead> 
					
		 			<tbody> 
		 				<tr ng-repeat="med in uniqMeds | filter : searchtxt | orderBy:orderByField:reverseSort" ng-hide="med.hide" ng-class="getRowClass(med)"> 
		 					<th scope="row">{{med.whenPrepared | date}}</th> 
		 					<td ng-click="getDetailView(med);">{{med.genericName}} </td>
		 					<td>{{med.brandName.display}}</td>
		 					<td>{{med.dispensedDrugStrength}}</td>
		 					<td>{{med.drugDosageForm}}</td>
		 					<td>{{med.dispensedQuantity}}</td>
		 					<td>{{med.estimatedDaysSupply}}</td>
		 					<td>{{med.refillsRemaining}}</td>
							<td>{{med.quantityRemaining}}</td>
		 					<td>{{med.prescriberLastname}}, {{med.prescriberFirstname}} </td>
		 					<td>{{med.prescriberPhoneNumber}}</td>
		 					<td>{{med.dispensingPharmacy}}</td>
		 					<td>{{med.dispensingPharmacyFaxNumber}}</td>
		 					<td ng-click="showGroupedMeds2(medsWithGroupedDups[med.getUniqVal()])"><span ng-if="med.headRecord"><a>{{medsWithGroupedDups[med.getUniqVal()].length}}</a></span><!-- {{med | json}}  --></td> 
		 					
		 				</tr> 
		 				<tr>
		 					<td colspan="12">
		 						{{meds.length}} results returned  <button type="button" class="btn btn-default btn-xs" ng-click="printSummary()">Print</button>
 		 					</td>
		 				</tr>
		 			</tbody> 
		 		</table>
		 		
				<%-- services  --%>
				<h6>Pharma Services <small><a ng-click="showHideServiceFilter()">Filter</a></small></h6>
				<div ng-show="showServiceFilter()" >
					<form class="form-horizontal">
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Pharmacy Service Description</label>
					    <div class="col-sm-10">
					      <input ng-model="searchServicetxt.genericName" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Pharmacy Service Type</label>
					    <div class="col-sm-10">
					      <input ng-model="searchServicetxt.brandName.display" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Last Service Date</label>
					    <div class="col-sm-10">
					      <input ng-model="searchServicetxt.whenPrepared" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Pharmacy Name</label>
					    <div class="col-sm-10">
					      <input ng-model="searchServicetxt.dispensingPharmacy" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Pharmacist Name</label>
					    <div class="col-sm-10">
					      <input ng-model="searchServicetxt.pharmacistLastname" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  <div class="form-group">
					    <label for="inputEmail3" class="col-sm-2 control-label">Pharmacy #</label>
					    <div class="col-sm-10">
					      <input ng-model="searchServicetxt.dispensingPharmacyPhoneNumber" type="text" placeholder="type to filter" class="form-control" />
					    </div>
					  </div>
					  
					</form>
					
				</div>
		 		<table class="table table-condensed table-striped table-bordered" ng-show="services.length > 0"> 		 			
		 			<thead> 
		 				<tr> 
		 					<th>
		 						<a ng-click="serviceOrderByField='whenPrepared'; serviceReverseSort = !serviceReverseSort">Last Service Date <span ng-show="serviceOrderByField == 'whenPrepared'"><span ng-show="!serviceReverseSort">^</span><span ng-show="serviceReverseSort">v</span></span></a>
		 					</th> 
		 					<th>
		 						<a ng-click="serviceOrderByField='whenHandedOver'; serviceReverseSort = !serviceReverseSort">Pickup Date <span ng-show="serviceOrderByField == 'whenHandedOver'"><span ng-show="!serviceReverseSort">^</span><span ng-show="serviceReverseSort">v</span></span></a>
		 					</th> 
		 					<th>
		 						<a ng-click="serviceOrderByField='brandName.display'; serviceReverseSort = !serviceReverseSort">Pharmacy Service Type<span ng-show="serviceOrderByField == 'brandName.display'"><span ng-show="!serviceReverseSort">^</span><span ng-show="serviceReverseSort">v</span></span></a> 
		 					</th> 
		 					<th>
		 						<a ng-click="serviceOrderByField='genericName'; serviceReverseSort = !serviceReverseSort">Pharmacy Service Description<span ng-show="serviceOrderByField == 'genericName'"><span ng-show="!serviceReverseSort">^</span><span ng-show="serviceReverseSort">v</span></span></a>
		 					</th> 
							<th>
		 						<a ng-click="serviceOrderByField='dispensingPharmacy'; serviceReverseSort = !serviceReverseSort">Pharmacy Name<span ng-show="serviceOrderByField == 'dispensingPharmacy'"><span ng-show="!serviceReverseSort">^</span><span ng-show="serviceReverseSort">v</span></span></a>
		 					</th>
		 					<th>
		 						<a ng-click="serviceOrderByField='pharmacistLastname'; serviceReverseSort = !serviceReverseSort">Pharmacist<span ng-show="serviceOrderByField == 'pharmacistLastname'"><span ng-show="!serviceReverseSort">^</span><span ng-show="serviceReverseSort">v</span></span></a>
		 					</th>
		 					<th>
		 						<a ng-click="serviceOrderByField='dispensingPharmacyFaxNumber'; serviceReverseSort = !serviceReverseSort">Pharmacy Fax<span ng-show="serviceOrderByField == 'dispensingPharmacyPhoneNumber'"><span ng-show="!serviceReverseSort">^</span><span ng-show="serviceReverseSort">v</span></span></a>
		 					</th>
		 					<th>Service Count</th> 
						</tr> 
					</thead> 
					 
		 			<tbody> 
		 				<tr ng-repeat="med in uniqServices | filter : searchServicetxt | orderBy:serviceOrderByField:serviceReverseSort" ng-hide="med.hide" ng-class="getRowClass(med)"> 
		 					<th scope="row">{{med.whenPrepared | date}}</th> 
		 					<td scope="row">{{med.whenHandedOver | date}}</td>
		 					<td>{{med.brandName.display}}</td> 
		 					<td>{{med.genericName}} </td>
		 					<td>{{med.dispensingPharmacy}}</td>
		 					<td>{{med.pharmacistLastname}}, {{med.pharmacistFirstname}} </td>
		 					<td>{{med.dispensingPharmacyFaxNumber}}</td> 
		 					<td ng-click="showGroupedServices2(servicesWithGroupedDups[med.brandName.display])"><span ng-if="med.headRecord"><a>{{servicesWithGroupedDups[med.brandName.display].length}}</a></span><!-- {{med | json}}  --></td> 
		 					
		 				</tr> 
		 				<tr>
		 					<td colspan="8">
		 						{{services.length}} results returned  <button type="button" class="btn btn-default btn-xs" ng-click="printSummary()">Print</button>
 		 					</td>
		 				</tr>
		 			</tbody> 
		 		</table>
				
				<!--  end services -->
		 </div>
	 	
	 	
	 	
	 	<div ng-show="viewWhen('comp')">	<!-- comparative view start -->
	 		<div class="row">
		 		<div class="col-xs-12" >
		 			<button type="button" class="btn btn-default btn-xs" ng-click="hideShowDhirData()"><span ng-if="hideShowDhirDataVal">Hide</span><span ng-if="!hideShowDhirDataVal">Show</span> DHDR DATA</button>
		 			<button type="button" class="btn btn-default btn-xs" ng-click="hideShowDhirPharma()"><span ng-if="hideShowDhirPharmaVal">Hide</span><span ng-if="!hideShowDhirPharmaVal">Show</span> DHDR PharmaServices</button>
		 			<button type="button" class="btn btn-default btn-xs" ng-click="hideShowDhirDrug()"><span ng-if="hideShowDhirDrugVal">Hide</span><span ng-if="!hideShowDhirDrugVal">Show</span> DHDR Drugs</button>
		 			
		 			<button type="button" class="btn btn-default btn-xs" ng-click="printComparative()">Print</button>
		 		</div>
		 	</div>
	 		
	 		<div class="row">
		 		<div class="col-xs-6" ng-if="hideShowDhirDataVal">
			 		<div ng-if="hideShowDhirDrugVal">
				 		<h4>DHDR Drugs</h4>
				 			<h6>Medication Dispense</h6>
				 			<table class="table table-condensed table-striped table-bordered" > 
				 			<%-- caption>
				 			<div><i>Warning: Limited to Drug and Pharmacy Service Information available in the Digital Health Drug Repository (DHDR) EHR Service. 
				 					To ensure a Best Possible Medication History, please review this information with the patient/family and use other available sources of medication 
				 					information in addition to the DHDR EHR Service. For more details on the information available in the DHDR EHR Service, 
				 					please  <a href="http://www.forms.ssb.gov.on.ca/mbs/ssb/forms/ssbforms.nsf/FormDetail?OpenForm&ACT=RDR&TAB=PROFILE&SRCH=&ENV=WWE&TIT=5056-87E&NO=014-5056-87E" target="_blank">click here</a></i></div>
				 			</caption --%>
				 			<thead> 
				 				<tr> 
				 					<th>Dispense Date</th> 
				 					<%-- th>Generic</th> --%> 
				 					<th>Brand</th> 
				 					<th>Quantity</th>
				 					<th>Status</th>
				 					<th>Prescriber</th>
				 					<th>Pharmacy</th>
								</tr> 
							</thead> 
				 			<tbody> 
				 				<tr ng-repeat="med in meds"> 
				 					<th scope="row">{{med.whenPrepared | date}}</th> 
				 					<%-- td >{{med.genericName}}</td> --%>
				 					<td ng-click="getDetailView(med);">{{med.brandName.display}} {{med.dispensedDrugStrength}} {{med.drugDosageForm}} ({{med.genericName}})</td>
				 					<td>{{med.dispensedQuantity}}</td>
				 					<td>
				 						Est Days Supply:{{med.estimatedDaysSupply}}
				 						Refills Remaining:{{med.refillsRemaining}}
										Quantity Remaining:{{med.quantityRemaining}}
				 					</td>
				 					<td>{{med.prescriberLastname}}, {{med.prescriberFirstname}} Tel:{{med.prescriberPhoneNumber}}</td>
				 					<td>{{med.dispensingPharmacy}} {{med.dispensingPharmacyFaxNumber}}</td>
				 					
				 					
				 				</tr>
				 				<tr>
				 					<td colspan="6">
				 						{{meds.length}} results returned
		 		 					</td>
				 				</tr> 
				 			</tbody> 
				 		</table>
			 		</div>
			 		<div ng-if="hideShowDhirPharmaVal">
				 		<h6>DHDR PharmaServices</h6>
				 		 <table class="table table-condensed table-striped table-bordered" ng-show="services.length > 0"> 		 			
				 			<thead> 
				 				<tr> 
				 					<th>Last Service Date</th> 
				 					<th>Pickup Date</th> 
				 					<th>Pharmacy Service Type</th> 
				 					<th>Pharmacy Service Description</th> 
									<th>Pharmacy Name</th>
				 					<th>Pharmacist</th>
								</tr> 
							</thead> 
							 
				 			<tbody> 
				 				<tr ng-repeat="med in services | filter : searchtxt | orderBy:serviceOrderByField:serviceReverseSort"> 
				 					<th scope="row">{{med.whenPrepared | date}}</th> 
				 					<td scope="row">{{med.whenHandedOver | date}}</td>
				 					<td>{{med.brandName.display}}</td> 
				 					<td>{{med.genericName}} </td>
				 					<td>{{med.dispensingPharmacy}} - Tel:{{med.dispensingPharmacyPhoneNumber}}</td>
				 					<td>{{med.pharmacistLastname}}, {{med.pharmacistFirstname}} </td>
				 					
				 				</tr> 
				 				<tr>
				 					<td colspan="8">
				 						{{services.length}} results returned  
		 		 					</td>
				 				</tr>
				 			</tbody> 
				 		</table>
			 		</div>
		 		</div>
		 		<div class="col-xs-6" >
		 		<h4>EMR prescriptions</h4>
		 			<table class="table table-condensed table-striped table-bordered" ng-show="compLocalMeds.length > 0"> 
		 			   	<thead> 
			 				<tr> 
			 					<th>Start Date</th> 
			 					<th>Medication</th>
			 					<th>Prescriber</th>
			 					<th>DIN</th>
			 					 
							</tr> 
						</thead> 
		 				<tbody> 
			 				<tr ng-repeat="med in compLocalMeds"> 
			 					<th scope="row">{{med.rxDate | date}}</th>
			 					<%-- td ng-click="getDetailView(med);">{{med.genericName}}</td> --%>
			 					<td>{{med.instructions}}</td>
			 					<td>{{med.providerName}}</td>
			 					<td>{{med.regionalIdentifier}}</td>
			 				</tr> 
			 			</tbody> 
		 			</table>
		 	
		 		</div>
		 	</div>
	 	
	 	
	 	</div> <!-- comparitive view end -->
	 	
	 	
		</div> <!-- container -->
	</div>
	<script type="text/ng-template" id="myModalContent.html">
        <div class="modal-header">
            <h3 class="modal-title" id="modal-title">{{med.genericName}} - {{med.whenPrepared | date}}</h3>
        </div>
        <div class="modal-body" id="modal-body">
            <div class="md-dialog-content" id="dialogContentApptProvider">
            
            <div class="row">
                <div class="col-xs-11">



                    <table class="table table-bordered table striped" >
                       
						<tr> 
		 					<th>Dispense Date</th> 
							<th scope="row">{{med.whenPrepared | date}}</th>
						</tr>
						<tr>
		 					<th>Generic</th> 
							<td>{{med.genericName}}</td>
</tr>
						<tr>
		 					<th>Brand</th>
							<td>{{med.brandName.display}}</td>
 </tr>
						<tr>
		 					<th>DIN/PIN</th>
							<td>{{med.brandName.code}}</td>
 						</tr>
						<tr>
		 					<th>Therapeutic Class</th>
							<td>{{med.ahfsClass.display}}</td>
 						</tr>
						<tr>
		 					<th>Therapeutic Sub-Class</th>
							<td>{{med.ahfsSubClass.display}}</td>
 						</tr>
						<tr>
		 					<th>Rx Number</th>
							<td>{{med.rxNumber}}</td>
 						</tr>
						<tr>
							<th>Medical Condition/Reason for Use</th>
							<td>
								<div ng-repeat="rcode in med.reasonCode">
									<div ng-repeat="reason in rcode">({{reason.code}}) -- {{reason.display}}</div>
								</div>
							</td>
						</tr>

						<tr>
		 					<th>Strength</th>	
							<td>{{med.dispensedDrugStrength}}</td>
						</tr>
						<tr>
		 					<th>Dosage Form</th>
							<td>{{med.drugDosageForm}}</td>
						</tr>
						<tr>		 					

							<th>Quantity</th>
							<td>{{med.dispensedQuantity}}</td>
						</tr>
						<tr>
		 					<th>Est Days Supply</th>
							<td>{{med.estimatedDaysSupply}}</td>
						</tr>

						<tr>
		 					<th>Refills Remaining</th>
							<td>{{med.refillsRemaining}}</td>
						</tr>
						<tr>
		 					<th>Quantity Remaining</th>
							<td>{{med.quantityRemaining}}</td>
						</tr>	
						
							

						<tr>
		 					<th>Prescriber</th>
							<td>{{med.prescriberLastname}}, {{med.prescriberFirstname}} ({{med.prescriberLicenceNumber.value}})</td>
						</tr>
						<tr>
						<tr>
		 					<th>Prescriber ID</th>
							<td> {{getLicence(med.prescriberLicenceNumber.system)}} ({{med.prescriberLicenceNumber.value}})</td>
						</tr>
						<tr>
		 					<th>Prescriber #</th>
							<td>{{med.prescriberPhoneNumber}}</td>
						</tr>	
						<tr>
		 					<th>Pharmacy</th>
							<td>{{med.dispensingPharmacy}}</td>
						</tr>
						<tr>
		 					<th>Pharmacy Fax</th>
							<td>{{med.dispensingPharmacyFaxNumber}}</td>
						</tr> 
						<tr>
		 					<th>Pharmacy Phone</th>
							<td>{{med.dispensingPharmacyPhoneNumber}}</td> 
						</tr> 
						<tr>
							<th>Pharmacist</th>
							<td>{{med.pharmacistLastname}}, {{med.pharmacistFirstname}} ({{med.pharmacistLicenceNumber.value}})
						</tr>
					
<!-- tr>
<td colspan=2>
<pre>{{med}}</pre>
</td>
</tr -->
                        
                    </table>
                </div>
            </div>
        </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-primary" type="button" ng-click="printDetail()">Print</button>
            <button class="btn btn-warning" type="button" ng-click="cancel()">Cancel</button>
        </div>
    </script>
    <script type="text/ng-template" id="pcoi.html">
<div class="modal-body" id="modal-body">
		<a ng-if="showUntilLoaded" ng-click="reload()"> Failed to load? click here</a>	
		<a ng-if="viewletNotResponding" ng-click="cancel()"> Viewlet not responding? click here</a>	
		<iframe id="pcoi-frame" src="{{pcoiUrl}}" sandbox="allow-forms allow-scripts allow-same-origin allow-modals"  width="540" height="600" ng-onload="loadingResult(state,message)"></iframe>
		
<div>
	</script>
	<script type="text/ng-template" id="drugDupsContent.html">
        <div class="modal-header">
            <h3 class="modal-title" id="modal-title">{{med.genericName}} - {{med.whenPrepared | date}}</h3>
        </div>
        <div class="modal-body" id="modal-body">
            <div class="md-dialog-content" id="dialogContentApptProvider">
            
            <div class="row">
                <div class="col-xs-12">
					<table class="table table-condensed table-striped table-bordered" ng-show="meds.length > 0"> 		 			
		 			<thead> 
		 				<tr> 
		 					<th>Dispense Date</th> 
		 					<th>Generic</th> 
		 					<th>Brand</th> 
		 					<th>Strength</th>
		 					<th>Dosage Form</th>
		 					<th>Quantity</th>
		 					<th>Est Days Supply</th>
		 					<th>Refills Remaining</th>
							<th>Quantity Remaining</th>
		 					<th>Prescriber</th>
		 					<th>Prescriber Tel#</th>
		 					<th>Pharmacy</th>
		 					<th>Pharmacy Fax</th>
						</tr> 
					</thead> 
					
		 			<tbody> 
		 				<tr ng-repeat="med in meds | filter : searchtxt | orderBy:whenPrepared:reverseSort"> 
		 					<th scope="row">{{med.whenPrepared | date}}</th> 
		 					<td ng-click="getDetailView(med);">{{med.genericName}} </td>
		 					<td>{{med.brandName.display}}</td>
		 					<td>{{med.dispensedDrugStrength}}</td>
		 					<td>{{med.drugDosageForm}}</td>
		 					<td>{{med.dispensedQuantity}}</td>
		 					<td>{{med.estimatedDaysSupply}}</td>
		 					<td>{{med.refillsRemaining}}</td>
							<td>{{med.quantityRemaining}}</td>
		 					<td>{{med.prescriberLastname}}, {{med.prescriberFirstname}} </td>
		 					<td>{{med.prescriberPhoneNumber}}</td>
		 					<td>{{med.dispensingPharmacy}}</td>
		 					<td>{{med.dispensingPharmacyFaxNumber}}</td> 
		 				</tr> 
		 			</tbody> 
		 		</table>
                </div>
            </div>
        </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-warning" type="button" ng-click="cancel()">Cancel</button>
        </div>
    </script>
	<script type="text/ng-template" id="pharmaDupsContent.html">
        <div class="modal-header">
            <h3 class="modal-title" id="modal-title">{{med.genericName}} - {{med.whenPrepared | date}}</h3>
        </div>
        <div class="modal-body" id="modal-body">
            <div class="md-dialog-content" id="dialogContentApptProvider">
            
            <div class="row">
                <div class="col-xs-12">
					<table class="table table-condensed table-striped table-bordered" ng-show="services.length > 0"> 		 			
		 			<thead> 
		 				<tr> 
		 					<th>Last Service Date </th> 
		 					<th>Pickup Date</th> 
		 					<th>Pharmacy Service Type</th> 
		 					<th>Pharmacy Service Description</th> 
							<th>Pharmacy Name</th>
		 					<th>Pharmacist</th>
		 					<th>Pharmacy Tel</th>
						</tr> 
					</thead> 
					 
		 			<tbody> 
		 				<tr ng-repeat="med in services | filter : searchServicetxt | orderBy:serviceOrderByField:serviceReverseSort" > 
		 					<th scope="row">{{med.whenPrepared | date}}</th> 
		 					<td scope="row">{{med.whenHandedOver | date}}</td>
		 					<td>{{med.brandName.display}}</td> 
		 					<td>{{med.genericName}} </td>
		 					<td>{{med.dispensingPharmacy}}</td>
		 					<td>{{med.pharmacistLastname}}, {{med.pharmacistFirstname}} </td>
		 					<td>{{med.dispensingPharmacyPhoneNumber}}</td> 
		 				</tr> 
		 			</tbody> 
		 		</table>
                </div>
            </div>
        </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-warning" type="button" ng-click="cancel()">Cancel</button>
        </div>
    </script>
	<script>
		var app = angular.module("dhdrView", ['demographicServices','providerServices','dhdrServices','oscarFilters','ui.bootstrap','rxServices']);
		
		//app.config(['$locationProvider'],function($locationProvider ) {
		//	$locationProvider.html5Mode(true);
		//});
		
		app.controller("dhdrView", function($scope,demographicService,providerService,dhdrService,rxService,$location,$window,$modal,$http,$filter) {

			console.log("$location.search()",$location);
			$scope.demographicNo = $location.search().demographic_no;
			
			//if($scope.demographicNo == undefined){
				var urlParams = new URLSearchParams(window.location.search);
				$scope.demographicNo = urlParams.get("demographic_no");
			//}
			$scope.demographic = {};
			activeProvidersHash = {};
			$scope.meds = [];
			$scope.uniqMeds = [];
			$scope.uniqServices = [];
			$scope.services = [];
			$scope.outcomes = [];
			defaultDaysToSearch = 120;
			$scope.searchConfig = {};
			$scope.searchConfig.endDate = new Date();
			$scope.searchConfig.startDate = new Date($scope.searchConfig.endDate);
			$scope.searchConfig.startDate.setDate($scope.searchConfig.endDate.getDate() - defaultDaysToSearch);
			$scope.searching = false;
			$scope.showDHDRDisclaimer = true;
			$scope.hideShowDhirDataVal = true;
			$scope.showSummaryProductFilter = false;
			$scope.showSummaryServiceFilter = false;
			$scope.hideShowDhirPharmaVal = true;
			$scope.hideShowDhirDrugVal = true;
			
			$scope.hideShowDhirData = function(){
				if($scope.hideShowDhirDataVal){
					$scope.hideShowDhirDataVal = false;
				}else{
					$scope.hideShowDhirDataVal = true;
				}
			}
			
			$scope.hideShowDhirPharma = function(){
				if($scope.hideShowDhirPharmaVal){
					$scope.hideShowDhirPharmaVal = false;
				}else{
					$scope.hideShowDhirPharmaVal = true;
				}
			}
			
			$scope.hideShowDhirDrug = function(){
				if($scope.hideShowDhirDrugVal){
					$scope.hideShowDhirDrugVal = false;
				}else{
					$scope.hideShowDhirDrugVal = true;
				}
			}
			
			$scope.showHideFilter = function(){
				if($scope.showSummaryProductFilter){
					$scope.searchtxt = {};
					$scope.showSummaryProductFilter =false;
				}else{
					$scope.showSummaryProductFilter = true;
				}
			}
			
			$scope.showFilter = function(){
				return $scope.showSummaryProductFilter;
			}
			
			$scope.showHideServiceFilter = function(){
				if($scope.showSummaryServiceFilter){
					$scope.searchServicetxt = {};
					$scope.showSummaryServiceFilter =false;
				}else{
					$scope.showSummaryServiceFilter = true;
				}
			}
			
			$scope.showServiceFilter = function(){
				return $scope.showSummaryServiceFilter;
			}
			
			
			
			$scope.closeWarning = function(){
				$scope.showDHDRDisclaimer = false;
				dhdrService.muteDisclaimer("DHDR").then(function(data) {
					console.log("set to hidden",data);
				}, function(errorMessage) {
					alert("Error saving ")
					//rxComp.error = errorMessage;
				});	
			
			}
			
			$scope.getShowDisclaimerStatus = function(){
				dhdrService.showDisclaimer("DHDR").then(function(data) {
					console.log("set to hidden",data);
					if(data.status == 268){
						$scope.showDHDRDisclaimer = false;
					}else{
						$scope.showDHDRDisclaimer = true;
					}
				}, function(errorMessage) {
					alert("Error saving ")
					//rxComp.error = errorMessage;
				});	
			}
			$scope.getShowDisclaimerStatus();
			
			getAllActiveProviders = function(){
	    			providerService.getAllActiveProviders().then(function(data){
		    			$scope.activeProviders = data;
		    			console.log("$scope.activeProviders",data);
		    			angular.forEach($scope.activeProviders, function(provider) {
		    				activeProvidersHash[provider.providerNo] = provider;
		    			});
		    			console.log("getAllActiveProviders", activeProvidersHash); //data);
				});
	    		};
	    		
	    		getAllActiveProviders();
	    		
	    		$scope.getProviderName = function(providerNumber){
	    			provider = activeProvidersHash[providerNumber];
	    			if(provider == null){ return providerNumber+" N/A inactive"}
	    			return provider.lastName+", "+provider.firstName;
	    		}
			
			$scope.orderByField = 'whenPrepared';
			$scope.reverseSort = true;
			
			$scope.serviceOrderByField = 'whenPrepared';
			$scope.serviceReverseSort = true;
			
			
			////////
			currentViewValue = 'summary'
			
			$scope.showSummary = function(){
				currentViewValue = 'summary';
			}
			
			$scope.printSummary = function(){
				var toPrint = {};
				toPrint.meds = $scope.meds;
				toPrint.services = $scope.services;
				toPrint.startDate = $filter('date')($scope.searchConfig.startDate, "yyyy-MM-dd");
				toPrint.endDate   = $filter('date')($scope.searchConfig.endDate, "yyyy-MM-dd");
				
				$http.post('../ws/rs/dhdr/'+$scope.demographicNo+'/print/summary',toPrint,{ responseType: 'arraybuffer' }).then(function (response) {
					
					console.log("respone",response);
				       var file = new Blob([response.data], {type: 'application/pdf'});
				       var fileURL = URL.createObjectURL(file);
				       window.open(fileURL);
				}, function(errorMessage) {
					alert("Error getting printout");
					//rxComp.error = errorMessage;
				});	
				//window.open('../ws/rs/dhdr/'+$scope.demographicNo+'/print/summary','_blank');
			}
			
			$scope.printComparative = function(){
				var toPrint = {};
				toPrint.meds = $scope.meds;
				toPrint.services = $scope.services;
				toPrint.localData = $scope.compLocalMeds;
				toPrint.startDate = $filter('date')($scope.searchConfig.startDate, "yyyy-MM-dd");
				toPrint.endDate   = $filter('date')($scope.searchConfig.endDate, "yyyy-MM-dd");
				
				$http.post('../ws/rs/dhdr/'+$scope.demographicNo+'/print/comparative',toPrint,{ responseType: 'arraybuffer' }).then(function (response) {
					
					console.log("respone",response);
				       var file = new Blob([response.data], {type: 'application/pdf'});
				       var fileURL = URL.createObjectURL(file);
				       window.open(fileURL);
				}, function(errorMessage) {
					alert("Error getting printout");
					//rxComp.error = errorMessage;
				});	
				//window.open('../ws/rs/dhdr/'+$scope.demographicNo+'/print/summary','_blank');
			}
			
			$scope.showComp = function() {
				currentViewValue = 'comp';	
					rxService.getMedications($scope.demographicNo, "").then(function(data) {
						console.log("getMedications--", data);
						$scope.compLocalMeds = data.data.content;
						
						angular.forEach($scope.compLocalMeds,function(med){
							med.providerName = $scope.getProviderName(med.providerNo);
						});
						
					}, function(errorMessage) {
						console.log("getMedications++" + errorMessage);
						//rxComp.error = errorMessage;
					});	
				
			}
			
			$scope.currentView = function(view){
				if(currentViewValue === view){
					return "active";
				}
			}
			
			$scope.viewWhen = function(view){
			
				if(currentViewValue === view){
					return true;
				}
			}
			

			
			
			
			$scope.setSearchDateToAll = function(){

				console.log("$scope.demographic",$scope.demographic.dobYear+"-"+$scope.demographic.dobMonth+"-"+$scope.demographic.dobDay);
				
				$scope.searchConfig.startDate = new Date($scope.demographic.dobYear+"-"+$scope.demographic.dobMonth+"-"+$scope.demographic.dobDay);
				$scope.searchConfig.endDate = new Date();
				$scope.callSearch();
			}
			
			$scope.medsWithGroupedDups = [];
			
			
			$scope.issueClass = function(issue){
				if(issue.severity === "warning"){
					return "alert-danger";
				}
				return "alert-warning";
			}
			
			
			$scope.compDhirMeds = [];
			$scope.compLocalMeds = [];
			
			/*$scope.fillCompView = function(){
				var compsearchConfig = {};
				compsearchConfig.startDate = new Date($scope.demographic.dobYear+"-"+$scope.demographic.dobMonth+"-"+$scope.demographic.dobDay);
				compsearchConfig.endDate = new Date();
			
				dhdrService.searchByDemographicNo2($scope.demographicNo,compsearchConfig).then(function(response){
					console.log("response.entry",response.entry);
					$scope.searching = false;
					$scope.compDhirMeds = [];
					$scope.outcomes = [];
					for (x of  response.entry) {
						console.log("x",x);
						if(x.resource.resourceType === "OperationOutcome"){
							var o = new OperationOutcome(x);
							$scope.outcomes.push(o);
							console.log("$scope.outcomes",$scope.outcomes);
						}else if(x.resource.resourceType === "MedicationDispense"){
							var d = new MedicationDispense(x);
							console.log("d",d,d.getUniqVal());
							$scope.compDhirMeds.push(d);
						}
					}
				},function(reason){
					$scope.searching = false;
					alert(reason);
				});
				
				
				rxService.getMedications($scope.demographicNo, "").then(function(data) {
					console.log("getMedications--", data);
					$scope.compLocalMeds = data.data.content;
				}, function(errorMessage) {
					console.log("getMedications++" + errorMessage);
					//rxComp.error = errorMessage;
				});
				
			};
			*/
			
			
			/*
			$scope.$watch('location.search()', function() {
				console.log("Watch called",$location.search());
		        $scope.demographicNo = ($location.search()).demographicNo;
		        getDemo();
		    }, true);
*/
			
			
			$scope.showGroupedMeds = function(med) {
				hiddenGroup = $scope.medsWithGroupedDups[med.getUniqVal()];
				//console.log("hiddenGroup",hiddenGroup);
				//for (x of  hiddenGroup) {
				//	x.hide = false;
				//}
				//console.log("hiddenGroup2",hiddenGroup);
				
				var currentlyHasHiddenItems = false; 
				for (x of  hiddenGroup) {
					if(x.hide){
						currentlyHasHiddenItems = true;
					}
				}
				
				if(currentlyHasHiddenItems){
					for (x of  hiddenGroup) {
						x.hide = false;
					}
				}else{
					for (x of  hiddenGroup) {
						if(x.hiddenRecord){
							x.hide = true;	
						}
					}
				}
				
			}
			
			$scope.showGroupedService = function(med){
				hiddenGroup = $scope.servicesWithGroupedDups[med.brandName.display];
				//console.log("hiddenGroup",hiddenGroup);
				var currentlyHasHiddenItems = false; 
				for (x of  hiddenGroup) {
					if(x.hide){
						currentlyHasHiddenItems = true;
					}
				}
				if(currentlyHasHiddenItems){
					for (x of  hiddenGroup) {
						x.hide = false;
					}
				}else{
					for (x of  hiddenGroup) {
						if(x.hiddenRecord){
							x.hide = true;	
						}
					}
				}
				//console.log("hiddenGroup2",hiddenGroup);
			}
			
			$scope.getRowClass = function(med){
				if(med.hiddenRecord){
					return "warning";
				}
			}
			
			processEntries = function(entries){
				for (x of entries) {
					console.log("x",x);
					if(x.resource.resourceType === "OperationOutcome"){
						var o = new OperationOutcome(x);
						$scope.outcomes.push(o);
						console.log("$scope.outcomes",$scope.outcomes);
					}else if(x.resource.resourceType === "MedicationDispense"){
						var d = new MedicationDispense(x);
						if(d.categoryCode === "service"){ 
							console.log("d",d,d.brandName.display);
							$scope.services.push(d);
							console.log("d.brandName.display",d.brandName.display,$scope.servicesWithGroupedDups[d.brandName.display]);
							
							//if ($scope.medsWithGroupedDups.indexOf(d.getUniqVal()) === -1) {
							if($scope.servicesWithGroupedDups[d.brandName.display] === undefined){
								$scope.servicesWithGroupedDups[d.brandName.display] = [];
								d.headRecord= true;
								$scope.uniqServices.push(d);
								
								$scope.servicesWithGroupedDups[d.brandName.display].push(d);
							}else{
								console.log("found ",d.getUniqVal(),$scope.servicesWithGroupedDups[d.brandName.display]);
								d.hide = true;
								d.hiddenRecord = true;
								$scope.servicesWithGroupedDups[d.brandName.display].push(d);
							}
							
						}else{
						
							///
							console.log("d",d,d.getUniqVal());
							$scope.meds.push(d);
							console.log("d.getUniqVal()",d.getUniqVal(),$scope.medsWithGroupedDups[d.getUniqVal()]);
							
							//if ($scope.medsWithGroupedDups.indexOf(d.getUniqVal()) === -1) {
							if($scope.medsWithGroupedDups[d.getUniqVal()] === undefined){
								$scope.medsWithGroupedDups[d.getUniqVal()] = [];
								d.headRecord= true;
								$scope.uniqMeds.push(d);
								$scope.medsWithGroupedDups[d.getUniqVal()].push(d);
							}else{
								console.log("found ",d.getUniqVal(),$scope.medsWithGroupedDups[d.getUniqVal()]);
								d.hide = true;
								d.hiddenRecord = true;
								$scope.medsWithGroupedDups[d.getUniqVal()].push(d);
							}
						}
					}
				}
						
				//If a block record is found the other warnings are dumped.  Probably a bad idea but OMD's requirement.
				for(outcome of $scope.outcomes) {
					var replaceIssue = null;
					for(issue of outcome.issues){	
						if	(issue.code === 'suppressed'){
							replaceIssue = issue;
						}
					}
					if(replaceIssue != null){
						outcome.issues = [];
						outcome.issues.push(replaceIssue);
					}
				}
				
			};
			
			$scope.callSearch = function(){
				
				$scope.meds = [];
				$scope.services = [];
				$scope.outcomes = [];
				$scope.uniqMeds = [];
				$scope.uniqServices = [];
				
				$scope.medsWithGroupedDups = [];
				$scope.servicesWithGroupedDups = [];
				$scope.searchConfig.searchId = null;
				$scope.searchConfig.pageId = null;
				search($scope.demographicNo,$scope.searchConfig);
			
			}
		
			search = function(demographicNo,searchConfig){
				$scope.searching = true;
				dhdrService.searchByDemographicNo2(demographicNo,searchConfig).then(function(response){
					
				    console.log("resonse",response);
					console.log("response.entry",response.entry);
					$scope.searching = false;
					
					
					console.log("HAS more ",response.link.length);
					
					if(angular.isUndefined(response.entry)){
						if(angular.isDefined(response.resourceType) && response.resourceType === "OperationOutcome"){
							var o = new OperationOutcome(response);
							$scope.outcomes.push(o);
							console.log("$scope.outcomes",$scope.outcomes);
							return;
						}
						
					}
						
					processEntries(response.entry);
					
					if(response.link.length > 1){
						$scope.searchConfig.searchId = response.id;
						console.log("$scope.searchConfig.",$scope.searchConfig);
						if($scope.searchConfig.pageId == null){
							$scope.searchConfig.pageId = 2;
						
						}else{
							$scope.searchConfig.pageId = $scope.searchConfig.pageId+1;
						}
						search($scope.demographicNo,$scope.searchConfig);
					}
					
					
					
				},function(reason){
					$scope.searching = false;
					alert(reason);
				});
			}
		
			getDemo = function(){
				demographicService.getDemographic($scope.demographicNo).then(function(response){
					$scope.demographic = response;
					//search($scope.demographicNo,$scope.searchConfig);
					$scope.callSearch();
				},function(reason){
					alert(reason);
				});
			};
			
			getDemo();
			
			$scope.getDetailView = function(med,$event){
			    
	    		    var modalInstance = $modal.open({
	    		      
	    		      templateUrl: 'myModalContent.html',
	    		      controller: 'ModalInstanceCtrl',
	    		      controllerAs: 'mpa',
	    		      parent: angular.element(document.body),
	    		      size: 'lg',
	    		      appendTo: $event,
	    		      resolve: {
	    		    	  	
	    		    	  		med: function () {
	    		          		return med;
	    		        		},
	    		        		demoNo: function () {
	    		          		return $scope.demographicNo;
	    		        		} 
	    		      }
	    		    });

	    		    modalInstance.result.then(function (selectedItem) {
	    		      selected = selectedItem;
	    		    }, function () {
	    		      console.log('Modal dismissed at: ' + new Date());
	    		    });
    		  };
	    	
    		  
    		  $scope.showGroupedMeds2 =function(meds,$event){
				var modalInstance = $modal.open({
	    		      
	    		      templateUrl: 'drugDupsContent.html',
	    		      controller: 'DrugDupsInstanceCtrl',
	    		      controllerAs: 'ddpa',
	    		      parent: angular.element(document.body),
	    		      size: 'lg',
	    		      appendTo: $event,
	    		      resolve: {
	    		    	  	
	    		    	  		meds: function () {
	    		          		return meds;
	    		        		},
	    		        		getDetailView: function () {
	    		          		return $scope.getDetailView;
	    		        		} 
	    		      }
	    		    });

	    		    modalInstance.result.then(function (selectedItem) {
	    		      selected = selectedItem;
	    		    }, function () {
	    		      console.log('Modal dismissed at: ' + new Date());
	    		    });
    		  };
    		  
    		  
    		  $scope.showGroupedServices2 =function(services,$event){
  				var modalInstance = $modal.open({
  	    		      
  	    		      templateUrl: 'pharmaDupsContent.html',
  	    		      controller: 'PharmaDupsInstanceCtrl',
  	    		      controllerAs: 'pdpa',
  	    		      parent: angular.element(document.body),
  	    		      size: 'lg',
  	    		      appendTo: $event,
  	    		      resolve: {
  	    		    	  	
  	    		    	  		services: function () {
  	    		          		return services;
  	    		        		},
  	    		        		getDetailView: function () {
  	    		          		return $scope.getDetailView;
  	    		        		} 
  	    		      }
  	    		    });

  	    		    modalInstance.result.then(function (selectedItem) {
  	    		      selected = selectedItem;
  	    		    }, function () {
  	    		      console.log('Modal dismissed at: ' + new Date());
  	    		    });
      		  };
    		  
    		  
    		  $scope.cancelBlock = function(){
    			  var cancelReason = prompt("Access to Drug and Pharmacy Service Information has been cancelled. \nReason:");

    			  if (cancelReason != null) {
    			    var cancelMsg= {};
    			    cancelMsg.type = 'CANCEL';
    			    cancelMsg.reason = cancelReason;
    		
    			    dhdrService.logConsentOverrideCancelRefuse($scope.demographicNo,cancelMsg).then(function(response){
    					console.log("logConsentOverrideCancelRefuse",response);
    					window.close();	
    				},function(reason){
    					alert(reason);
    				});
    				
    			
    			    
    			    
    			    
    			  } 
    		  }
    		  
    		  $scope.refusedBlock = function(){
    			  var refusedReason = prompt("Access to Drug and Pharmacy Service Information has been refused by the patient. \nReason:");

    			  if (refusedReason != null) {
    				  var refusedMsg= {};
    				  refusedMsg.type = 'REFUSED';
    				  refusedMsg.reason = refusedReason;
      		
	    			    dhdrService.logConsentOverrideCancelRefuse($scope.demographicNo,refusedMsg).then(function(response){
	    					console.log("logConsentOverrideCancelRefuse",response);
	    					window.close();	
	    				},function(reason){
	    					alert(reason);
	    				});
    			  }
    		  }
			
    		  $scope.callConsentBlock = function($event){
    				console.log("callConsentBlock");	 
    				dhdrService.getConsentOveride($scope.demographicNo).then(function(response){
    					console.log("response.referenceURL",response);
    					if(response.status == 268){
    						console.log("error ",response.data);
    						alert("Error check the log for more details :\n"+response.data.summary);// response.data);
    						return;
    					}
    					
    					var med = response.data;
    					
    					//window.open(med.referenceURL);  only for testing in chrome
    					
    					
    					var modalInstance = $modal.open({
    		    		      
    		    		      templateUrl: 'pcoi.html',
    		    		      controller: 'PcoiInstanceCtrl',
    		    		      controllerAs: 'mpcoi',
    		    		      parent: angular.element(document.body),
    		    		      size: 'lg',
    		    		      appendTo: $event,
    		    		      resolve: {
    		    		    	  	
    		    		    	  		med: function () {
    		    		          		return med;
    		    		        		}
    		    		      }
    		    		    });
    					//pcoi message back 
    					//message { target: Window, isTrusted: true, data: "{\"status\":\"completed\"}", origin: "https://pcoi-pst.apps.dev.ehealthontario.ca", lastEventId: "", source: Restricted https://pcoi-pst.apps.dev.ehealthontario.ca/main, ports: Restricted, srcElement: Window, currentTarget: Window, eventPhase: 2,  }
    					modalInstance.result.then(function (selectedItem) {
    						console.log("result from pcoi ",selectedItem.data);
    						dhdrService.logConsentOveride($scope.demographicNo,med.uuid,selectedItem.data).then(function(response){
    	    						console.log("logConsentOveride",response);
    	    					});
    						$scope.callSearch();
    		    		    }, function () {
    		    		      console.log('Modal dismissed at: ' + new Date());
    		    		    });
    					
    				},function(reason){
    					alert(reason);
    				});
    				
    		  }
	
			
			
			
		});
		
		function OperationOutcome(operationOutcome){
			
			this.outcomme = operationOutcome;
			this.issues = [];
			
			if(angular.isDefined(this.outcomme.resource) && angular.isDefined(this.outcomme.resource.issue)){
				this.issues = this.outcomme.resource.issue;
			}else if(angular.isDefined(this.outcomme.issue)){
				this.issues = this.outcomme.issue;
			}
				
			
			
		}

		
		function MedicationDispense(medication){
			this.med = medication;
			this.hide = false;
			
			/* uniq value
			 a) Generic name of the dispensed drug [Medication.code.coding[2].display]
			 b) Dispensed drug strength [Medication.extension[1].valueString]
			 c) Drug dosage form (e.g., tablet, capsule, injection) [Medication.form.coding.display]
			*/
			this.getUniqVal = function(){
				 return this.genericName+":"+this.dispensedDrugStrength+":"+this.drugDosageForm;
			 }
			
			this.uniqVal = this.genericName+":"+this.dispensedDrugStrength+":"+this.drugDosageForm;
			 
			 /*
<pre>

Prescriber Information
g) Prescriber ID (e.g., practitioner license or CPSO number) [Practitioner.identifier.value]
h) ID Reference [Practitioner.identifier.system]
Pharmacy Information
i) Pharmacist Name [Practitioner.name.given] [Practitioner.name.family]
j) Pharmacy Phone Number [Organization.telecom[1].value]
</pre>
			 
			 */
			
			if(angular.isDefined(this.med.resource.identifier)){
				for (ident of  this.med.resource.identifier) {
					if(angular.isDefined(ident.value)){
						this.rxNumber = ident.value;			
					}
				}				
			} 
			 
			 /*
			 "extension": [
          {
            "url": "http://ehealthontario.ca/fhir/StructureDefinition/ca-on-medications-ext-refills-remaining",
            "valueInteger": 1
          },
          {
            "url": "http://ehealthontario.ca/fhir/StructureDefinition/ca-on-medications-ext-quantity-remaining",
            "valueQuantity": {
              "value": 120,
              "unit": "tsp",
              "system": "http://snomed.info/sct",
              "code": "SOL"
            }
          }
        ],
        */
			
			if(angular.isDefined(this.med.resource.extension)){
				
			    console.log("this.med.resource.extension",this.med.resource.extension);
				for (ext of  this.med.resource.extension) {
					if(angular.isDefined(ext.url) && ext.url === "http://ehealthontario.ca/fhir/StructureDefinition/ca-on-medications-ext-refills-remaining"){
						
					   console.log("ext.valueInteger",ext.valueInteger);
						this.refillsRemaining = ext.valueInteger;
					}else if(angular.isDefined(ext.url) && ext.url === "http://ehealthontario.ca/fhir/StructureDefinition/ca-on-medications-ext-quantity-remaining"){
						this.quantityRemaining = ext.valueQuantity.value+" "+ext.valueQuantity.unit;
					} 
				}				
			} else {
				console.log("extension not present");
			}
        
			this.whenPrepared = this.med.resource.whenPrepared;
			if(angular.isDefined(this.med.resource.quantity) && angular.isDefined(this.med.resource.quantity.value)){
				this.dispensedQuantity = this.med.resource.quantity.value;
			}
			if(angular.isDefined(this.med.resource.daysSupply) && angular.isDefined(this.med.resource.daysSupply.value)){
				this.estimatedDaysSupply = this.med.resource.daysSupply.value;
			}
			if(angular.isDefined(this.med.resource.reasonCode)){
				this.reasonCode = this.med.resource.reasonCode;
			}
			console.log("dleete me ",this.med);
			if(angular.isDefined(this.med.resource.category)){
				console.log("CATEGORY FOIND !!!!!",this.med.resource.category);
				for(coding of this.med.resource.category.coding) {
					
					if("http://ehealthontario.ca/fhir/NamingSystem/ca-on-medication-dispense-category" === coding.system) {
						this.categoryCode = coding.code;
						this.categoryDisplay = coding.display
					}	
				}				
		
			}
			
			
			for (res of  this.med.resource.contained) {
				
				if(res.resourceType === "Medication") {
					
					if(res.code != null) {
						
						if(angular.isDefined(res.form) && angular.isDefined(res.form.text)){
							this.drugDosageForm = res.form.text	
						}
						
						if(angular.isDefined(res.extension)){
							for(ext of res.extension) {
								if("http://ehealthontario.ca/fhir/StructureDefinition/ca-on-medications-ext-medication-strength" === ext.url){
									this.dispensedDrugStrength = ext.valueString;
								}
							}
						}
				
						
						for(coding of res.code.coding) {
							//{"system": "http://hl7.org/fhir/NamingSystem/ca-hc-din","code": "01916580","display": "Hycodan"
							if("http://hl7.org/fhir/NamingSystem/ca-hc-din" === coding.system) {
								this.brandName = coding;
							}
							//"system": "http://ehealthontario.ca/fhir/NamingSystem/ca-drug-gen-name","display": "HYDROCODONE BITARTRATE"
							if("http://ehealthontario.ca/fhir/NamingSystem/ca-drug-gen-name" === coding.system) {
								this.genericName = coding.display;
							}
				            //"system": "http://ehealthontario.ca/fhir/NamingSystem/ca-on-drug-class-ahfs","code": "480000000","display": "COUGH PREPARATIONS"
				            if("http://ehealthontario.ca/fhir/NamingSystem/ca-on-drug-class-ahfs" === coding.system) {
								this.ahfsClass = coding;
							}
				            //"system": "http://ehealthontario.ca/fhir/NamingSystem/ca-on-drug-subclass-ahfs","code": "480400000","display": "ANTITUSSIVES"\
				            if("http://ehealthontario.ca/fhir/NamingSystem/ca-on-drug-subclass-ahfs" === coding.system) {
								this.ahfsSubClass = coding;
							}
				         
						}
					}else {
						logger.error("was null "+medication);
					}
				
				}else if(res.resourceType ===  "Organization") {
					this.dispensingPharmacy = res.name;
					if(angular.isDefined(res.telecom)){
						for(tele of res.telecom){
							if("fax" === tele.system){
								this.dispensingPharmacyFaxNumber = tele.value;		
							}
							if("phone" === tele.system){
								this.dispensingPharmacyPhoneNumber = tele.value;		
							}
	
						}
					}
				}else if(res.resourceType ===  "MedicationRequest") {
					this.reasonCode = [];
					console.log("reasonCode",res.reasonCode);
					if(angular.isDefined(res.reasonCode)){
						for(code of res.reasonCode){	
							this.reasonCode = code;
						}
					}	
					
				}else if(res.resourceType ==="Practitioner") {
					
					for(identifier of res.identifier) {
						if("https://fhir.infoway-inforoute.ca/NamingSystem/ca-on-license-physician" === identifier.system) {
							/* Does this have a different system value if it's a CPSO value?
							Prescriber Information
							g) Prescriber ID (e.g., practitioner license or CPSO number) [Practitioner.identifier.value]
				h) ID Reference [Practitioner.identifier.system]

							*/							
							this.prescriberLicenceNumber = identifier;
							if(angular.isDefined(res.name)){
								for( humanName of res.name) {
									console.log("humanName",humanName);
									this.prescriberLastname = humanName.family;
									if(angular.isDefined(humanName.given)){
										this.prescriberFirstname = humanName.given[0];
									}
								}
							}
							for(tele of res.telecom){
								if("phone" === tele.system){
									this.prescriberPhoneNumber = tele.value;		
								}
							}
							
							
							console.log("res for telecom ",res);
							//this.prescriberPhoneNumber = res.telecom[0].value);
						}else if("https://fhir.infoway-inforoute.ca/NamingSystem/ca-on-license-pharmacist" === identifier.system) {
							this.pharmacistLicenceNumber = identifier;
							if(angular.isDefined(res.name)){
								for( humanName of res.name) {
									console.log("humanName",humanName);
									this.pharmacistLastname = humanName.family;
									if(angular.isDefined(humanName.given)){
										this.pharmacistFirstname = humanName.given[0];
									}
								}
							}
							
						}else{
							console.log(" not processing "+identifier,res);
						}
							
					}
				}else {
					console.log("resource.getResourceType()",res.resourceType);
				}
				
			}
			
		}
			
		app.controller('ModalInstanceCtrl', function ModalInstanceCtrl($scope, $modal, $modalInstance,med,demoNo,$http){
			$scope.med = med;
			console.log("ModalInstanceCtrl",med);
			
			$scope.cancel = function(){
				
				$modalInstance.close(false);	
			}
			
			$scope.getLicence = function(val){
				if(val == null){
					return "N/A";
				}
				
				if(val.endsWith("ca-on-license-physician")){
					return "College of Physicians and Surgeons of Ontario";
				}else if(val.endsWith("ca-on-license-dental-surgeon")){
					return "Royal College of Dental Surgeons of Ontario";
				}else if(val.endsWith("ca-out-of-province -prescriber")){
					return "Out-of-Province Prescriber";
				}else if(val.endsWith("ca-on-license-chiropodist")){
					return "College of Chiropodists of Ontario";
				}else if(val.endsWith("ca-on-license-midwife")){
					return "College of Midwives of Ontario";
				}else if(val.endsWith("ca-on-license-pharmacist")){
					return "Ontario College of Pharmacists";
				}else if(val.endsWith("ca-on-license-optometrist")){
					return "College of Optometrists of Ontario";
				}else if(val.endsWith("ca-on-license-nurse")){
					return "College of Nurses of Ontario";
				}else if(val.endsWith("ca-on-license-naturopath")){
					return "College of Naturopaths of Ontario";
				}else if(val.endsWith("ca-on-unknown-prescriber")){
					return "Unknown Prescriber";
				}
				return "N/A";
			}
			
			$scope.printDetail = function(){
					console.log("trying to print");
					var toPrint = {};
					toPrint.med = $scope.med;
					
					$http.post('../ws/rs/dhdr/'+demoNo+'/print/detail',toPrint,{ responseType: 'arraybuffer' }).then(function (response) {
						
						console.log("respone for detail print",response);
					       var file = new Blob([response.data], {type: 'application/pdf'});
					       var fileURL = URL.createObjectURL(file);
					       window.open(fileURL);
					}, function(errorMessage) {
						alert("Error getting printout");
						//rxComp.error = errorMessage;
					});	
					//window.open('../ws/rs/dhdr/'+$scope.demographicNo+'/print/summary','_blank');
			
			}
			
		});
		
		app.controller('DrugDupsInstanceCtrl', function ModalInstanceCtrl($scope, $modal, $modalInstance,meds,getDetailView,$http){
			$scope.meds = meds;
			$scope.getDetailView = getDetailView;
			console.log("DrugDupsInstanceCtrl",meds);
			
			$scope.cancel = function(){
				
				$modalInstance.close(false);	
			}
			
			
			
		});
		
		app.controller('PharmaDupsInstanceCtrl', function ModalInstanceCtrl($scope, $modal, $modalInstance,services,getDetailView,$http){
			$scope.services = services;
			$scope.getDetailView = getDetailView;
			console.log("PharmaDupsInstanceCtrl",services);
			
			$scope.cancel = function(){
				
				$modalInstance.close(false);	
			}
			
			
			
		});
		
		
		
		
		app.controller('PcoiInstanceCtrl', function ModalInstanceCtrl($scope, $modal, $modalInstance,med,$sce,$window,$http,$timeout){
			
			$window.addEventListener('message', function(e) {

		        console.log("pcoi message back",e);
		    		$modalInstance.close(e);	

		    });
			
			$scope.showUntilLoaded = true;
			$scope.viewletNotResponding = false;
			

			$timeout(function() {
				$scope.viewletNotResponding = true;
			}, <%=oscar.OscarProperties.getInstance().getProperty("oneid.viewlet.timeout","300000")%>);
			
			
			
			$scope.med = med;
			$scope.pcoiUrl = $sce.trustAsResourceUrl(med.referenceURL);
		
			$scope.reload = function(){
				
				console.log("setting pcoiUrl");
				$scope.pcoiUrl = $sce.trustAsResourceUrl(med.referenceURL);
			}
		
			$scope.loadingResult = function(e){
				$scope.showUntilLoaded = false;
				$scope.$apply();
			}
			console.log("PcoiInstanceCtrl",med);
			
			$scope.cancel = function(){
				
				$modalInstance.close(false);	
			}
		});
		
		app.directive("ngOnload", function elementOnloadDirective() {
	        return {
	            restrict: "A",
	            scope: {
	                callback: "&ngOnload"
	            },
	            link: function link(scope, element, attrs) {
	                // hooking up the onload event - calling the callback on load event
	                element.one("load", function (state,message) {
	                	
	                	console.log("state ",state,message);
	                    var contentLocation = element.length > 0 && element[0].contentWindow ? element[0].contentWindow.location : undefined;
			console.log("onload", element,scope);
	                    scope.callback({
	                        contentLocation: contentLocation
	                    });
	                });
	            }
	        };
	    });
	
		
	</script>
	</body>
</html>	    			