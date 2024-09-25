-- updated to OSCAR 19 spec Feb 2 2021
--
-- Table structure for table `AppDefinition`
--


CREATE TABLE `AppDefinition` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `appType` varchar(255) DEFAULT NULL,
  `config` text,
  `active` tinyint(1) DEFAULT NULL,
  `addedBy` varchar(8) DEFAULT NULL,
  `added` datetime DEFAULT NULL,
  `consentTypeId` int(15) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `AppUser`
--


CREATE TABLE `AppUser` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(8) DEFAULT NULL,
  `appId` int(9) DEFAULT NULL,
  `authenticationData` text,
  `added` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `AppointmentDxLink`
--


CREATE TABLE `AppointmentDxLink` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(6) DEFAULT NULL,
  `code` varchar(20) DEFAULT NULL,
  `codeType` varchar(20) DEFAULT NULL,
  `ageRange` varchar(20) DEFAULT NULL,
  `symbol` varchar(20) DEFAULT NULL,
  `colour` varchar(20) DEFAULT NULL,
  `message` varchar(255) DEFAULT NULL,
  `link` varchar(255) DEFAULT NULL,
  `updateDate` datetime DEFAULT NULL,
  `createDate` datetime DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `code` (`code`)
);

--
-- Table structure for table `AppointmentSearch`
--


CREATE TABLE `AppointmentSearch` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(6) DEFAULT NULL,
  `searchType` varchar(100) DEFAULT NULL,
  `searchName` varchar(100) DEFAULT NULL,
  `fileContents` mediumblob,
  `updateDate` datetime DEFAULT NULL,
  `createDate` datetime DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `uuid` char(40) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `providerNo` (`providerNo`),
  KEY `uuid` (`uuid`)
);

--
-- Table structure for table `BORNPathwayMapping`
--


CREATE TABLE `BORNPathwayMapping` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `bornPathway` varchar(100) DEFAULT NULL,
  `serviceId` int(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `BornTransmissionLog`
--


CREATE TABLE `BornTransmissionLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `submitDateTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `success` tinyint(1) DEFAULT '0',
  `filename` varchar(100) DEFAULT NULL,
  `demographicNo` int(11) DEFAULT NULL,
  `type` varchar(20) DEFAULT NULL,
  `httpCode` varchar(20) DEFAULT NULL,
  `httpResult` mediumtext,
  `httpHeaders` text,
  `hialTransactionId` varchar(255) DEFAULT NULL,
  `contentLocation` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `CVCImmunization`
--


CREATE TABLE `CVCImmunization` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `versionId` int(11) DEFAULT NULL,
  `snomedConceptId` varchar(255) DEFAULT NULL,
  `displayName` varchar(255) DEFAULT NULL,
  `picklistName` varchar(255) DEFAULT NULL,
  `generic` tinyint(1) DEFAULT NULL,
  `prevalence` int(11) DEFAULT NULL,
  `parentConceptId` varchar(255) DEFAULT NULL,
  `ispa` tinyint(1) DEFAULT NULL,
  `typicalDose` varchar(255) DEFAULT NULL,
  `typicalDoseUofM` varchar(255) DEFAULT NULL,
  `route` varchar(10) DEFAULT NULL,
  `strength` varchar(255) DEFAULT NULL,
  `shelfStatus` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `CVCImmunizationName`
--


CREATE TABLE `CVCImmunizationName` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `language` varchar(30) DEFAULT NULL,
  `useSystem` varchar(255) DEFAULT NULL,
  `useCode` varchar(255) DEFAULT NULL,
  `useDisplay` varchar(255) DEFAULT NULL,
  `value` varchar(255) DEFAULT NULL,
  `CVCImmunizationId` varchar(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `CVCMapping`
--


CREATE TABLE `CVCMapping` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `oscarName` varchar(255) DEFAULT NULL,
  `cvcSnomedId` varchar(255) DEFAULT NULL,
  `preferCVC` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `CVCMedication`
--


CREATE TABLE `CVCMedication` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `versionId` int(11) DEFAULT NULL,
  `din` int(11) DEFAULT NULL,
  `dinDisplayName` varchar(255) DEFAULT NULL,
  `snomedCode` varchar(255) DEFAULT NULL,
  `snomedDisplay` varchar(255) DEFAULT NULL,
  `status` varchar(40) DEFAULT NULL,
  `isBrand` tinyint(1) DEFAULT NULL,
  `manufacturerId` int(11) DEFAULT NULL,
  `manufacturerDisplay` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `CVCMedicationGTIN`
--


CREATE TABLE `CVCMedicationGTIN` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cvcMedicationId` int(11) NOT NULL,
  `gtin` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `CVCMedicationLotNumber`
--


CREATE TABLE `CVCMedicationLotNumber` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cvcMedicationId` int(11) NOT NULL,
  `lotNumber` varchar(255) NOT NULL,
  `expiryDate` date DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `Consent`
--


CREATE TABLE `Consent` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `consent_type_id` int(10) DEFAULT NULL,
  `explicit` tinyint(1) DEFAULT NULL,
  `optout` tinyint(1) DEFAULT NULL,
  `last_entered_by` varchar(10) DEFAULT NULL,
  `consent_date` datetime DEFAULT NULL,
  `optout_date` datetime DEFAULT NULL,
  `edit_date` datetime DEFAULT NULL,
  `deleted` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `Contact`
--


CREATE TABLE `Contact` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(20) DEFAULT NULL,
  `lastName` varchar(100) DEFAULT NULL,
  `firstName` varchar(100) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `address2` varchar(255) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `province` varchar(25) DEFAULT NULL,
  `country` varchar(25) DEFAULT NULL,
  `postal` varchar(25) DEFAULT NULL,
  `residencePhone` varchar(30) DEFAULT NULL,
  `cellPhone` varchar(30) DEFAULT NULL,
  `workPhone` varchar(30) DEFAULT NULL,
  `workPhoneExtension` varchar(10) DEFAULT NULL,
  `email` varchar(50) DEFAULT NULL,
  `fax` varchar(30) DEFAULT NULL,
  `note` text,
  `specialty` varchar(255) DEFAULT NULL,
  `cpso` varchar(10) DEFAULT NULL,
  `systemId` varchar(30) DEFAULT NULL,
  `deleted` tinyint(4) DEFAULT NULL,
  `updateDate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `type` (`type`),
  KEY `cpso` (`cpso`),
  KEY `systemId` (`systemId`)
);

--
-- Table structure for table `ContactSpecialty`
--


CREATE TABLE `ContactSpecialty` (
  `id` int(11) NOT NULL,
  `specialty` varchar(50) NOT NULL,
  `description` varchar(140) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `CtlRelationships`
--


CREATE TABLE `CtlRelationships` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` varchar(50) NOT NULL,
  `label` varchar(255) DEFAULT NULL,
  `active` tinyint(1) NOT NULL,
  `maleInverse` varchar(50) DEFAULT NULL,
  `femaleInverse` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DHIRSubmissionLog`
--


CREATE TABLE `DHIRSubmissionLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographicNo` int(11) DEFAULT NULL,
  `preventionId` int(11) DEFAULT NULL,
  `submitterProviderNo` varchar(255) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `dateCreated` datetime DEFAULT NULL,
  `transactionId` varchar(100) DEFAULT NULL,
  `bundleId` varchar(255) DEFAULT NULL,
  `response` mediumtext,
  `clientRequestId` varchar(100) DEFAULT NULL,
  `clientResponseId` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DHIRTransactionLog`
--


CREATE TABLE `DHIRTransactionLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `started` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `initiatingProviderNo` varchar(25) DEFAULT NULL,
  `transactionType` varchar(25) DEFAULT NULL,
  `externalSystem` varchar(50) DEFAULT NULL,
  `demographicNo` int(10) DEFAULT NULL,
  `resultCode` int(10) DEFAULT NULL,
  `success` tinyint(1) DEFAULT NULL,
  `error` mediumtext,
  `headers` mediumtext,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DemographicContact`
--


CREATE TABLE `DemographicContact` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updateDate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `deleted` tinyint(4) DEFAULT NULL,
  `demographicNo` int(11) DEFAULT NULL,
  `contactId` varchar(100) DEFAULT NULL,
  `role` varchar(100) DEFAULT NULL,
  `type` int(11) DEFAULT NULL,
  `sdm` varchar(25) DEFAULT NULL,
  `ec` varchar(25) DEFAULT NULL,
  `category` varchar(100) DEFAULT NULL,
  `note` varchar(200) DEFAULT NULL,
  `facilityId` int(11) NOT NULL,
  `creator` varchar(20) NOT NULL,
  `consentToContact` tinyint(1) DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `mrp` tinyint(1) DEFAULT NULL,
  `best_contact` varchar(30) DEFAULT NULL,
  `health_care_team` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `demographicNo` (`demographicNo`)
);

--
-- Table structure for table `Department`
--


CREATE TABLE `Department` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `annotation` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DocumentExtraReviewer`
--


CREATE TABLE `DocumentExtraReviewer` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `documentNo` int(11) DEFAULT NULL,
  `reviewerProviderNo` varchar(40) DEFAULT NULL,
  `reviewDateTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DrugDispensing`
--


CREATE TABLE `DrugDispensing` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `drugId` int(9) DEFAULT NULL,
  `dateCreated` datetime DEFAULT NULL,
  `productId` int(9) DEFAULT NULL,
  `quantity` int(9) DEFAULT NULL,
  `unit` varchar(20) DEFAULT NULL,
  `dispensingProviderNo` varchar(20) DEFAULT NULL,
  `providerNo` varchar(20) DEFAULT NULL,
  `paidFor` tinyint(1) DEFAULT NULL,
  `notes` text,
  `programNo` int(11) DEFAULT NULL,
  `archived` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DrugDispensingMapping`
--


CREATE TABLE `DrugDispensingMapping` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `din` varchar(50) DEFAULT NULL,
  `duration` varchar(255) DEFAULT NULL,
  `durUnit` char(1) DEFAULT NULL,
  `freqCode` varchar(6) DEFAULT NULL,
  `quantity` varchar(20) DEFAULT NULL,
  `takeMin` float DEFAULT NULL,
  `takeMax` float DEFAULT NULL,
  `productCode` varchar(255) DEFAULT NULL,
  `dateCreated` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DrugProduct`
--


CREATE TABLE `DrugProduct` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `code` varchar(255) DEFAULT NULL,
  `lotNumber` varchar(255) DEFAULT NULL,
  `dispensingEvent` int(9) DEFAULT NULL,
  `amount` int(11) NOT NULL,
  `expiryDate` date DEFAULT NULL,
  `location` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `DrugProductTemplate`
--


CREATE TABLE `DrugProductTemplate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `code` varchar(255) DEFAULT NULL,
  `amount` int(11) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EFormDocs`
--


CREATE TABLE `EFormDocs` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `fdid` int(10) NOT NULL,
  `document_no` int(10) NOT NULL,
  `doctype` char(1) NOT NULL,
  `deleted` char(1) DEFAULT NULL,
  `attach_date` date DEFAULT NULL,
  `provider_no` varchar(6) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EFormReportTool`
--


CREATE TABLE `EFormReportTool` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tableName` varchar(255) NOT NULL,
  `eformId` int(11) NOT NULL,
  `expiryDate` datetime DEFAULT NULL,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `providerNo` varchar(6) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `dateLastPopulated` timestamp NULL DEFAULT NULL,
  `latestMarked` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `Episode`
--


CREATE TABLE `Episode` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographicNo` int(11) NOT NULL,
  `startDate` date NOT NULL,
  `endDate` date DEFAULT NULL,
  `code` varchar(50) DEFAULT NULL,
  `codingSystem` varchar(50) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `status` varchar(25) DEFAULT NULL,
  `lastUpdateUser` varchar(25) NOT NULL,
  `lastUpdateTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `notes` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `Eyeform`
--


CREATE TABLE `Eyeform` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `appointment_no` int(11) DEFAULT NULL,
  `discharge` varchar(20) DEFAULT NULL,
  `stat` varchar(20) DEFAULT NULL,
  `opt` varchar(20) DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EyeformConsultationReport`
--


CREATE TABLE `EyeformConsultationReport` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `date` datetime DEFAULT NULL,
  `referralId` int(11) DEFAULT NULL,
  `greeting` int(11) DEFAULT NULL,
  `appointmentNo` int(11) DEFAULT NULL,
  `appointmentDate` date DEFAULT NULL,
  `appointmentTime` time DEFAULT NULL,
  `demographicNo` int(11) DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `type` varchar(255) DEFAULT NULL,
  `cc` varchar(255) DEFAULT NULL,
  `memo` varchar(255) DEFAULT NULL,
  `clinicalInfo` text,
  `currentMeds` text,
  `allergies` text,
  `providerNo` varchar(20) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `sendTo` varchar(255) DEFAULT NULL,
  `examination` text,
  `concurrentProblems` text,
  `impression` text,
  `plan` text,
  `urgency` varchar(100) DEFAULT NULL,
  `patientWillBook` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EyeformFollowUp`
--


CREATE TABLE `EyeformFollowUp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `appointment_no` int(11) DEFAULT NULL,
  `demographic_no` int(11) DEFAULT NULL,
  `timespan` int(11) DEFAULT NULL,
  `timeframe` varchar(25) DEFAULT NULL,
  `followup_provider` varchar(100) DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `type` varchar(25) DEFAULT NULL,
  `urgency` varchar(50) DEFAULT NULL,
  `comment` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EyeformMacro`
--


CREATE TABLE `EyeformMacro` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `label` varchar(255) NOT NULL,
  `displayOrder` int(10) NOT NULL,
  `impression` text,
  `followupNo` smallint(5) DEFAULT NULL,
  `followupUnit` varchar(50) DEFAULT NULL,
  `followupDoctor` varchar(6) DEFAULT NULL,
  `followupReason` varchar(255) DEFAULT NULL,
  `ticklerStaff` varchar(6) DEFAULT NULL,
  `billingVisitType` varchar(50) DEFAULT NULL,
  `billingVisitLocation` varchar(50) DEFAULT NULL,
  `billingCodes` text,
  `billingDxcode` varchar(50) DEFAULT NULL,
  `billingTotal` varchar(50) DEFAULT NULL,
  `billingComment` varchar(255) DEFAULT NULL,
  `billingBilltype` varchar(50) DEFAULT NULL,
  `billingPayMethod` varchar(50) DEFAULT NULL,
  `billingBillto` varchar(50) DEFAULT NULL,
  `billingRemitto` varchar(50) DEFAULT NULL,
  `billingGstBilledTotal` varchar(50) DEFAULT NULL,
  `billingPayment` varchar(50) DEFAULT NULL,
  `billingRefund` varchar(50) DEFAULT NULL,
  `billingGst` varchar(50) DEFAULT NULL,
  `testRecords` text,
  `dischargeFlag` varchar(20) DEFAULT NULL,
  `statFlag` varchar(20) DEFAULT NULL,
  `optFlag` varchar(20) DEFAULT NULL,
  `sliCode` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EyeformOcularProcedure`
--


CREATE TABLE `EyeformOcularProcedure` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographicNo` int(11) NOT NULL,
  `provider` varchar(60) DEFAULT NULL,
  `date` date NOT NULL,
  `eye` varchar(2) NOT NULL,
  `procedureName` varchar(100) NOT NULL,
  `procedureType` varchar(30) DEFAULT NULL,
  `procedureNote` text,
  `doctor` varchar(30) DEFAULT NULL,
  `location` varchar(30) DEFAULT NULL,
  `updateTime` datetime DEFAULT NULL,
  `status` varchar(2) DEFAULT NULL,
  `appointmentNo` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EyeformProcedureBook`
--


CREATE TABLE `EyeformProcedureBook` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `eyeform_id` bigint(20) DEFAULT NULL,
  `demographic_no` int(11) DEFAULT NULL,
  `appointment_no` int(11) DEFAULT NULL,
  `provider` varchar(60) DEFAULT NULL,
  `procedure_name` varchar(30) DEFAULT NULL,
  `eye` varchar(20) DEFAULT NULL,
  `location` varchar(50) DEFAULT NULL,
  `urgency` varchar(10) DEFAULT NULL,
  `comment` text,
  `date` datetime DEFAULT NULL,
  `status` varchar(2) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EyeformSpecsHistory`
--


CREATE TABLE `EyeformSpecsHistory` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographicNo` int(11) NOT NULL,
  `provider` varchar(60) DEFAULT NULL,
  `date` date DEFAULT NULL,
  `doctor` varchar(30) DEFAULT NULL,
  `type` varchar(30) DEFAULT NULL,
  `odSph` varchar(10) DEFAULT NULL,
  `odCyl` varchar(10) DEFAULT NULL,
  `odAxis` varchar(10) DEFAULT NULL,
  `odAdd` varchar(10) DEFAULT NULL,
  `odPrism` varchar(10) DEFAULT NULL,
  `osSph` varchar(10) DEFAULT NULL,
  `osCyl` varchar(10) DEFAULT NULL,
  `osAxis` varchar(10) DEFAULT NULL,
  `osAdd` varchar(10) DEFAULT NULL,
  `osPrism` varchar(10) DEFAULT NULL,
  `updateTime` datetime DEFAULT NULL,
  `status` varchar(2) DEFAULT NULL,
  `appointmentNo` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `EyeformTestBook`
--


CREATE TABLE `EyeformTestBook` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `testname` varchar(60) DEFAULT NULL,
  `appointment_no` int(11) DEFAULT NULL,
  `demographic_no` int(11) DEFAULT NULL,
  `provider` varchar(60) DEFAULT NULL,
  `eyeform_id` bigint(20) DEFAULT NULL,
  `eye` varchar(20) DEFAULT NULL,
  `urgency` varchar(30) DEFAULT NULL,
  `comment` varchar(100) DEFAULT NULL,
  `date` datetime DEFAULT NULL,
  `status` varchar(2) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `Facility`
--


CREATE TABLE `Facility` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` varchar(150) DEFAULT NULL,
  `contactName` varchar(255) DEFAULT NULL,
  `contactEmail` varchar(255) DEFAULT NULL,
  `contactPhone` varchar(255) DEFAULT NULL,
  `hic` tinyint(1) NOT NULL,
  `disabled` tinyint(1) NOT NULL,
  `orgId` int(11) NOT NULL,
  `sectorId` int(11) NOT NULL,
  `integratorEnabled` tinyint(1) NOT NULL,
  `integratorUrl` varchar(255) DEFAULT NULL,
  `integratorUser` varchar(255) DEFAULT NULL,
  `integratorPassword` varchar(255) DEFAULT NULL,
  `enableIntegratedReferrals` tinyint(1) NOT NULL,
  `enableHealthNumberRegistry` tinyint(1) NOT NULL,
  `allowSims` tinyint(1) unsigned NOT NULL,
  `enableDigitalSignatures` tinyint(1) NOT NULL,
  `ocanServiceOrgNumber` int(10) NOT NULL,
  `enableOcanForms` tinyint(1) NOT NULL,
  `enableCbiForm` tinyint(1) NOT NULL,
  `enableAnonymous` tinyint(1) unsigned NOT NULL,
  `enablePhoneEncounter` tinyint(1) unsigned NOT NULL,
  `enableGroupNotes` tinyint(1) unsigned NOT NULL,
  `lastUpdated` datetime NOT NULL,
  `enableEncounterTime` tinyint(1) NOT NULL,
  `enableEncounterTransportationTime` tinyint(1) NOT NULL,
  `registrationIntake` int(8) DEFAULT NULL,
  `rxInteractionWarningLevel` int(10) NOT NULL,
  `displayAllVacancies` int(1) NOT NULL,
  `vacancyWithdrawnTicklerProvider` varchar(25) DEFAULT NULL,
  `vacancyWithdrawnTicklerDemographic` int(10) DEFAULT NULL,
  `assignNewVacancyTicklerProvider` varchar(25) DEFAULT NULL,
  `assignNewVacancyTicklerDemographic` int(10) DEFAULT NULL,
  `assignRejectedVacancyApplicant` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
);

--
-- Table structure for table `FaxClientLog`
--


CREATE TABLE `FaxClientLog` (
  `faxLogId` int(9) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `startTime` datetime DEFAULT NULL,
  `endTime` datetime DEFAULT NULL,
  `result` varchar(255) DEFAULT NULL,
  `requestId` varchar(10) DEFAULT NULL,
  `faxId` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`faxLogId`)
);

--
-- Table structure for table `FlowSheetUserCreated`
--


CREATE TABLE `FlowSheetUserCreated` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(4) DEFAULT NULL,
  `dxcodeTriggers` varchar(255) DEFAULT NULL,
  `displayName` varchar(255) DEFAULT NULL,
  `warningColour` varchar(20) DEFAULT NULL,
  `recommendationColour` varchar(20) DEFAULT NULL,
  `topHTML` text,
  `archived` tinyint(1) DEFAULT NULL,
  `createdDate` date DEFAULT NULL,
  `createdBy` varchar(100) DEFAULT NULL,
  `scope` varchar(100) DEFAULT NULL,
  `scopeProviderNo` varchar(100) DEFAULT NULL,
  `scopeDemographicNo` int(10) DEFAULT NULL,
  `template` varchar(100) DEFAULT NULL,
  `xmlContent` text,
  PRIMARY KEY (`id`),
  KEY `FlowSheetUserCreated_archived` (`archived`)
);

--
-- Table structure for table `Flowsheet`
--


CREATE TABLE `Flowsheet` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(25) DEFAULT NULL,
  `content` text,
  `enabled` tinyint(1) DEFAULT NULL,
  `external` tinyint(1) DEFAULT NULL,
  `createdDate` date DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HL7HandlerMSHMapping`
--


CREATE TABLE `HL7HandlerMSHMapping` (
  `id` int(50) NOT NULL AUTO_INCREMENT,
  `hospital_site` varchar(255) DEFAULT NULL,
  `facility` varchar(100) DEFAULT NULL,
  `facility_name` varchar(255) DEFAULT NULL,
  `notes` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HRMCategory`
--


CREATE TABLE `HRMCategory` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `categoryName` varchar(255) NOT NULL,
  `subClassNameMnemonic` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HRMDocument`
--


CREATE TABLE `HRMDocument` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `timeReceived` datetime DEFAULT NULL,
  `reportType` varchar(50) DEFAULT NULL,
  `reportHash` varchar(64) DEFAULT NULL,
  `reportLessTransactionInfoHash` varchar(64) DEFAULT NULL,
  `reportStatus` varchar(10) DEFAULT NULL,
  `reportFile` varchar(255) DEFAULT NULL,
  `unmatchedProviders` varchar(255) DEFAULT NULL,
  `numDuplicatesReceived` int(11) DEFAULT NULL,
  `reportDate` datetime DEFAULT NULL,
  `parentReport` int(11) DEFAULT NULL,
  `reportLessDemographicInfoHash` varchar(64) DEFAULT NULL,
  `sourceFacility` varchar(120) DEFAULT NULL,
  `hrmCategoryId` int(11) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `formattedName` varchar(100) DEFAULT NULL,
  `dob` varchar(10) DEFAULT NULL,
  `gender` varchar(1) DEFAULT NULL,
  `hcn` varchar(20) DEFAULT NULL,
  `recipientId` varchar(15) DEFAULT NULL,
  `recipientName` varchar(255) DEFAULT NULL,
  `recipientProviderNo` varchar(25) DEFAULT NULL,
  `className` varchar(255) DEFAULT NULL,
  `subClassName` varchar(255) DEFAULT NULL,
  `sourceFacilityReportNo` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HRMDocumentComment`
--


CREATE TABLE `HRMDocumentComment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(20) DEFAULT NULL,
  `hrmDocumentId` int(11) DEFAULT NULL,
  `comment` text,
  `commentTime` datetime DEFAULT NULL,
  `deleted` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HRMDocumentSubClass`
--


CREATE TABLE `HRMDocumentSubClass` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hrmDocumentId` int(11) DEFAULT NULL,
  `subClass` varchar(50) DEFAULT NULL,
  `subClassMnemonic` varchar(50) DEFAULT NULL,
  `subClassDescription` varchar(255) DEFAULT NULL,
  `subClassDateTime` date DEFAULT NULL,
  `isActive` tinyint(4) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HRMDocumentToDemographic`
--


CREATE TABLE `HRMDocumentToDemographic` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographicNo` varchar(20) DEFAULT NULL,
  `hrmDocumentId` varchar(20) DEFAULT NULL,
  `timeAssigned` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HRMDocumentToProvider`
--


CREATE TABLE `HRMDocumentToProvider` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(20) DEFAULT NULL,
  `hrmDocumentId` varchar(20) DEFAULT NULL,
  `signedOff` int(11) DEFAULT NULL,
  `signedOffTimestamp` datetime DEFAULT NULL,
  `viewed` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HRMProviderConfidentialityStatement`
--


CREATE TABLE `HRMProviderConfidentialityStatement` (
  `providerNo` varchar(20) NOT NULL DEFAULT '',
  `statement` text,
  PRIMARY KEY (`providerNo`)
);

--
-- Table structure for table `HRMSubClass`
--


CREATE TABLE `HRMSubClass` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `className` varchar(255) DEFAULT NULL,
  `subClassName` varchar(255) DEFAULT NULL,
  `subClassMnemonic` varchar(255) DEFAULT NULL,
  `subClassDescription` varchar(255) DEFAULT NULL,
  `sendingFacilityId` varchar(50) NOT NULL,
  `hrmCategoryId` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HrmLog`
--


CREATE TABLE `HrmLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `started` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `initiatingProviderNo` varchar(25) DEFAULT NULL,
  `transactionType` varchar(25) DEFAULT NULL,
  `externalSystem` varchar(50) DEFAULT NULL,
  `error` varchar(255) DEFAULT NULL,
  `connected` tinyint(1) DEFAULT NULL,
  `downloadedFiles` tinyint(1) DEFAULT NULL,
  `numFilesDownloaded` int(11) DEFAULT NULL,
  `deleted` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `HrmLogEntry`
--


CREATE TABLE `HrmLogEntry` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hrmLogId` int(11) DEFAULT NULL,
  `encryptedFileName` varchar(255) DEFAULT NULL,
  `decrypted` tinyint(1) DEFAULT NULL,
  `decryptedFileName` varchar(255) DEFAULT NULL,
  `filename` varchar(255) DEFAULT NULL,
  `error` varchar(255) DEFAULT NULL,
  `parsed` tinyint(1) DEFAULT NULL,
  `recipientId` varchar(100) DEFAULT NULL,
  `recipientName` varchar(255) DEFAULT NULL,
  `distributed` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ISO36612`
--


CREATE TABLE `ISO36612` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code` varchar(255) DEFAULT NULL,
  `province` varchar(255) DEFAULT NULL,
  `country` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `Icd9Synonym`
--


CREATE TABLE `Icd9Synonym` (
  `dxCode` varchar(10) NOT NULL,
  `patientFriendly` varchar(250) NOT NULL,
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `IndicatorResultItem`
--


CREATE TABLE `IndicatorResultItem` (
    `id` int(11) auto_increment,
    `providerNo` varchar(30),
    `timeGenerated` timestamp,
    `indicatorTemplateId` int,
    `label` varchar(255),
    `result` float,
    PRIMARY KEY(`id`)
);

--
-- Table structure for table `Institution`
--


CREATE TABLE `Institution` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `address` varchar(255) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `province` varchar(100) DEFAULT NULL,
  `postal` varchar(10) DEFAULT NULL,
  `country` varchar(25) DEFAULT NULL,
  `phone` varchar(25) DEFAULT NULL,
  `fax` varchar(25) DEFAULT NULL,
  `website` varchar(100) DEFAULT NULL,
  `email` varchar(50) DEFAULT NULL,
  `annotation` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `InstitutionDepartment`
--


CREATE TABLE `InstitutionDepartment` (
  `institutionId` int(11) NOT NULL,
  `departmentId` int(11) NOT NULL,
  PRIMARY KEY (`institutionid`)
);

--
-- Table structure for table `IntegratorFileLog`
--


CREATE TABLE `IntegratorFileLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filename` varchar(255) DEFAULT NULL,
  `checksum` varchar(255) DEFAULT NULL,
  `lastDateUpdated` datetime DEFAULT NULL,
  `currentDate` datetime DEFAULT NULL,
  `integratorStatus` varchar(100) DEFAULT NULL,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `IntegratorProgress`
--


CREATE TABLE `IntegratorProgress` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `status` varchar(50) DEFAULT NULL,
  `errorMessage` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`)
);

--
-- Table structure for table `IntegratorProgressItem`
--


CREATE TABLE `IntegratorProgressItem` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographicNo` int(11) NOT NULL,
  `integratorProgressId` int(11) NOT NULL,
  `dateUpdated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `status` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_id` (`integratorProgressId`),
  KEY `idx_status` (`status`)
);

--
-- Table structure for table `IssueGroup`
--


CREATE TABLE `IssueGroup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `IssueGroupIssues`
--


CREATE TABLE `IssueGroupIssues` (
  `issueGroupId` int(11) NOT NULL,
  `issue_id` int(11) NOT NULL,
  UNIQUE KEY `issueGroupId` (`issueGroupId`,`issue_id`),
  KEY `issue_id` (`issue_id`)
);

--
-- Table structure for table `LookupList`
--


CREATE TABLE `LookupList` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `listTitle` varchar(50) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `categoryId` int(11) DEFAULT NULL,
  `active` tinyint(1) NOT NULL,
  `createdBy` varchar(8) NOT NULL,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `LookupListItem`
--


CREATE TABLE `LookupListItem` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `lookupListId` int(11) NOT NULL,
  `value` varchar(50) NOT NULL,
  `label` varchar(255) DEFAULT NULL,
  `displayOrder` int(11) NOT NULL,
  `active` tinyint(1) NOT NULL,
  `createdBy` varchar(8) NOT NULL,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `MyGroupAccessRestriction`
--


CREATE TABLE `MyGroupAccessRestriction` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `myGroupNo` varchar(50) NOT NULL,
  `providerNo` varchar(20) NOT NULL,
  `lastUpdateUser` varchar(20) DEFAULT NULL,
  `lastUpdateDate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `myGroupNo` (`myGroupNo`),
  KEY `myGroupNo_2` (`myGroupNo`,`providerNo`)
);

--
-- Table structure for table `OLISQueryLog`
--


CREATE TABLE `OLISQueryLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `initiatingProviderNo` varchar(30) DEFAULT NULL,
  `queryType` varchar(20) DEFAULT NULL,
  `queryExecutionDate` datetime DEFAULT NULL,
  `uuid` varchar(255) DEFAULT NULL,
  `requestingHIC` varchar(30) DEFAULT NULL,
  `demographicNo` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `OLISResults`
--


CREATE TABLE `OLISResults` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `requestingHICProviderNo` varchar(30) DEFAULT NULL,
  `providerNo` varchar(30) DEFAULT NULL,
  `queryType` varchar(20) DEFAULT NULL,
  `results` text,
  `hash` varchar(255) DEFAULT NULL,
  `status` varchar(10) DEFAULT NULL,
  `uuid` varchar(255) DEFAULT NULL,
  `query` varchar(255) DEFAULT NULL,
  `demographicNo` int(11) DEFAULT NULL,
  `queryUuid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ORNCkdScreeningReportLog`
--


CREATE TABLE `ORNCkdScreeningReportLog` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(10) NOT NULL,
  `reportData` text NOT NULL,
  `lastUpdateDate` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ORNPreImplementationReportLog`
--


CREATE TABLE `ORNPreImplementationReportLog` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(10) NOT NULL,
  `reportData` text NOT NULL,
  `lastUpdateDate` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `OscarCode`
--


CREATE TABLE `OscarCode` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `OscarCode` varchar(25) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `OscarJob`
--


CREATE TABLE `OscarJob` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `oscarJobTypeId` int(11) DEFAULT NULL,
  `cronExpression` varchar(255) DEFAULT NULL,
  `providerNo` varchar(10) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL,
  `updated` datetime NOT NULL,
  `config` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `OscarJobType`
--


CREATE TABLE `OscarJobType` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `className` varchar(255) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL,
  `updated` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `PHRVerification`
--


CREATE TABLE `PHRVerification` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographicNo` int(10) DEFAULT NULL,
  `phrUserName` varchar(255) DEFAULT NULL,
  `verificationLevel` varchar(100) DEFAULT NULL,
  `verificationDate` datetime DEFAULT NULL,
  `verificationBy` varchar(6) DEFAULT NULL,
  `photoId` tinyint(1) DEFAULT NULL,
  `parentGuardian` tinyint(1) DEFAULT NULL,
  `comments` text,
  `createdDate` datetime DEFAULT NULL,
  `archived` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `PHRVerification_archived` (`archived`)
);

--
-- Table structure for table `PageMonitor`
--


CREATE TABLE `PageMonitor` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pageName` varchar(100) NOT NULL,
  `pageId` varchar(255) NOT NULL,
  `session` varchar(100) DEFAULT NULL,
  `remoteAddr` varchar(20) DEFAULT NULL,
  `locked` tinyint(1) DEFAULT NULL,
  `updateDate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `timeout` int(10) DEFAULT NULL,
  `providerNo` varchar(10) DEFAULT NULL,
  `providerName` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `PreventionReport`
--


CREATE TABLE `PreventionReport` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(6) DEFAULT NULL,
  `reportName` varchar(255) DEFAULT NULL,
  `json` text,
  `updateDate` datetime DEFAULT NULL,
  `createDate` datetime DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `archived` tinyint(1) DEFAULT NULL,
  `uuid` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `PreventionsLotNrs`
--


CREATE TABLE `PreventionsLotNrs` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `creationDate` datetime DEFAULT NULL,
  `providerNo` varchar(6) NOT NULL,
  `preventionType` varchar(20) NOT NULL,
  `lotNr` text NOT NULL,
  `deleted` tinyint(1) NOT NULL,
  `lastUpdateDate` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `PrintResourceLog`
--


CREATE TABLE `PrintResourceLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `resourceName` varchar(100) NOT NULL,
  `resourceId` varchar(50) NOT NULL,
  `dateTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `providerNo` varchar(10) DEFAULT NULL,
  `externalLocation` varchar(200) DEFAULT NULL,
  `externalMethod` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ProductLocation`
--


CREATE TABLE `ProductLocation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ProviderPreference`
--


CREATE TABLE `ProviderPreference` (
  `providerNo` varchar(6) NOT NULL,
  `startHour` tinyint(4) DEFAULT NULL,
  `endHour` tinyint(4) DEFAULT NULL,
  `everyMin` tinyint(4) DEFAULT NULL,
  `myGroupNo` varchar(10) DEFAULT NULL,
  `colourTemplate` varchar(10) DEFAULT NULL,
  `newTicklerWarningWindow` varchar(10) DEFAULT NULL,
  `defaultServiceType` varchar(10) DEFAULT NULL,
  `defaultCaisiPmm` varchar(10) DEFAULT NULL,
  `defaultNewOscarCme` varchar(10) DEFAULT NULL,
  `printQrCodeOnPrescriptions` tinyint(4) NOT NULL,
  `lastUpdated` datetime NOT NULL,
  `appointmentScreenLinkNameDisplayLength` int(11) NOT NULL,
  `defaultDoNotDeleteBilling` tinyint(1) NOT NULL,
  `defaultDxCode` varchar(4) DEFAULT NULL,
  `eRxEnabled` tinyint(1) NOT NULL,
  `eRx_SSO_URL` varchar(128) DEFAULT NULL,
  `eRxUsername` varchar(32) DEFAULT NULL,
  `eRxPassword` varchar(64) DEFAULT NULL,
  `eRxFacility` varchar(32) DEFAULT NULL,
  `eRxTrainingMode` tinyint(1) NOT NULL,
  `encryptedMyOscarPassword` varbinary(255) DEFAULT NULL,
  PRIMARY KEY (`providerNo`)
);

--
-- Table structure for table `ProviderPreferenceAppointmentScreenEForm`
--


CREATE TABLE `ProviderPreferenceAppointmentScreenEForm` (
  `providerNo` varchar(6) NOT NULL,
  `appointmentScreenEForm` int(11) NOT NULL,
  PRIMARY KEY (`providerNo`)
);

--
-- Table structure for table `ProviderPreferenceAppointmentScreenForm`
--


CREATE TABLE `ProviderPreferenceAppointmentScreenForm` (
  `providerNo` varchar(6) NOT NULL,
  `appointmentScreenForm` varchar(128) NOT NULL,
  PRIMARY KEY (`providerNo`)
);

--
-- Table structure for table `ProviderPreferenceAppointmentScreenQuickLink`
--


CREATE TABLE `ProviderPreferenceAppointmentScreenQuickLink` (
  `providerNo` varchar(6) NOT NULL,
  `name` varchar(64) NOT NULL,
  `url` varchar(255) NOT NULL,
  PRIMARY KEY (`providerNo`)
);

--
-- Table structure for table `RemoteDataLog`
--


CREATE TABLE `RemoteDataLog` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(255) NOT NULL,
  `actionDate` datetime NOT NULL,
  `action` varchar(32) NOT NULL,
  `documentId` varchar(255) NOT NULL,
  `documentContents` blob NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `RemoteIntegratedDataCopy`
--


CREATE TABLE `RemoteIntegratedDataCopy` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `datatype` varchar(255) DEFAULT NULL,
  `data` longtext,
  `lastUpdateDate` datetime DEFAULT NULL,
  `signature` varchar(255) DEFAULT NULL,
  `facilityId` int(11) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `archived` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `RemoteReferral`
--


CREATE TABLE `RemoteReferral` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `facilityId` int(11) NOT NULL,
  `demographicId` int(11) NOT NULL,
  `referringProviderNo` varchar(6) NOT NULL,
  `referredToFacilityName` varchar(255) NOT NULL,
  `referredToProgramName` varchar(255) NOT NULL,
  `referalDate` datetime NOT NULL,
  `reasonForReferral` varchar(255) DEFAULT NULL,
  `presentingProblem` varchar(255) DEFAULT NULL,
  `createDate` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `facilityId` (`facilityId`),
  KEY `demographicId` (`demographicId`)
);

--
-- Table structure for table `ResourceStorage`
--


CREATE TABLE `ResourceStorage` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `resourceType` varchar(100) DEFAULT NULL,
  `resourceName` varchar(100) DEFAULT NULL,
  `uuid` varchar(40) DEFAULT NULL,
  `fileContents` mediumblob,
  `uploadDate` datetime DEFAULT NULL,
  `update_date` datetime DEFAULT NULL,
  `reference_date` datetime DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ResourceStorage_resourceType_active` (`resourceType`(10),`active`),
  KEY `ResourceStorage_resourceType_uuid` (`uuid`)
);

--
-- Table structure for table `SecurityArchive`
--


CREATE TABLE `SecurityArchive` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `security_no` int(6) NOT NULL,
  `user_name` varchar(30) NOT NULL,
  `password` varchar(255) NOT NULL,
  `provider_no` varchar(6),
  `pin` varchar(255),
  `b_ExpireSet` int(1),
  `date_ExpireDate` date,
  `b_LocalLockSet` int(1),
  `b_RemoteLockSet` int(1),
  `forcePasswordReset` tinyint(1),
  `passwordUpdateDate` datetime,
  `pinUpdateDate` datetime,
  `lastUpdateUser` varchar(20),
  `lastUpdateDate` timestamp NOT NULL ON UPDATE CURRENT_TIMESTAMP,
  `oneIdKey` varchar(255),
  `oneIdEmail` varchar(255),
  `delegateOneIdEmail` varchar(255),
  `totp_enabled` smallint(1) NOT NULL,
  `totp_secret` varchar(254) NOT NULL,
  `totp_algorithm` varchar(50) NOT NULL,
  `totp_digits` smallint(6) NOT NULL,
  `totp_period` smallint(6) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `SecurityToken`
--


CREATE TABLE `SecurityToken` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `token` varchar(100) NOT NULL,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `expiry` datetime NOT NULL,
  `data` varchar(255) DEFAULT NULL,
  `providerNo` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `token` (`token`)
);

--
-- Table structure for table `SentToPHRTracking`
--


CREATE TABLE `SentToPHRTracking` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `demographicNo` int(10) NOT NULL,
  `objectName` varchar(60) NOT NULL,
  `sentDatetime` datetime NOT NULL,
  `sentToServer` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `demographicNo` (`demographicNo`,`objectName`,`sentToServer`)
);

--
-- Table structure for table `ServiceAccessToken`
--


CREATE TABLE `ServiceAccessToken` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `clientId` int(11) DEFAULT NULL,
  `tokenId` varchar(255) NOT NULL,
  `tokenSecret` varchar(255) NOT NULL,
  `lifetime` int(10) NOT NULL,
  `issued` int(10) NOT NULL,
  `providerNo` varchar(25) DEFAULT NULL,
  `scopes` varchar(255) DEFAULT NULL,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ServiceClient`
--


CREATE TABLE `ServiceClient` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `clientKey` varchar(255) NOT NULL,
  `clientSecret` varchar(255) NOT NULL,
  `uri` varchar(255) DEFAULT NULL,
  `lifetime` int(11) DEFAULT NULL,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ServiceRequestToken`
--


CREATE TABLE `ServiceRequestToken` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `clientId` int(11) DEFAULT NULL,
  `tokenId` varchar(255) NOT NULL,
  `tokenSecret` varchar(255) NOT NULL,
  `callback` varchar(255) NOT NULL,
  `verifier` varchar(255) DEFAULT NULL,
  `providerNo` varchar(25) DEFAULT NULL,
  `scopes` varchar(255) DEFAULT NULL,
  `dateCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `SurveillanceData`
--


CREATE TABLE `SurveillanceData` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `surveyId` varchar(50) DEFAULT NULL,
  `data` mediumblob,
  `createDate` datetime DEFAULT NULL,
  `lastUpdateDate` datetime DEFAULT NULL,
  `transmissionDate` datetime DEFAULT NULL,
  `sent` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `allergies`
--


CREATE TABLE `allergies` (
  `allergyid` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `entry_date` date DEFAULT NULL,
  `DESCRIPTION` varchar(50) NOT NULL DEFAULT '',
  `HICL_SEQNO` int(6) DEFAULT NULL,
  `HIC_SEQNO` int(6) DEFAULT NULL,
  `AGCSP` int(6) DEFAULT NULL,
  `AGCCS` int(6) DEFAULT NULL,
  `TYPECODE` tinyint(4) NOT NULL DEFAULT '0',
  `reaction` text,
  `drugref_id` varchar(100) DEFAULT NULL,
  `archived` char(1) DEFAULT '0',
  `start_date` date DEFAULT NULL,
  `age_of_onset` char(4) DEFAULT '0',
  `severity_of_reaction` char(1) DEFAULT '0',
  `onset_of_reaction` char(1) DEFAULT '0',
  `regional_identifier` varchar(100) DEFAULT NULL,
  `life_stage` char(1) DEFAULT NULL,
  `position` int(10) NOT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `providerNo` varchar(6) DEFAULT NULL,
  `nonDrug` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`allergyid`)
);

--
-- Table structure for table `appointment`
--


CREATE TABLE `appointment` (
  `appointment_no` int(12) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `appointment_date` date NOT NULL DEFAULT '0001-01-01',
  `start_time` time NOT NULL DEFAULT '00:00:00',
  `end_time` time NOT NULL DEFAULT '00:00:00',
  `name` varchar(50) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `program_id` int(11) DEFAULT '0',
  `notes` varchar(255) DEFAULT NULL,
  `reasonCode` int(11) DEFAULT NULL,
  `reason` varchar(80) DEFAULT NULL,
  `location` varchar(30) DEFAULT NULL,
  `resources` varchar(255) DEFAULT NULL,
  `type` varchar(50) DEFAULT NULL,
  `style` varchar(10) DEFAULT NULL,
  `billing` varchar(10) DEFAULT NULL,
  `status` char(2) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  `imported_status` varchar(20) DEFAULT NULL,
  `createdatetime` datetime DEFAULT NULL,
  `updatedatetime` datetime DEFAULT NULL,
  `creator` varchar(50) DEFAULT NULL,
  `lastupdateuser` varchar(6) DEFAULT NULL,
  `remarks` varchar(50) DEFAULT NULL,
  `urgency` varchar(30) DEFAULT NULL,
  `creatorSecurityId` int(11) DEFAULT NULL,
  `bookingSource` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`appointment_no`),
  KEY `appointment_date` (`appointment_date`,`start_time`,`demographic_no`),
  KEY `demographic_no` (`demographic_no`),
  KEY `location` (`location`)
);

--
-- Table structure for table `appointmentArchive`
--


CREATE TABLE `appointmentArchive` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `appointment_no` int(12) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `appointment_date` date DEFAULT NULL,
  `start_time` time DEFAULT NULL,
  `end_time` time DEFAULT NULL,
  `name` varchar(50) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `program_id` int(11) DEFAULT NULL,
  `notes` varchar(255) DEFAULT NULL,
  `reason` varchar(80) DEFAULT NULL,
  `location` varchar(30) DEFAULT NULL,
  `resources` varchar(255) DEFAULT NULL,
  `type` varchar(50) DEFAULT NULL,
  `style` varchar(10) DEFAULT NULL,
  `billing` varchar(10) DEFAULT NULL,
  `status` char(2) DEFAULT NULL,
  `imported_status` varchar(20) DEFAULT NULL,
  `createdatetime` datetime DEFAULT NULL,
  `updatedatetime` datetime DEFAULT NULL,
  `creator` varchar(50) DEFAULT NULL,
  `lastupdateuser` varchar(6) DEFAULT NULL,
  `remarks` varchar(50) DEFAULT NULL,
  `urgency` varchar(30) DEFAULT NULL,
  `creatorSecurityId` int(11) DEFAULT NULL,
  `bookingSource` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `appointmentType`
--


CREATE TABLE `appointmentType` (
  `id` int(12) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) DEFAULT NULL,
  `notes` varchar(80) DEFAULT NULL,
  `reason` varchar(80) DEFAULT NULL,
  `location` varchar(30) DEFAULT NULL,
  `resources` varchar(10) DEFAULT NULL,
  `duration` int(12) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `appointment_status`
--


CREATE TABLE `appointment_status` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `status` char(2) NOT NULL,
  `description` char(30) NOT NULL DEFAULT 'no description',
  `color` char(7) NOT NULL DEFAULT '#cccccc',
  `icon` char(30) NOT NULL DEFAULT '''''',
  `active` int(1) NOT NULL DEFAULT '1',
  `editable` int(1) NOT NULL DEFAULT '0',
  `short_letter_colour` int(11) DEFAULT NULL COMMENT 'The colour of the short letters in the system',
  `short_letters` varchar(5) DEFAULT NULL COMMENT 'The short letter representation of the appointment status',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `batchEligibility`
--


CREATE TABLE `batchEligibility` (
  `responseCode` int(9) NOT NULL,
  `MOHResponse` varchar(100) NOT NULL,
  `reason` varchar(255) NOT NULL,
  PRIMARY KEY (`responseCode`)
);

--
-- Table structure for table `billactivity`
--


CREATE TABLE `billactivity` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `monthCode` char(1) DEFAULT NULL,
  `batchcount` int(3) DEFAULT NULL,
  `htmlfilename` varchar(50) DEFAULT NULL,
  `ohipfilename` varchar(50) DEFAULT NULL,
  `providerohipno` varchar(6) DEFAULT NULL,
  `groupno` varchar(6) DEFAULT NULL,
  `creator` varchar(6) DEFAULT NULL,
  `htmlcontext` mediumtext,
  `ohipcontext` mediumtext,
  `claimrecord` varchar(10) DEFAULT NULL,
  `updatedatetime` datetime DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  `total` varchar(20) DEFAULT NULL,
  `sentdate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `billcenter`
--


CREATE TABLE `billcenter` (
  `billcenter_code` char(2) NOT NULL,
  `billcenter_desc` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`billcenter_code`)
);

--
-- Table structure for table `billing`
--


CREATE TABLE `billing` (
  `billing_no` int(10) NOT NULL AUTO_INCREMENT,
  `clinic_no` int(10) NOT NULL DEFAULT '0',
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `appointment_no` int(12) DEFAULT NULL,
  `organization_spec_code` varchar(6) DEFAULT NULL,
  `demographic_name` varchar(60) DEFAULT NULL,
  `hin` varchar(12) DEFAULT NULL,
  `update_date` date DEFAULT NULL,
  `update_time` time DEFAULT NULL,
  `billing_date` date DEFAULT NULL,
  `billing_time` time DEFAULT NULL,
  `clinic_ref_code` varchar(10) DEFAULT NULL,
  `content` text,
  `total` varchar(6) DEFAULT NULL,
  `status` varchar(1) DEFAULT NULL,
  `dob` varchar(8) DEFAULT NULL,
  `visitdate` date DEFAULT NULL,
  `visittype` char(2) DEFAULT NULL,
  `provider_ohip_no` varchar(20) DEFAULT NULL,
  `provider_rma_no` varchar(20) DEFAULT NULL,
  `apptProvider_no` varchar(6) DEFAULT NULL,
  `asstProvider_no` varchar(6) DEFAULT NULL,
  `creator` varchar(6) DEFAULT NULL,
  `billingtype` varchar(4) DEFAULT 'MSP',
  PRIMARY KEY (`billing_no`),
  KEY `appointment_no` (`appointment_no`,`demographic_no`),
  KEY `demographic_no` (`demographic_no`),
  KEY `billing_date` (`billing_date`),
  KEY `provider_no` (`provider_no`),
  KEY `provider_ohip_no` (`provider_ohip_no`),
  KEY `apptProvider_no` (`apptProvider_no`),
  KEY `creator` (`creator`),
  KEY `status` (`status`)
);

--
-- Table structure for table `billing_on_3rdPartyAddress`
--


CREATE TABLE `billing_on_3rdPartyAddress` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `attention` varchar(100) NOT NULL DEFAULT '',
  `company_name` varchar(100) NOT NULL DEFAULT '',
  `address` varchar(200) NOT NULL DEFAULT '',
  `city` varchar(200) NOT NULL DEFAULT '',
  `province` varchar(10) NOT NULL DEFAULT '',
  `postcode` varchar(10) NOT NULL DEFAULT '',
  `telephone` varchar(15) NOT NULL DEFAULT '',
  `fax` varchar(15) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `billing_on_item_payment`
--


CREATE TABLE `billing_on_item_payment` (
  `id` int(12) NOT NULL AUTO_INCREMENT,
  `ch1_id` int(12) NOT NULL,
  `billing_on_payment_id` int(12) NOT NULL,
  `billing_on_item_id` int(12) NOT NULL,
  `payment_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `paid` decimal(10,2) NOT NULL,
  `refund` decimal(10,2) NOT NULL,
  `discount` decimal(10,2) NOT NULL,
  `credit` decimal(10,2) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ch1_id` (`ch1_id`),
  KEY `billing_on_payment_id` (`billing_on_payment_id`),
  KEY `billing_on_item_id` (`billing_on_item_id`)
);

--
-- Table structure for table `billing_on_payment`
--


CREATE TABLE `billing_on_payment` (
  `payment_id` int(10) NOT NULL AUTO_INCREMENT,
  `billing_no` int(6) NOT NULL,
  `pay_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `paymentTypeId` int(10) DEFAULT NULL,
  `creator` varchar(30) DEFAULT NULL,
  `total_payment` decimal(10,2) NOT NULL,
  `total_discount` decimal(10,2) NOT NULL,
  `total_refund` decimal(10,2) NOT NULL,
  `total_credit` decimal(10,2) NOT NULL,
  PRIMARY KEY (`payment_id`)
);

--
-- Table structure for table `billing_on_transaction`
--


CREATE TABLE `billing_on_transaction` (
  `id` int(12) NOT NULL AUTO_INCREMENT,
  `ch1_id` int(12) NOT NULL,
  `payment_id` int(12) NOT NULL,
  `billing_on_item_payment_id` int(12) NOT NULL,
  `demographic_no` int(10) NOT NULL,
  `update_provider_no` varchar(6) NOT NULL,
  `update_datetime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `payment_date` date DEFAULT NULL,
  `ref_num` varchar(6) DEFAULT NULL,
  `province` char(2) DEFAULT NULL,
  `man_review` char(1) DEFAULT NULL,
  `billing_date` date DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  `pay_program` char(3) DEFAULT NULL,
  `facility_num` char(4) DEFAULT NULL,
  `clinic` varchar(30) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `creator` varchar(30) DEFAULT NULL,
  `visittype` char(2) DEFAULT NULL,
  `admission_date` date DEFAULT NULL,
  `sli_code` varchar(10) DEFAULT NULL,
  `service_code` varchar(10) DEFAULT NULL,
  `service_code_num` char(2) DEFAULT NULL,
  `service_code_invoiced` varchar(64) DEFAULT NULL,
  `service_code_paid` decimal(10,2) DEFAULT NULL,
  `service_code_refund` decimal(10,2) DEFAULT NULL,
  `service_code_discount` decimal(10,2) DEFAULT NULL,
  `dx_code` varchar(3) DEFAULT NULL,
  `billing_notes` varchar(255) DEFAULT NULL,
  `action_type` char(1) DEFAULT NULL,
  `payment_type_id` int(2) DEFAULT NULL,
  `service_code_credit` decimal(10,2) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ch1_id` (`ch1_id`),
  KEY `payment_id` (`payment_id`),
  KEY `service_code` (`service_code`),
  KEY `dx_code` (`dx_code`),
  KEY `payment_type_id` (`payment_type_id`),
  KEY `demographic_no` (`demographic_no`),
  KEY `provider_no` (`provider_no`),
  KEY `creator` (`creator`),
  KEY `pay_program` (`pay_program`)
);

--
-- Table structure for table `billing_payment_type`
--


CREATE TABLE `billing_payment_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `payment_type` varchar(25) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `billingdetail`
--


CREATE TABLE `billingdetail` (
  `billing_dt_no` int(10) NOT NULL AUTO_INCREMENT,
  `billing_no` int(10) NOT NULL DEFAULT '0',
  `service_code` varchar(5) DEFAULT NULL,
  `service_desc` varchar(255) DEFAULT NULL,
  `billing_amount` varchar(6) DEFAULT NULL,
  `diagnostic_code` char(3) DEFAULT NULL,
  `appointment_date` date DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  `billingunit` char(2) DEFAULT NULL,
  PRIMARY KEY (`billing_dt_no`),
  KEY `billingno` (`billing_no`)
);

--
-- Table structure for table `billinginr`
--


CREATE TABLE `billinginr` (
  `billinginr_no` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `demographic_name` varchar(60) NOT NULL DEFAULT '',
  `hin` varchar(12) DEFAULT NULL,
  `dob` varchar(8) DEFAULT NULL,
  `provider_no` varchar(10) DEFAULT NULL,
  `provider_ohip_no` varchar(20) DEFAULT NULL,
  `provider_rma_no` varchar(20) DEFAULT NULL,
  `creator` varchar(6) DEFAULT NULL,
  `diagnostic_code` char(3) DEFAULT NULL,
  `service_code` varchar(6) DEFAULT NULL,
  `service_desc` varchar(255) DEFAULT NULL,
  `billing_amount` varchar(6) DEFAULT NULL,
  `billing_unit` char(1) DEFAULT NULL,
  `createdatetime` datetime NOT NULL DEFAULT '0001-01-01 00:00:00',
  `status` char(1) DEFAULT NULL,
  PRIMARY KEY (`billinginr_no`)
);

--
-- Table structure for table `billingperclimit`
--


CREATE TABLE `billingperclimit` (
  `service_code` varchar(10) NOT NULL,
  `min` varchar(8) DEFAULT NULL,
  `max` varchar(8) DEFAULT NULL,
  `effective_date` date DEFAULT NULL,
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `billingreferral`
--


CREATE TABLE `billingreferral` (
  `billingreferral_no` int(10) NOT NULL AUTO_INCREMENT,
  `referral_no` varchar(6) NOT NULL,
  `last_name` varchar(30) DEFAULT NULL,
  `first_name` varchar(30) DEFAULT NULL,
  `specialty` varchar(30) DEFAULT NULL,
  `address1` varchar(50) DEFAULT NULL,
  `address2` varchar(50) DEFAULT NULL,
  `city` varchar(30) DEFAULT NULL,
  `province` varchar(30) DEFAULT NULL,
  `country` varchar(30) DEFAULT NULL,
  `postal` varchar(10) DEFAULT NULL,
  `phone` varchar(25) DEFAULT NULL,
  `fax` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`billingreferral_no`),
  KEY `referral_no` (`referral_no`)
);

--
-- Table structure for table `billingservice`
--


CREATE TABLE `billingservice` (
  `billingservice_no` int(10) NOT NULL AUTO_INCREMENT,
  `service_compositecode` varchar(30) DEFAULT NULL,
  `service_code` varchar(10) DEFAULT NULL,
  `description` text,
  `value` varchar(8) DEFAULT NULL,
  `percentage` varchar(8) DEFAULT NULL,
  `billingservice_date` date DEFAULT NULL,
  `specialty` varchar(15) DEFAULT NULL,
  `region` varchar(5) DEFAULT NULL,
  `anaesthesia` char(2) DEFAULT NULL,
  `termination_date` date DEFAULT '9999-12-31',
  `displaystyle` int(10) DEFAULT NULL,
  `sliFlag` tinyint(1) NOT NULL DEFAULT '0',
  `gstFlag` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`billingservice_no`),
  KEY `billingservice_service_code_index` (`service_code`)
);

--
-- Table structure for table `casemgmt_note_ext`
--


CREATE TABLE `casemgmt_note_ext` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `note_id` int(10) NOT NULL,
  `key_val` varchar(64) NOT NULL,
  `value` text,
  `date_value` date DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `casemgmt_note_link`
--


CREATE TABLE `casemgmt_note_link` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `table_name` int(6) NOT NULL,
  `table_id` int(10) NOT NULL,
  `note_id` int(10) NOT NULL,
  `other_id` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `casemgmt_note_lock`
--


CREATE TABLE `casemgmt_note_lock` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `session_id` varchar(255) DEFAULT NULL,
  `ip_address` varchar(64) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `note_id` int(10) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `lock_acquired` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `casemgmt_note_lock_providerNo` (`provider_no`),
  KEY `casemgmt_note_lock_note_id` (`note_id`),
  KEY `casemgmt_note_lock_providerNo_noteId` (`provider_no`,`note_id`)
);

--
-- Table structure for table `clinic`
--


CREATE TABLE `clinic` (
  `clinic_no` int(10) NOT NULL AUTO_INCREMENT,
  `clinic_name` varchar(100) DEFAULT NULL,
  `clinic_address` varchar(60) DEFAULT '',
  `clinic_city` varchar(40) DEFAULT '',
  `clinic_postal` varchar(15) DEFAULT '',
  `clinic_phone` varchar(50) DEFAULT NULL,
  `clinic_fax` varchar(20) DEFAULT '',
  `clinic_location_code` varchar(10) DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  `clinic_province` varchar(40) DEFAULT NULL,
  `clinic_delim_phone` text,
  `clinic_delim_fax` text,
  PRIMARY KEY (`clinic_no`)
);

--
-- Table structure for table `clinic_location`
--


CREATE TABLE `clinic_location` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `clinic_location_no` varchar(15) NOT NULL DEFAULT '',
  `clinic_no` int(10) NOT NULL DEFAULT '0',
  `clinic_location_name` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `clinic_nbr`
--


CREATE TABLE `clinic_nbr` (
  `nbr_id` int(11) NOT NULL AUTO_INCREMENT,
  `nbr_value` varchar(11) NOT NULL,
  `nbr_string` text,
  `nbr_status` varchar(1) DEFAULT NULL,
  PRIMARY KEY (`nbr_id`)
);

--
-- Table structure for table `config_Immunization`
--


CREATE TABLE `config_Immunization` (
  `setId` int(10) NOT NULL AUTO_INCREMENT,
  `setName` varchar(255) DEFAULT NULL,
  `setXmlDoc` text,
  `createDate` date DEFAULT NULL,
  `providerNo` varchar(6) DEFAULT NULL,
  `archived` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`setId`)
);

--
-- Table structure for table `consentType`
--


CREATE TABLE `consentType` (
  `id` int(15) NOT NULL AUTO_INCREMENT,
  `type` varchar(50) DEFAULT NULL,
  `name` varchar(50) DEFAULT NULL,
  `description` varchar(500) DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `providerNo` varchar(6) DEFAULT NULL,
  `remoteEnabled` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `consultResponseDoc`
--


CREATE TABLE `consultResponseDoc` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `responseId` int(10) NOT NULL,
  `documentNo` int(10) NOT NULL,
  `docType` char(1) NOT NULL,
  `deleted` char(1) DEFAULT NULL,
  `attachDate` date DEFAULT NULL,
  `providerNo` varchar(6) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `consultationRequestExt`
--


CREATE TABLE `consultationRequestExt` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `requestId` int(10) NOT NULL,
  `name` varchar(100) NOT NULL,
  `value` text NOT NULL,
  `dateCreated` date NOT NULL,
  PRIMARY KEY (`id`),
  KEY `requestId` (`requestId`)
);

--
-- Table structure for table `consultationRequestExtArchive`
--


CREATE TABLE `consultationRequestExtArchive` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `originalId` int(10) NOT NULL,
  `requestId` int(10) NOT NULL,
  `name` varchar(100) NOT NULL,
  `value` text NOT NULL,
  `dateCreated` date NOT NULL,
  `consultationRequestArchiveId` int(10) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `requestId` (`requestId`)
);

--
-- Table structure for table `consultationRequests`
--


CREATE TABLE `consultationRequests` (
  `referalDate` date DEFAULT NULL,
  `serviceId` int(10) DEFAULT NULL,
  `specId` int(10) DEFAULT NULL,
  `appointmentDate` date DEFAULT NULL,
  `appointmentTime` time DEFAULT NULL,
  `reason` text,
  `clinicalInfo` text,
  `currentMeds` text,
  `allergies` text,
  `providerNo` varchar(6) DEFAULT NULL,
  `demographicNo` int(10) DEFAULT NULL,
  `status` char(2) DEFAULT NULL,
  `statusText` text,
  `sendTo` varchar(20) DEFAULT NULL,
  `requestId` int(10) NOT NULL AUTO_INCREMENT,
  `concurrentProblems` text,
  `urgency` char(2) DEFAULT NULL,
  `appointmentInstructions` varchar(256) DEFAULT NULL,
  `patientWillBook` tinyint(1) DEFAULT NULL,
  `followUpDate` date DEFAULT NULL,
  `site_name` varchar(255) DEFAULT NULL,
  `signature_img` varchar(20) DEFAULT NULL,
  `letterheadName` varchar(255) DEFAULT NULL,
  `letterheadAddress` text,
  `letterheadPhone` varchar(50) DEFAULT NULL,
  `letterheadFax` varchar(50) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `fdid` int(10) DEFAULT NULL,
  `source` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`requestId`)
);

--
-- Table structure for table `consultationRequestsArchive`
--


CREATE TABLE `consultationRequestsArchive` (
  `Id` int(10) NOT NULL AUTO_INCREMENT,
  `referalDate` date DEFAULT NULL,
  `serviceId` int(10) DEFAULT NULL,
  `specId` int(10) DEFAULT NULL,
  `appointmentDate` date DEFAULT NULL,
  `appointmentTime` time DEFAULT NULL,
  `reason` text,
  `clinicalInfo` text,
  `currentMeds` text,
  `allergies` text,
  `providerNo` varchar(6) DEFAULT NULL,
  `demographicNo` int(10) DEFAULT NULL,
  `status` char(2) DEFAULT NULL,
  `statusText` text,
  `sendTo` varchar(20) DEFAULT NULL,
  `requestId` int(10) NOT NULL,
  `concurrentProblems` text,
  `urgency` char(2) DEFAULT NULL,
  `appointmentInstructions` varchar(256) DEFAULT NULL,
  `patientWillBook` tinyint(1) DEFAULT NULL,
  `followUpDate` date DEFAULT NULL,
  `site_name` varchar(255) DEFAULT NULL,
  `signature_img` varchar(20) DEFAULT NULL,
  `letterheadName` varchar(255) DEFAULT NULL,
  `letterheadAddress` text,
  `letterheadPhone` varchar(50) DEFAULT NULL,
  `letterheadFax` varchar(50) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `fdid` int(10) DEFAULT NULL,
  `source` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`Id`)
);

--
-- Table structure for table `consultationResponse`
--


CREATE TABLE `consultationResponse` (
  `responseId` int(10) NOT NULL AUTO_INCREMENT,
  `responseDate` date DEFAULT NULL,
  `referralDate` date DEFAULT NULL,
  `referringDocId` int(10) DEFAULT NULL,
  `appointmentDate` date DEFAULT NULL,
  `appointmentTime` time DEFAULT NULL,
  `appointmentNote` text,
  `referralReason` text,
  `examination` text,
  `impression` text,
  `plan` text,
  `clinicalInfo` text,
  `currentMeds` text,
  `allergies` text,
  `providerNo` varchar(6) DEFAULT NULL,
  `demographicNo` int(10) DEFAULT NULL,
  `status` char(2) DEFAULT NULL,
  `sendTo` varchar(20) DEFAULT NULL,
  `concurrentProblems` text,
  `urgency` char(2) DEFAULT NULL,
  `followUpDate` date DEFAULT NULL,
  `signatureImg` varchar(20) DEFAULT NULL,
  `letterheadName` varchar(20) DEFAULT NULL,
  `letterheadAddress` text,
  `letterheadPhone` varchar(50) DEFAULT NULL,
  `letterheadFax` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`responseId`)
);

--
-- Table structure for table `consultationServices`
--


CREATE TABLE `consultationServices` (
  `serviceId` int(10) NOT NULL AUTO_INCREMENT,
  `serviceDesc` varchar(255) DEFAULT NULL,
  `active` char(2) DEFAULT NULL,
  PRIMARY KEY (`serviceId`)
);

--
-- Table structure for table `consultdocs`
--


CREATE TABLE `consultdocs` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `requestId` int(10) NOT NULL,
  `document_no` int(10) NOT NULL,
  `doctype` char(1) NOT NULL,
  `deleted` char(1) DEFAULT NULL,
  `attach_date` date DEFAULT NULL,
  `provider_no` varchar(6) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `country_codes`
--


CREATE TABLE `country_codes` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `country_name` varchar(255) DEFAULT NULL,
  `country_id` char(4) DEFAULT NULL,
  `c_locale` char(10) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `country_id` (`country_id`),
  KEY `c_locale` (`c_locale`)
);

--
-- Table structure for table `criteria`
--


CREATE TABLE `criteria` (
  `CRITERIA_ID` int(11) NOT NULL AUTO_INCREMENT,
  `CRITERIA_TYPE_ID` int(11) NOT NULL,
  `CRITERIA_VALUE` varchar(255) DEFAULT NULL,
  `RANGE_START_VALUE` int(11) DEFAULT NULL,
  `RANGE_END_VALUE` int(11) DEFAULT NULL,
  `TEMPLATE_ID` int(11) DEFAULT NULL,
  `VACANCY_ID` int(11) DEFAULT NULL,
  `MATCH_SCORE_WEIGHT` double NOT NULL,
  `CAN_BE_ADHOC` int(1) NOT NULL,
  PRIMARY KEY (`CRITERIA_ID`)
);

--
-- Table structure for table `criteria_selection_option`
--


CREATE TABLE `criteria_selection_option` (
  `SELECT_OPTION_ID` int(11) NOT NULL AUTO_INCREMENT,
  `CRITERIA_ID` int(11) NOT NULL,
  `OPTION_VALUE` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`SELECT_OPTION_ID`)
);

--
-- Table structure for table `criteria_type`
--


CREATE TABLE `criteria_type` (
  `CRITERIA_TYPE_ID` int(11) NOT NULL AUTO_INCREMENT,
  `FIELD_NAME` varchar(128) NOT NULL,
  `FIELD_TYPE` varchar(128) NOT NULL,
  `DEFAULT_VALUE` varchar(255) DEFAULT NULL,
  `ACTIVE` tinyint(1) NOT NULL,
  `WL_PROGRAM_ID` int(11) DEFAULT NULL,
  `CAN_BE_ADHOC` tinyint(1) NOT NULL,
  PRIMARY KEY (`CRITERIA_TYPE_ID`)
);

--
-- Table structure for table `criteria_type_option`
--


CREATE TABLE `criteria_type_option` (
  `OPTION_ID` int(11) NOT NULL AUTO_INCREMENT,
  `CRITERIA_TYPE_ID` int(11) NOT NULL,
  `DISPLAY_ORDER_NUMBER` int(11) NOT NULL,
  `OPTION_LABEL` varchar(128) NOT NULL,
  `OPTION_VALUE` varchar(255) DEFAULT NULL,
  `RANGE_START_VALUE` int(11) DEFAULT NULL,
  `RANGE_END_VALUE` int(11) DEFAULT NULL,
  PRIMARY KEY (`OPTION_ID`)
);

--
-- Table structure for table `cssStyles`
--


CREATE TABLE `cssStyles` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `style` text,
  `status` char(1) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ctl_billingservice`
--


CREATE TABLE `ctl_billingservice` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `servicetype_name` varchar(150) DEFAULT NULL,
  `servicetype` varchar(10) DEFAULT NULL,
  `service_code` varchar(10) DEFAULT NULL,
  `service_group_name` varchar(30) DEFAULT NULL,
  `service_group` varchar(30) DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  `service_order` int(4) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ctl_billingservice_premium`
--


CREATE TABLE `ctl_billingservice_premium` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `servicetype_name` varchar(150) DEFAULT '',
  `service_code` varchar(10) DEFAULT '',
  `status` char(1) DEFAULT '',
  `update_date` date DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ctl_diagcode`
--


CREATE TABLE `ctl_diagcode` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `servicetype` varchar(10) DEFAULT NULL,
  `diagnostic_code` varchar(5) DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ctl_doc_class`
--


CREATE TABLE `ctl_doc_class` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `reportclass` varchar(60) NOT NULL,
  `subclass` varchar(60) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ctl_doctype`
--


CREATE TABLE `ctl_doctype` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `module` varchar(30) NOT NULL DEFAULT '',
  `doctype` varchar(60) NOT NULL DEFAULT '',
  `status` char(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ctl_document`
--


CREATE TABLE `ctl_document` (
  `module` varchar(30) NOT NULL DEFAULT '',
  `module_id` int(6) NOT NULL DEFAULT '0',
  `document_no` int(6) NOT NULL DEFAULT '0',
  `status` char(1) DEFAULT NULL,
  PRIMARY KEY (`module_id`,`module`,`document_no`),
  KEY `module` (`module`),
  KEY `document_no` (`document_no`)
);

--
-- Table structure for table `ctl_frequency`
--


CREATE TABLE `ctl_frequency` (
  `freqid` tinyint(4) NOT NULL AUTO_INCREMENT,
  `freqcode` varchar(8) NOT NULL DEFAULT '',
  `dailymin` varchar(5) NOT NULL DEFAULT '0',
  `dailymax` varchar(5) NOT NULL DEFAULT '0',
  PRIMARY KEY (`freqid`)
);

--
-- Table structure for table `ctl_specialinstructions`
--


CREATE TABLE `ctl_specialinstructions` (
  `id` tinyint(4) NOT NULL AUTO_INCREMENT,
  `description` varchar(50) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `dashboard`
--


CREATE TABLE `dashboard` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `creator` varchar(11) DEFAULT NULL,
  `edited` datetime DEFAULT NULL,
  `active` bit(1) DEFAULT NULL,
  `locked` bit(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `dataExport`
--


CREATE TABLE `dataExport` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `file` varchar(255) DEFAULT NULL,
  `daterun` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `user` varchar(255) DEFAULT NULL,
  `type` varchar(255) DEFAULT NULL,
  `contactLName` varchar(255) DEFAULT NULL,
  `contactFName` varchar(255) DEFAULT NULL,
  `contactPhone` varchar(255) DEFAULT NULL,
  `contactEmail` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `default_issue`
--


CREATE TABLE `default_issue` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `assigned_time` datetime NOT NULL,
  `issue_ids` text,
  `provider_no` varchar(6) NOT NULL,
  `update_time` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `demographic`
--


CREATE TABLE `demographic` (
  `demographic_no` int(10) NOT NULL AUTO_INCREMENT,
  `title` varchar(10) DEFAULT NULL,
  `last_name` varchar(30) NOT NULL DEFAULT '',
  `first_name` varchar(30) NOT NULL DEFAULT '',
  `address` varchar(60) DEFAULT NULL,
  `city` varchar(50) DEFAULT NULL,
  `province` varchar(20) DEFAULT NULL,
  `postal` varchar(9) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `phone2` varchar(20) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `myOscarUserName` varchar(255) DEFAULT NULL,
  `year_of_birth` varchar(4) DEFAULT NULL,
  `month_of_birth` varchar(2) DEFAULT NULL,
  `date_of_birth` varchar(2) DEFAULT NULL,
  `hin` varchar(20) DEFAULT NULL,
  `ver` char(3) DEFAULT NULL,
  `roster_status` varchar(20) DEFAULT NULL,
  `roster_date` date DEFAULT NULL,
  `roster_termination_date` date DEFAULT NULL,
  `roster_termination_reason` varchar(2) DEFAULT NULL,
  `roster_enrolled_to` varchar(20) DEFAULT NULL,
  `patient_status` varchar(20) DEFAULT NULL,
  `patient_status_date` date DEFAULT NULL,
  `date_joined` date DEFAULT NULL,
  `chart_no` varchar(10) DEFAULT NULL,
  `official_lang` varchar(60) DEFAULT NULL,
  `spoken_lang` varchar(60) DEFAULT NULL,
  `provider_no` varchar(250) DEFAULT NULL,
  `sex` char(1) NOT NULL DEFAULT '',
  `end_date` date DEFAULT NULL,
  `eff_date` date DEFAULT NULL,
  `pcn_indicator` varchar(20) DEFAULT NULL,
  `hc_type` varchar(20) DEFAULT NULL,
  `hc_renew_date` date DEFAULT NULL,
  `family_doctor` varchar(80) DEFAULT NULL,
  `alias` varchar(70) DEFAULT NULL,
  `previousAddress` varchar(255) DEFAULT NULL,
  `children` varchar(255) DEFAULT NULL,
  `sourceOfIncome` varchar(255) DEFAULT NULL,
  `citizenship` varchar(40) DEFAULT NULL,
  `sin` varchar(15) DEFAULT NULL,
  `country_of_origin` char(4) DEFAULT NULL,
  `newsletter` varchar(32) DEFAULT NULL,
  `anonymous` varchar(32) DEFAULT NULL,
  `lastUpdateUser` varchar(6) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `middleNames` varchar(100) DEFAULT NULL,
  `residentialAddress` varchar(60) DEFAULT NULL,
  `residentialCity` varchar(50) DEFAULT NULL,
  `residentialProvince` varchar(20) DEFAULT NULL,
  `residentialPostal` varchar(9) DEFAULT NULL,
  `consentToUseEmailForCare` tinyint(1) DEFAULT NULL,
  `family_physician` varchar(80) DEFAULT NULL,
  `pref_name` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`demographic_no`),
  UNIQUE KEY `myOscarUserName` (`myOscarUserName`),
  KEY `hin` (`hin`),
  KEY `name` (`last_name`,`first_name`),
  KEY `country_of_origin` (`country_of_origin`)
);

--
-- Table structure for table `demographicArchive`
--


CREATE TABLE `demographicArchive` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `title` varchar(10) DEFAULT NULL,
  `last_name` varchar(30) DEFAULT NULL,
  `first_name` varchar(30) DEFAULT NULL,
  `middleNames` varchar(100) DEFAULT NULL,
  `address` varchar(60) DEFAULT NULL,
  `city` varchar(20) DEFAULT NULL,
  `province` varchar(20) DEFAULT NULL,
  `postal` varchar(9) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `phone2` varchar(20) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `myOscarUserName` varchar(255) DEFAULT NULL,
  `year_of_birth` varchar(4) DEFAULT NULL,
  `month_of_birth` char(2) DEFAULT NULL,
  `date_of_birth` char(2) DEFAULT NULL,
  `hin` varchar(20) DEFAULT NULL,
  `ver` char(3) DEFAULT NULL,
  `roster_status` varchar(20) DEFAULT NULL,
  `roster_date` date DEFAULT NULL,
  `roster_termination_date` date DEFAULT NULL,
  `roster_termination_reason` varchar(2) DEFAULT NULL,
  `roster_enrolled_to` varchar(20) DEFAULT NULL,
  `patient_status` varchar(20) DEFAULT NULL,
  `patient_status_date` date DEFAULT NULL,
  `date_joined` date DEFAULT NULL,
  `chart_no` varchar(10) DEFAULT NULL,
  `official_lang` varchar(60) DEFAULT NULL,
  `spoken_lang` varchar(60) DEFAULT NULL,
  `provider_no` varchar(250) DEFAULT NULL,
  `sex` char(1) DEFAULT NULL,
  `end_date` date DEFAULT NULL,
  `eff_date` date DEFAULT NULL,
  `pcn_indicator` varchar(20) DEFAULT NULL,
  `hc_type` varchar(20) DEFAULT NULL,
  `hc_renew_date` date DEFAULT NULL,
  `family_doctor` varchar(80) DEFAULT NULL,
  `alias` varchar(70) DEFAULT NULL,
  `previousAddress` varchar(255) DEFAULT NULL,
  `children` varchar(255) DEFAULT NULL,
  `sourceOfIncome` varchar(255) DEFAULT NULL,
  `citizenship` varchar(40) DEFAULT NULL,
  `sin` varchar(15) DEFAULT NULL,
  `country_of_origin` char(4) DEFAULT NULL,
  `newsletter` varchar(32) DEFAULT NULL,
  `anonymous` varchar(32) DEFAULT NULL,
  `lastUpdateUser` varchar(6) DEFAULT NULL,
  `lastUpdateDate` date DEFAULT NULL,
  `residentialAddress` varchar(60) DEFAULT NULL,
  `residentialCity` varchar(50) DEFAULT NULL,
  `residentialProvince` varchar(20) DEFAULT NULL,
  `residentialPostal` varchar(9) DEFAULT NULL,
  `consentToUseEmailForCare` TINYINT(1) DEFAULT NULL,
  `family_physician` varchar(80) DEFAULT NULL,
  `pref_name` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `demographicExt`
--


CREATE TABLE `demographicExt` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `key_val` varchar(64) DEFAULT NULL,
  `value` text,
  `date_time` datetime DEFAULT NULL,
  `hidden` char(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `demographic_no` (`demographic_no`)
);

--
-- Table structure for table `demographicExtArchive`
--


CREATE TABLE `demographicExtArchive` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `archiveId` bigint(20) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `key_val` varchar(64) DEFAULT NULL,
  `value` text,
  `date_time` datetime DEFAULT NULL,
  `hidden` char(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `demographic_no` (`demographic_no`)
);

--
-- Table structure for table `demographicPharmacy`
--


CREATE TABLE `demographicPharmacy` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `pharmacyID` int(10) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `status` char(1) DEFAULT '1',
  `addDate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `preferredOrder` int(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `demographicQueryFavourites`
--


CREATE TABLE `demographicQueryFavourites` (
  `favId` int(9) NOT NULL AUTO_INCREMENT,
  `selects` text,
  `age` varchar(255) DEFAULT NULL,
  `startYear` varchar(8) DEFAULT NULL,
  `endYear` varchar(8) DEFAULT NULL,
  `firstName` varchar(255) DEFAULT NULL,
  `lastName` varchar(255) DEFAULT NULL,
  `rosterStatus` text,
  `sex` varchar(10) DEFAULT NULL,
  `providerNo` text,
  `patientStatus` text,
  `queryName` varchar(255) DEFAULT NULL,
  `archived` char(1) DEFAULT NULL,
  `demoIds` text,
  PRIMARY KEY (`favId`)
);

--
-- Table structure for table `demographicSets`
--


CREATE TABLE `demographicSets` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `set_name` varchar(20) DEFAULT NULL,
  `eligibility` char(1) DEFAULT NULL,
  `archive` char(1) DEFAULT '0',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `demographic_merged`
--


CREATE TABLE `demographic_merged` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `merged_to` int(10) NOT NULL,
  `deleted` int(1) NOT NULL DEFAULT '0',
  `lastUpdateUser` varchar(6) DEFAULT NULL,
  `lastUpdateDate` date DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `dem_merged` (`demographic_no`,`merged_to`,`deleted`),
  KEY `dem_merged_dem` (`demographic_no`,`deleted`),
  KEY `dem_merged_merge` (`merged_to`,`deleted`)
);

--
-- Table structure for table `demographicaccessory`
--


CREATE TABLE `demographicaccessory` (
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `content` text,
  PRIMARY KEY (`demographic_no`)
);

--
-- Table structure for table `demographiccust`
--


CREATE TABLE `demographiccust` (
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `cust1` varchar(255) DEFAULT NULL,
  `cust2` varchar(255) DEFAULT NULL,
  `cust3` varchar(255) DEFAULT NULL,
  `cust4` varchar(255) DEFAULT NULL,
  `content` text,
  PRIMARY KEY (`demographic_no`),
  KEY `cust1` (`cust1`),
  KEY `cust2` (`cust2`),
  KEY `cust3` (`cust3`),
  KEY `cust4` (`cust4`)
);

--
-- Table structure for table `demographiccustArchive`
--


CREATE TABLE `demographiccustArchive` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `cust1` varchar(255) DEFAULT NULL,
  `cust2` varchar(255) DEFAULT NULL,
  `cust3` varchar(255) DEFAULT NULL,
  `cust4` varchar(255) DEFAULT NULL,
  `content` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `demographicstudy`
--


CREATE TABLE `demographicstudy` (
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `study_no` int(3) NOT NULL DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`demographic_no`,`study_no`)
);

--
-- Table structure for table `desannualreviewplan`
--


CREATE TABLE `desannualreviewplan` (
  `des_no` int(10) NOT NULL AUTO_INCREMENT,
  `des_date` date NOT NULL DEFAULT '0001-01-01',
  `des_time` time NOT NULL DEFAULT '00:00:00',
  `demographic_no` int(10) DEFAULT '0',
  `form_no` int(10) DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `risk_content` text,
  `checklist_content` text,
  PRIMARY KEY (`des_no`)
);

--
-- Table structure for table `desaprisk`
--


CREATE TABLE `desaprisk` (
  `desaprisk_no` int(10) NOT NULL AUTO_INCREMENT,
  `desaprisk_date` date NOT NULL DEFAULT '0001-01-01',
  `desaprisk_time` time NOT NULL DEFAULT '00:00:00',
  `demographic_no` int(10) DEFAULT '0',
  `form_no` int(10) DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `risk_content` text,
  `checklist_content` text,
  PRIMARY KEY (`desaprisk_no`)
);

--
-- Table structure for table `diagnosticcode`
--


CREATE TABLE `diagnosticcode` (
  `diagnosticcode_no` int(5) NOT NULL AUTO_INCREMENT,
  `diagnostic_code` varchar(5) NOT NULL DEFAULT '',
  `description` text,
  `status` char(1) DEFAULT NULL,
  `region` varchar(5) DEFAULT NULL,
  PRIMARY KEY (`diagnosticcode_no`),
  KEY `diagnosticcode_diagnostic_code_index` (`diagnostic_code`)
);

--
-- Table structure for table `diseases`
--


CREATE TABLE `diseases` (
  `diseaseid` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `ICD9_E` char(6) NOT NULL DEFAULT '',
  `entry_date` date DEFAULT NULL,
  PRIMARY KEY (`diseaseid`)
);

--
-- Table structure for table `doc_category`
--


CREATE TABLE `doc_category` (
  `cat_id` int(11) NOT NULL AUTO_INCREMENT,
  `level` int(11) NOT NULL,
  `parent_id` int(11) DEFAULT NULL,
  `category` varchar(40) NOT NULL,
  `description` varchar(100) DEFAULT NULL,
  `testmark` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`cat_id`),
  KEY `parent_id` (`parent_id`)
);

--
-- Table structure for table `doc_manager`
--


CREATE TABLE `doc_manager` (
  `id` int(20) NOT NULL AUTO_INCREMENT,
  `category_id` int(11) DEFAULT NULL,
  `doc_path` varchar(100) DEFAULT NULL,
  `demographic_no` int(20) NOT NULL,
  `primary_provider_no` varchar(6) NOT NULL,
  `reviewed_flag` tinyint(1) NOT NULL,
  `upload_from_id` int(11) DEFAULT NULL,
  `tickler_no` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_doc_manager` (`category_id`),
  CONSTRAINT `doc_manager_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `doc_category` (`cat_id`)
);

--
-- Table structure for table `document`
--


CREATE TABLE `document` (
  `document_no` int(20) NOT NULL AUTO_INCREMENT,
  `doctype` varchar(60) DEFAULT NULL,
  `docClass` varchar(60) DEFAULT NULL,
  `docSubClass` varchar(60) DEFAULT NULL,
  `docdesc` varchar(255) NOT NULL DEFAULT '',
  `docxml` text,
  `docfilename` varchar(255) NOT NULL DEFAULT '',
  `doccreator` varchar(30) NOT NULL DEFAULT '',
  `responsible` varchar(30) NOT NULL DEFAULT '',
  `source` varchar(60) DEFAULT NULL,
  `sourceFacility` varchar(120) DEFAULT NULL,
  `program_id` int(11) DEFAULT NULL,
  `updatedatetime` datetime DEFAULT NULL,
  `status` char(1) NOT NULL DEFAULT '',
  `contenttype` varchar(255) NOT NULL DEFAULT '',
  `contentdatetime` datetime DEFAULT NULL,
  `public1` int(1) NOT NULL DEFAULT '0',
  `observationdate` date DEFAULT NULL,
  `reviewer` varchar(30) DEFAULT '',
  `reviewdatetime` datetime DEFAULT NULL,
  `number_of_pages` int(6) DEFAULT NULL,
  `appointment_no` int(11) DEFAULT NULL,
  `restrictToProgram` tinyint(1) NOT NULL,
  `receivedDate` date DEFAULT NULL,
  `abnormal` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`document_no`)
);

--
-- Table structure for table `documentDescriptionTemplate`
--


CREATE TABLE `documentDescriptionTemplate` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `doctype` varchar(60) NOT NULL,
  `description` varchar(255) NOT NULL,
  `descriptionShortcut` varchar(20) NOT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `lastUpdated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `document_storage`
--


CREATE TABLE `document_storage` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `documentNo` int(10) DEFAULT NULL,
  `fileContents` mediumblob,
  `uploadDate` date DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `drugReason`
--


CREATE TABLE `drugReason` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `drugId` int(10) NOT NULL,
  `codingSystem` varchar(255) DEFAULT NULL,
  `code` varchar(255) DEFAULT NULL,
  `comments` text,
  `primaryReasonFlag` tinyint(1) NOT NULL,
  `archivedFlag` tinyint(1) NOT NULL,
  `archivedReason` text,
  `demographicNo` int(10) NOT NULL,
  `providerNo` varchar(6) NOT NULL,
  `dateCoded` date DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `drugId` (`drugId`),
  KEY `archivedFlag` (`archivedFlag`),
  KEY `codingSystem` (`codingSystem`(30),`code`(30))
);

--
-- Table structure for table `drugs`
--


CREATE TABLE `drugs` (
  `drugid` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `rx_date` date NOT NULL DEFAULT '0001-01-01',
  `end_date` date NOT NULL DEFAULT '0001-01-01',
  `written_date` date DEFAULT '0001-01-01',
  `pickup_datetime` datetime DEFAULT NULL,
  `BN` varchar(255) DEFAULT '',
  `GCN_SEQNO` decimal(10,0) NOT NULL DEFAULT '0',
  `customName` varchar(60) DEFAULT NULL,
  `takemin` float DEFAULT NULL,
  `takemax` float DEFAULT NULL,
  `freqcode` varchar(6) DEFAULT NULL,
  `duration` varchar(4) DEFAULT NULL,
  `durunit` char(1) DEFAULT NULL,
  `quantity` varchar(20) DEFAULT NULL,
  `repeat` tinyint(4) DEFAULT NULL,
  `last_refill_date` date DEFAULT NULL,
  `nosubs` tinyint(1) NOT NULL DEFAULT '0',
  `prn` tinyint(1) NOT NULL DEFAULT '0',
  `special` text,
  `special_instruction` text,
  `archived` tinyint(1) NOT NULL DEFAULT '0',
  `GN` varchar(255) DEFAULT NULL,
  `ATC` varchar(20) DEFAULT NULL,
  `script_no` int(10) DEFAULT NULL,
  `regional_identifier` varchar(100) DEFAULT NULL,
  `unit` varchar(5) DEFAULT 'tab',
  `method` varchar(5) DEFAULT 'Take',
  `route` varchar(50) DEFAULT 'PO',
  `drug_form` varchar(50) DEFAULT NULL,
  `create_date` datetime DEFAULT NULL,
  `dosage` text,
  `custom_instructions` tinyint(1) DEFAULT '0',
  `unitName` varchar(10) DEFAULT NULL,
  `custom_note` tinyint(1) DEFAULT NULL,
  `long_term` tinyint(1) DEFAULT NULL,
  `short_term` tinyint(1) DEFAULT NULL,
  `non_authoritative` tinyint(1) DEFAULT NULL,
  `past_med` tinyint(1) DEFAULT NULL,
  `patient_compliance` tinyint(1) DEFAULT NULL,
  `outside_provider_name` varchar(100) DEFAULT NULL,
  `outside_provider_ohip` varchar(20) DEFAULT NULL,
  `archived_reason` varchar(100) DEFAULT '',
  `archived_date` datetime DEFAULT NULL,
  `hide_from_drug_profile` tinyint(1) DEFAULT '0',
  `eTreatmentType` varchar(20) DEFAULT NULL,
  `rxStatus` varchar(20) DEFAULT NULL,
  `dispense_interval` varchar(100) DEFAULT NULL,
  `refill_duration` int(10) DEFAULT NULL,
  `refill_quantity` int(10) DEFAULT NULL,
  `hide_cpp` tinyint(1) DEFAULT NULL,
  `position` int(10) NOT NULL,
  `comment` varchar(255) DEFAULT NULL,
  `start_date_unknown` tinyint(1) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `dispenseInternal` tinyint(1) NOT NULL,
  `protocol` varchar(255) DEFAULT NULL,
  `priorRxProtocol` varchar(255) DEFAULT NULL,
  `pharmacyId` int(11) DEFAULT NULL,
  PRIMARY KEY (`drugid`)
);

--
-- Table structure for table `dsGuidelineProviderMap`
--


CREATE TABLE `dsGuidelineProviderMap` (
  `mapid` int(11) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(11) NOT NULL,
  `guideline_uuid` varchar(60) NOT NULL,
  PRIMARY KEY (`mapid`)
);

--
-- Table structure for table `dsGuidelines`
--


CREATE TABLE `dsGuidelines` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(60) NOT NULL,
  `title` varchar(100) NOT NULL,
  `version` int(11) DEFAULT NULL,
  `author` varchar(60) NOT NULL,
  `xml` text,
  `source` varchar(60) NOT NULL,
  `engine` varchar(60) NOT NULL,
  `dateStart` datetime DEFAULT NULL,
  `dateDecomissioned` datetime DEFAULT NULL,
  `status` varchar(1) DEFAULT 'A',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `dx_associations`
--


CREATE TABLE `dx_associations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `dx_codetype` varchar(50) NOT NULL,
  `dx_code` varchar(50) NOT NULL,
  `codetype` varchar(50) NOT NULL,
  `code` varchar(50) NOT NULL,
  `update_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `dxresearch`
--


CREATE TABLE `dxresearch` (
  `dxresearch_no` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT '0',
  `start_date` date DEFAULT '0001-01-01',
  `update_date` datetime NOT NULL,
  `status` char(1) DEFAULT 'A',
  `dxresearch_code` varchar(10) DEFAULT '',
  `coding_system` varchar(20) DEFAULT NULL,
  `association` tinyint(1) NOT NULL DEFAULT '0',
  `providerNo` varchar(6) DEFAULT NULL,
  PRIMARY KEY (`dxresearch_no`)
);

--
-- Table structure for table `eChart`
--


CREATE TABLE `eChart` (
  `eChartId` int(15) NOT NULL AUTO_INCREMENT,
  `timeStamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `demographicNo` int(10) NOT NULL DEFAULT '0',
  `providerNo` varchar(6) NOT NULL DEFAULT '',
  `subject` varchar(128) DEFAULT NULL,
  `socialHistory` text,
  `familyHistory` text,
  `medicalHistory` text,
  `ongoingConcerns` text,
  `reminders` text,
  `encounter` text,
  PRIMARY KEY (`eChartId`),
  KEY `demographicno` (`demographicNo`)
);

--
-- Table structure for table `eform`
--


CREATE TABLE `eform` (
  `fid` int(8) NOT NULL AUTO_INCREMENT,
  `form_name` varchar(255) DEFAULT NULL,
  `file_name` varchar(255) DEFAULT NULL,
  `subject` varchar(255) DEFAULT NULL,
  `form_date` date DEFAULT NULL,
  `form_time` time DEFAULT NULL,
  `form_creator` varchar(255) DEFAULT NULL,
  `status` tinyint(1) NOT NULL DEFAULT '1',
  `form_html` mediumtext,
  `showLatestFormOnly` tinyint(1) NOT NULL,
  `patient_independent` tinyint(1) NOT NULL,
  `roleType` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`fid`),
  UNIQUE KEY `id` (`fid`)
);

--
-- Table structure for table `eform_data`
--


CREATE TABLE `eform_data` (
  `fdid` int(8) NOT NULL AUTO_INCREMENT,
  `fid` int(8) NOT NULL DEFAULT '0',
  `form_name` varchar(255) DEFAULT NULL,
  `subject` varchar(255) DEFAULT NULL,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `status` tinyint(1) NOT NULL DEFAULT '1',
  `form_date` date DEFAULT NULL,
  `form_time` time DEFAULT NULL,
  `form_provider` varchar(255) DEFAULT NULL,
  `form_data` mediumtext,
  `showLatestFormOnly` tinyint(1) NOT NULL,
  `patient_independent` tinyint(1) NOT NULL,
  `roleType` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`fdid`),
  UNIQUE KEY `id` (`fdid`),
  KEY `idx_eform_data_demographic_no` (`demographic_no`),
  KEY `idx_eform_data_status` (`status`),
  KEY `idx_eform_data_from_date` (`form_date`),
  KEY `idx_eform_data_form_name` (`form_name`),
  KEY `idx_eform_data_subject` (`subject`),
  KEY `idx_eform_data_fid_status_demo` (`fid`, `status`, `demographic_no`),
  KEY `idx_eform_data_form_provider` (`form_provider`)
);

--
-- Table structure for table `eform_groups`
--


CREATE TABLE `eform_groups` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `fid` int(8) NOT NULL DEFAULT '0',
  `group_name` varchar(20) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `eform_values`
--


CREATE TABLE `eform_values` (
  `id` int(16) NOT NULL AUTO_INCREMENT,
  `fdid` int(8) DEFAULT NULL,
  `fid` int(8) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT '0',
  `var_name` varchar(30) NOT NULL DEFAULT '',
  `var_value` text,
  PRIMARY KEY (`id`),
  KEY `eform_values_varname_varvalue` (`var_name`,`var_value`(30))
);

--
-- Table structure for table `encounter`
--


CREATE TABLE `encounter` (
  `encounter_no` int(12) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `encounter_date` date NOT NULL DEFAULT '0001-01-01',
  `encounter_time` time NOT NULL DEFAULT '00:00:00',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `subject` varchar(100) DEFAULT NULL,
  `content` text,
  `encounterattachment` text,
  PRIMARY KEY (`encounter_no`)
);

--
-- Table structure for table `encounterForm`
--


CREATE TABLE `encounterForm` (
  `form_name` varchar(30) NOT NULL DEFAULT '',
  `form_value` varchar(255) NOT NULL DEFAULT '',
  `form_table` varchar(50) NOT NULL DEFAULT '',
  `hidden` int(5) NOT NULL DEFAULT '0'
);

--
-- Table structure for table `encounterWindow`
--


CREATE TABLE `encounterWindow` (
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `rowOneSize` int(10) NOT NULL DEFAULT '60',
  `rowTwoSize` int(10) NOT NULL DEFAULT '60',
  `presBoxSize` int(10) NOT NULL DEFAULT '30',
  `rowThreeSize` int(10) NOT NULL DEFAULT '378',
  PRIMARY KEY (`provider_no`)
);

--
-- Table structure for table `encountertemplate`
--


CREATE TABLE `encountertemplate` (
  `encountertemplate_name` varchar(50) NOT NULL DEFAULT '',
  `createdatetime` datetime DEFAULT NULL,
  `encountertemplate_value` text,
  `creator` varchar(6) DEFAULT NULL,
  PRIMARY KEY (`encountertemplate_name`),
  KEY `encountertemplate_url` (`createdatetime`)
);

--
-- Table structure for table `erefer_attachment`
--


CREATE TABLE `erefer_attachment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(11) DEFAULT NULL,
  `created` datetime DEFAULT NULL,
  `archived` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `erefer_attachment_data`
--


CREATE TABLE `erefer_attachment_data` (
  `erefer_attachment_id` int(11) NOT NULL DEFAULT '0',
  `lab_id` int(11) NOT NULL DEFAULT '0',
  `lab_type` varchar(20) NOT NULL DEFAULT '',
  PRIMARY KEY (`erefer_attachment_id`,`lab_id`,`lab_type`)
);

--
-- Table structure for table `eyeform_macro_billing`
--


CREATE TABLE `eyeform_macro_billing` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `macroId` int(11) DEFAULT NULL,
  `billingServiceCode` varchar(50) DEFAULT NULL,
  `multiplier` double DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `eyeform_macro_def`
--


CREATE TABLE `eyeform_macro_def` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `macroName` varchar(255) DEFAULT NULL,
  `lastUpdated` datetime DEFAULT NULL,
  `copyFromLastImpression` tinyint(1) DEFAULT NULL,
  `impressionText` text,
  `planText` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `favorites`
--


CREATE TABLE `favorites` (
  `favoriteid` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `favoritename` varchar(50) NOT NULL DEFAULT '',
  `BN` varchar(255) DEFAULT NULL,
  `GCN_SEQNO` decimal(10,0) NOT NULL DEFAULT '0',
  `customName` varchar(60) DEFAULT NULL,
  `takemin` float DEFAULT NULL,
  `takemax` float DEFAULT NULL,
  `freqcode` varchar(6) DEFAULT NULL,
  `duration` varchar(4) DEFAULT NULL,
  `durunit` char(1) DEFAULT NULL,
  `quantity` varchar(20) DEFAULT NULL,
  `repeat` tinyint(4) DEFAULT NULL,
  `nosubs` tinyint(1) NOT NULL DEFAULT '0',
  `prn` tinyint(1) NOT NULL DEFAULT '0',
  `special` varchar(255) NOT NULL DEFAULT '',
  `GN` varchar(255) DEFAULT NULL,
  `ATC` varchar(255) DEFAULT NULL,
  `regional_identifier` varchar(100) DEFAULT NULL,
  `unit` varchar(5) DEFAULT 'tab',
  `method` varchar(5) DEFAULT 'Take',
  `route` varchar(5) DEFAULT 'PO',
  `drug_form` varchar(50) DEFAULT NULL,
  `dosage` text,
  `custom_instructions` tinyint(1) DEFAULT '0',
  `unitName` varchar(10) DEFAULT NULL,
  `dispenseInternal` tinyint(1) NOT NULL,
  PRIMARY KEY (`favoriteid`)
);

--
-- Table structure for table `favoritesprivilege`
--


CREATE TABLE `favoritesprivilege` (
  `id` int(4) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `opentopublic` tinyint(1) DEFAULT NULL,
  `writeable` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `fax_config`
--


CREATE TABLE `fax_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) DEFAULT NULL,
  `siteUser` varchar(255) DEFAULT NULL,
  `passwd` varchar(255) DEFAULT NULL,
  `faxUser` varchar(255) DEFAULT NULL,
  `faxPasswd` varchar(255) DEFAULT NULL,
  `queue` varchar(255) DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `faxNumber` varchar(10) DEFAULT NULL,
  `senderEmail` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `faxes`
--


CREATE TABLE `faxes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filename` varchar(255) DEFAULT NULL,
  `faxline` varchar(11) DEFAULT NULL,
  `destination` varchar(11) DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `statusString` varchar(255) DEFAULT NULL,
  `document` text,
  `numPages` int(11) DEFAULT NULL,
  `stamp` datetime DEFAULT NULL,
  `user` varchar(255) DEFAULT NULL,
  `jobId` int(11) DEFAULT NULL,
  `oscarUser` varchar(6) DEFAULT NULL,
  `demographicNo` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `faxline` (`faxline`),
  KEY `faxstatus` (`status`)
);

--
-- Table structure for table `fileUploadCheck`
--


CREATE TABLE `fileUploadCheck` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `filename` varchar(255) NOT NULL DEFAULT '',
  `md5sum` varchar(255) DEFAULT NULL,
  `date_time` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `flowsheet_customization`
--


CREATE TABLE `flowsheet_customization` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `flowsheet` varchar(40) DEFAULT NULL,
  `action` varchar(10) DEFAULT NULL,
  `measurement` varchar(255) DEFAULT NULL,
  `payload` text,
  `provider_no` varchar(6) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `create_date` datetime DEFAULT NULL,
  `archived` char(1) DEFAULT '0',
  `archived_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `flowsheet_drug`
--


CREATE TABLE `flowsheet_drug` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `flowsheet` varchar(40) DEFAULT NULL,
  `atc_code` varchar(40) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `create_date` datetime DEFAULT NULL,
  `archived` char(1) DEFAULT '0',
  `archived_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `flowsheet_dx`
--


CREATE TABLE `flowsheet_dx` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `flowsheet` varchar(40) DEFAULT NULL,
  `dx_code` varchar(40) DEFAULT NULL,
  `dx_code_type` varchar(40) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `create_date` datetime DEFAULT NULL,
  `archived` char(1) DEFAULT '0',
  `archived_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `form`
--


CREATE TABLE `form` (
  `form_no` int(12) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `form_date` date NOT NULL DEFAULT '0001-01-01',
  `form_time` time NOT NULL DEFAULT '00:00:00',
  `form_name` varchar(50) DEFAULT NULL,
  `content` text,
  PRIMARY KEY (`form_no`),
  KEY `form_select` (`demographic_no`,`form_name`)
);

--
-- Table structure for table `form2MinWalk`
--


CREATE TABLE `form2MinWalk` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `distance` varchar(255) DEFAULT NULL,
  `Q1tried` tinyint(1) DEFAULT NULL,
  `Q1FullTandem3To9` tinyint(1) DEFAULT NULL,
  `Q1SideBySide10` tinyint(1) DEFAULT NULL,
  `Q1FullTandem10` tinyint(1) DEFAULT NULL,
  `Q1SemiTandem10` tinyint(1) DEFAULT NULL,
  `Q1Cmt` varchar(255) DEFAULT NULL,
  `Q2time1` varchar(255) DEFAULT NULL,
  `Q2time2` varchar(255) DEFAULT NULL,
  `Q2Cmt` varchar(255) DEFAULT NULL,
  `Q3Unable` tinyint(1) DEFAULT NULL,
  `Q3From11To13s` tinyint(1) DEFAULT NULL,
  `Q3LessThan16s` tinyint(1) DEFAULT NULL,
  `Q3LessThan11s` tinyint(1) DEFAULT NULL,
  `Q3From13To16s` tinyint(1) DEFAULT NULL,
  `Q3Cmt` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formAR`
--



--
-- Table structure for table `formAdf`
--


CREATE TABLE `formAdf` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `c_patientname` varchar(60) DEFAULT NULL,
  `residentno` varchar(20) DEFAULT NULL,
  `c_physician` varchar(60) DEFAULT NULL,
  `c_address` varchar(80) DEFAULT NULL,
  `c_phone` varchar(20) DEFAULT NULL,
  `cComplait` text,
  `histPresIll` text,
  `childhood` varchar(80) DEFAULT NULL,
  `adult` varchar(80) DEFAULT NULL,
  `operations` varchar(80) DEFAULT NULL,
  `injuries` varchar(80) DEFAULT NULL,
  `mentalIll` varchar(80) DEFAULT NULL,
  `familyHist` text,
  `socialHist` text,
  `general` varchar(80) DEFAULT NULL,
  `histSkin` varchar(80) DEFAULT NULL,
  `headNeck` varchar(80) DEFAULT NULL,
  `respiratory` varchar(80) DEFAULT NULL,
  `cardiovascular` varchar(80) DEFAULT NULL,
  `gi` varchar(80) DEFAULT NULL,
  `gu` varchar(80) DEFAULT NULL,
  `cns` varchar(80) DEFAULT NULL,
  `histExtremities` varchar(80) DEFAULT NULL,
  `allergies` text,
  `sensitivityDrug` text,
  `currentMedication` text,
  `temp` varchar(80) DEFAULT NULL,
  `pulse` varchar(80) DEFAULT NULL,
  `resp` varchar(80) DEFAULT NULL,
  `bp` varchar(80) DEFAULT NULL,
  `height` varchar(80) DEFAULT NULL,
  `weight` varchar(80) DEFAULT NULL,
  `physicalCondition` text,
  `mentalCondition` text,
  `skin` varchar(80) DEFAULT NULL,
  `eyes` varchar(80) DEFAULT NULL,
  `ears` varchar(80) DEFAULT NULL,
  `nose` varchar(80) DEFAULT NULL,
  `mouthTeeth` varchar(80) DEFAULT NULL,
  `throat` varchar(80) DEFAULT NULL,
  `neck` varchar(80) DEFAULT NULL,
  `chest` varchar(80) DEFAULT NULL,
  `heart` varchar(80) DEFAULT NULL,
  `abdomen` varchar(80) DEFAULT NULL,
  `genitalia` varchar(80) DEFAULT NULL,
  `lymphatics` varchar(80) DEFAULT NULL,
  `bloodVessels` varchar(80) DEFAULT NULL,
  `locomotor` varchar(80) DEFAULT NULL,
  `extremities` varchar(80) DEFAULT NULL,
  `rectal` varchar(80) DEFAULT NULL,
  `vaginal` varchar(80) DEFAULT NULL,
  `neurological` varchar(80) DEFAULT NULL,
  `behaviorProblem` text,
  `functionalLimitation` text,
  `diagnoses` text,
  `sigDate` date DEFAULT NULL,
  `signature` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formAdfV2`
--


CREATE TABLE `formAdfV2` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `c_patientname` varchar(60) DEFAULT NULL,
  `sendFacility` varchar(80) DEFAULT NULL,
  `poaSdm` varchar(80) DEFAULT NULL,
  `capTreatDecY` tinyint(1) DEFAULT NULL,
  `capTreatDecN` tinyint(1) DEFAULT NULL,
  `advDirective` varchar(100) DEFAULT NULL,
  `actProblem` text,
  `inactProblem` text,
  `courseOverYear` text,
  `medications` text,
  `allergy` varchar(255) DEFAULT NULL,
  `diet` varchar(255) DEFAULT NULL,
  `influDate` date DEFAULT NULL,
  `pneuDate` date DEFAULT NULL,
  `mantDateRes` varchar(50) DEFAULT NULL,
  `immuOthers` varchar(50) DEFAULT NULL,
  `pertLabInvest` text,
  `communication` varchar(100) DEFAULT NULL,
  `appetDysphWeight` varchar(100) DEFAULT NULL,
  `sleepEnergy` varchar(100) DEFAULT NULL,
  `depreSymptom` varchar(100) DEFAULT NULL,
  `problemBehav` varchar(100) DEFAULT NULL,
  `funcStatus` varchar(100) DEFAULT NULL,
  `fallFracture` varchar(100) DEFAULT NULL,
  `pain` varchar(100) DEFAULT NULL,
  `continence` varchar(100) DEFAULT NULL,
  `sysSkin` varchar(100) DEFAULT NULL,
  `socialSupp` varchar(100) DEFAULT NULL,
  `sysOther` varchar(100) DEFAULT NULL,
  `phyWeight` varchar(10) DEFAULT NULL,
  `phyHeight` varchar(10) DEFAULT NULL,
  `phyBPlying` varchar(16) DEFAULT NULL,
  `phyBPStanding` varchar(16) DEFAULT NULL,
  `phyGenAppear` varchar(100) DEFAULT NULL,
  `phyEyes` varchar(50) DEFAULT NULL,
  `phyEars` varchar(50) DEFAULT NULL,
  `phyOralHygeine` varchar(50) DEFAULT NULL,
  `phyBreast` varchar(50) DEFAULT NULL,
  `phyCardHeartSound` varchar(30) DEFAULT NULL,
  `phyPeriPulse` varchar(30) DEFAULT NULL,
  `phyOther` varchar(30) DEFAULT NULL,
  `phyRespiratory` varchar(100) DEFAULT NULL,
  `phyNeurological` varchar(30) DEFAULT NULL,
  `phyReflexes` varchar(30) DEFAULT NULL,
  `phyBabinski` varchar(30) DEFAULT NULL,
  `phyPower` varchar(30) DEFAULT NULL,
  `phyTone` varchar(30) DEFAULT NULL,
  `phyPowerOther` varchar(30) DEFAULT NULL,
  `phyMMSE` varchar(20) DEFAULT NULL,
  `phyComment` varchar(80) DEFAULT NULL,
  `phySkin` varchar(100) DEFAULT NULL,
  `phyAbdomen` varchar(80) DEFAULT NULL,
  `highRiskProb1` varchar(80) DEFAULT NULL,
  `investPlanCare1` varchar(80) DEFAULT NULL,
  `highRiskProb2` varchar(80) DEFAULT NULL,
  `investPlanCare2` varchar(80) DEFAULT NULL,
  `highRiskProb3` varchar(80) DEFAULT NULL,
  `investPlanCare3` varchar(80) DEFAULT NULL,
  `highRiskProb4` varchar(80) DEFAULT NULL,
  `investPlanCare4` varchar(80) DEFAULT NULL,
  `sigDate` date DEFAULT NULL,
  `signature` varchar(60) DEFAULT NULL,
  `sigName` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formAlpha`
--


CREATE TABLE `formAlpha` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `pName` varchar(60) DEFAULT NULL,
  `socialSupport` text,
  `lifeEvents` text,
  `coupleRelationship` text,
  `prenatalCare` text,
  `prenatalEducation` text,
  `feelingsRePregnancy` text,
  `relationshipParents` text,
  `selfEsteem` text,
  `psychHistory` text,
  `depression` text,
  `alcoholDrugAbuse` text,
  `abuse` text,
  `womanAbuse` text,
  `childAbuse` text,
  `childDiscipline` text,
  `provCounselling` tinyint(1) DEFAULT NULL,
  `homecare` tinyint(1) DEFAULT NULL,
  `assaultedWomen` tinyint(1) DEFAULT NULL,
  `addAppts` tinyint(1) DEFAULT NULL,
  `parentingClasses` tinyint(1) DEFAULT NULL,
  `legalAdvice` tinyint(1) DEFAULT NULL,
  `postpartumAppts` tinyint(1) DEFAULT NULL,
  `addictPrograms` tinyint(1) DEFAULT NULL,
  `cas` tinyint(1) DEFAULT NULL,
  `babyVisits` tinyint(1) DEFAULT NULL,
  `quitSmoking` tinyint(1) DEFAULT NULL,
  `other1` tinyint(1) DEFAULT NULL,
  `other1Name` varchar(30) DEFAULT NULL,
  `publicHealth` tinyint(1) DEFAULT NULL,
  `socialWorker` tinyint(1) DEFAULT NULL,
  `other2` tinyint(1) DEFAULT NULL,
  `other2Name` varchar(30) DEFAULT NULL,
  `prenatalEdu` tinyint(1) DEFAULT NULL,
  `psych` tinyint(1) DEFAULT NULL,
  `other3` tinyint(1) DEFAULT NULL,
  `other3Name` varchar(30) DEFAULT NULL,
  `nutritionist` tinyint(1) DEFAULT NULL,
  `therapist` tinyint(1) DEFAULT NULL,
  `other4` tinyint(1) DEFAULT NULL,
  `other4Name` varchar(30) DEFAULT NULL,
  `resources` tinyint(1) DEFAULT NULL,
  `comments` text,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formAnnual`
--


CREATE TABLE `formAnnual` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `pName` varchar(60) DEFAULT NULL,
  `age` char(3) DEFAULT NULL,
  `formDate` date DEFAULT NULL,
  `currentConcerns` text,
  `currentConcernsNo` tinyint(1) DEFAULT NULL,
  `currentConcernsYes` tinyint(1) DEFAULT NULL,
  `headN` tinyint(1) DEFAULT NULL,
  `headAbN` tinyint(1) DEFAULT NULL,
  `head` varchar(30) DEFAULT NULL,
  `respN` tinyint(1) DEFAULT NULL,
  `respAbN` tinyint(1) DEFAULT NULL,
  `resp` varchar(30) DEFAULT NULL,
  `cardioN` tinyint(1) DEFAULT NULL,
  `cardioAbN` tinyint(1) DEFAULT NULL,
  `cardio` varchar(30) DEFAULT NULL,
  `giN` tinyint(1) DEFAULT NULL,
  `giAbN` tinyint(1) DEFAULT NULL,
  `gi` varchar(30) DEFAULT NULL,
  `guN` tinyint(1) DEFAULT NULL,
  `guAbN` tinyint(1) DEFAULT NULL,
  `gu` varchar(30) DEFAULT NULL,
  `noGtpalRevisions` tinyint(1) DEFAULT NULL,
  `yesGtpalRevisions` tinyint(1) DEFAULT NULL,
  `frontSheet` tinyint(1) DEFAULT NULL,
  `lmp` date DEFAULT NULL,
  `menopause` char(3) DEFAULT NULL,
  `papSmearsN` tinyint(1) DEFAULT NULL,
  `papSmearsAbN` tinyint(1) DEFAULT NULL,
  `papSmears` varchar(30) DEFAULT NULL,
  `skinN` tinyint(1) DEFAULT NULL,
  `skinAbN` tinyint(1) DEFAULT NULL,
  `skin` varchar(30) DEFAULT NULL,
  `mskN` tinyint(1) DEFAULT NULL,
  `mskAbN` tinyint(1) DEFAULT NULL,
  `msk` varchar(30) DEFAULT NULL,
  `endocrinN` tinyint(1) DEFAULT NULL,
  `endocrinAbN` tinyint(1) DEFAULT NULL,
  `endocrin` varchar(30) DEFAULT NULL,
  `otherN` tinyint(1) DEFAULT NULL,
  `otherAbN` tinyint(1) DEFAULT NULL,
  `other` varchar(255) DEFAULT NULL,
  `drugs` tinyint(1) DEFAULT NULL,
  `medSheet` tinyint(1) DEFAULT NULL,
  `allergies` tinyint(1) DEFAULT NULL,
  `frontSheet1` tinyint(1) DEFAULT NULL,
  `familyHistory` tinyint(1) DEFAULT NULL,
  `frontSheet2` tinyint(1) DEFAULT NULL,
  `smokingNo` tinyint(1) DEFAULT NULL,
  `smokingYes` tinyint(1) DEFAULT NULL,
  `smoking` varchar(30) DEFAULT NULL,
  `sexualityNo` tinyint(1) DEFAULT NULL,
  `sexualityYes` tinyint(1) DEFAULT NULL,
  `sexuality` varchar(30) DEFAULT NULL,
  `alcoholNo` tinyint(1) DEFAULT NULL,
  `alcoholYes` tinyint(1) DEFAULT NULL,
  `alcohol` varchar(30) DEFAULT NULL,
  `occupationalNo` tinyint(1) DEFAULT NULL,
  `occupationalYes` tinyint(1) DEFAULT NULL,
  `occupational` varchar(30) DEFAULT NULL,
  `otcNo` tinyint(1) DEFAULT NULL,
  `otcYes` tinyint(1) DEFAULT NULL,
  `otc` varchar(30) DEFAULT NULL,
  `drivingNo` tinyint(1) DEFAULT NULL,
  `drivingYes` tinyint(1) DEFAULT NULL,
  `driving` varchar(30) DEFAULT NULL,
  `exerciseNo` tinyint(1) DEFAULT NULL,
  `exerciseYes` tinyint(1) DEFAULT NULL,
  `exercise` varchar(30) DEFAULT NULL,
  `travelNo` tinyint(1) DEFAULT NULL,
  `travelYes` tinyint(1) DEFAULT NULL,
  `travel` varchar(30) DEFAULT NULL,
  `nutritionNo` tinyint(1) DEFAULT NULL,
  `nutritionYes` tinyint(1) DEFAULT NULL,
  `nutrition` varchar(30) DEFAULT NULL,
  `otherNo` tinyint(1) DEFAULT NULL,
  `otherYes` tinyint(1) DEFAULT NULL,
  `otherLifestyle` varchar(255) DEFAULT NULL,
  `dentalNo` tinyint(1) DEFAULT NULL,
  `dentalYes` tinyint(1) DEFAULT NULL,
  `dental` varchar(30) DEFAULT NULL,
  `relationshipNo` tinyint(1) DEFAULT NULL,
  `relationshipYes` tinyint(1) DEFAULT NULL,
  `relationship` varchar(150) DEFAULT NULL,
  `mammogram` tinyint(1) DEFAULT NULL,
  `rectal` tinyint(1) DEFAULT NULL,
  `breast` tinyint(1) DEFAULT NULL,
  `maleCardiac` tinyint(1) DEFAULT NULL,
  `pap` tinyint(1) DEFAULT NULL,
  `maleImmunization` tinyint(1) DEFAULT NULL,
  `femaleImmunization` tinyint(1) DEFAULT NULL,
  `maleOther1c` tinyint(1) DEFAULT NULL,
  `maleOther1` varchar(30) DEFAULT NULL,
  `precontraceptive` tinyint(1) DEFAULT NULL,
  `maleOther2c` tinyint(1) DEFAULT NULL,
  `maleOther2` varchar(30) DEFAULT NULL,
  `femaleCardiac` tinyint(1) DEFAULT NULL,
  `osteoporosis` tinyint(1) DEFAULT NULL,
  `femaleOther1c` tinyint(1) DEFAULT NULL,
  `femaleOther1` varchar(30) DEFAULT NULL,
  `femaleOther2c` tinyint(1) DEFAULT NULL,
  `femaleOther2` varchar(30) DEFAULT NULL,
  `bprTop` char(3) DEFAULT NULL,
  `bprBottom` char(3) DEFAULT NULL,
  `pulse` varchar(10) DEFAULT NULL,
  `height` varchar(4) DEFAULT NULL,
  `weight` varchar(4) DEFAULT NULL,
  `bplTop` char(3) DEFAULT NULL,
  `bplBottom` char(3) DEFAULT NULL,
  `rhythm` varchar(10) DEFAULT NULL,
  `urine` varchar(30) DEFAULT NULL,
  `physicalSigns` text,
  `assessment` text,
  `plan` text,
  `signature` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formAnnualV2`
--


CREATE TABLE `formAnnualV2` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `pName` varchar(60) DEFAULT NULL,
  `age` char(3) DEFAULT NULL,
  `formDate` date DEFAULT NULL,
  `pmhxPshxUpdated` tinyint(1) DEFAULT NULL,
  `famHxUpdated` tinyint(1) DEFAULT NULL,
  `socHxUpdated` tinyint(1) DEFAULT NULL,
  `allergiesUpdated` tinyint(1) DEFAULT NULL,
  `medicationsUpdated` tinyint(1) DEFAULT NULL,
  `weight` varchar(4) DEFAULT NULL,
  `height` varchar(4) DEFAULT NULL,
  `waist` varchar(4) DEFAULT NULL,
  `lmp` date DEFAULT NULL,
  `BP` varchar(7) DEFAULT NULL,
  `smokingNo` tinyint(1) DEFAULT NULL,
  `smokingYes` tinyint(1) DEFAULT NULL,
  `smoking` varchar(100) DEFAULT NULL,
  `etohNo` tinyint(1) DEFAULT NULL,
  `etohYes` tinyint(1) DEFAULT NULL,
  `etoh` varchar(100) DEFAULT NULL,
  `caffineNo` tinyint(1) DEFAULT NULL,
  `caffineYes` tinyint(1) DEFAULT NULL,
  `caffine` varchar(100) DEFAULT NULL,
  `otcNo` tinyint(1) DEFAULT NULL,
  `otcYes` tinyint(1) DEFAULT NULL,
  `otc` varchar(100) DEFAULT NULL,
  `exerciseNo` tinyint(1) DEFAULT NULL,
  `exerciseYes` tinyint(1) DEFAULT NULL,
  `exercise` varchar(100) DEFAULT NULL,
  `nutritionNo` tinyint(1) DEFAULT NULL,
  `nutritionYes` tinyint(1) DEFAULT NULL,
  `nutrition` varchar(100) DEFAULT NULL,
  `dentalNo` tinyint(1) DEFAULT NULL,
  `dentalYes` tinyint(1) DEFAULT NULL,
  `dental` varchar(100) DEFAULT NULL,
  `occupationalNo` tinyint(1) DEFAULT NULL,
  `occupationalYes` tinyint(1) DEFAULT NULL,
  `occupational` varchar(100) DEFAULT NULL,
  `travelNo` tinyint(1) DEFAULT NULL,
  `travelYes` tinyint(1) DEFAULT NULL,
  `travel` varchar(100) DEFAULT NULL,
  `sexualityNo` tinyint(1) DEFAULT NULL,
  `sexualityYes` tinyint(1) DEFAULT NULL,
  `sexuality` varchar(100) DEFAULT NULL,
  `generalN` tinyint(1) DEFAULT NULL,
  `generalAbN` tinyint(1) DEFAULT NULL,
  `general` varchar(100) DEFAULT NULL,
  `headN` tinyint(1) DEFAULT NULL,
  `headAbN` tinyint(1) DEFAULT NULL,
  `head` varchar(100) DEFAULT NULL,
  `chestN` tinyint(1) DEFAULT NULL,
  `chestAbN` tinyint(1) DEFAULT NULL,
  `chest` varchar(100) DEFAULT NULL,
  `cvsN` tinyint(1) DEFAULT NULL,
  `cvsAbN` tinyint(1) DEFAULT NULL,
  `cvs` varchar(100) DEFAULT NULL,
  `giN` tinyint(1) DEFAULT NULL,
  `giAbN` tinyint(1) DEFAULT NULL,
  `gi` varchar(100) DEFAULT NULL,
  `guN` tinyint(1) DEFAULT NULL,
  `guAbN` tinyint(1) DEFAULT NULL,
  `gu` varchar(100) DEFAULT NULL,
  `cnsN` tinyint(1) DEFAULT NULL,
  `cnsAbN` tinyint(1) DEFAULT NULL,
  `cns` varchar(100) DEFAULT NULL,
  `mskN` tinyint(1) DEFAULT NULL,
  `mskAbN` tinyint(1) DEFAULT NULL,
  `msk` varchar(100) DEFAULT NULL,
  `skinN` tinyint(1) DEFAULT NULL,
  `skinAbN` tinyint(1) DEFAULT NULL,
  `skin` varchar(100) DEFAULT NULL,
  `moodN` tinyint(1) DEFAULT NULL,
  `moodAbN` tinyint(1) DEFAULT NULL,
  `mood` varchar(100) DEFAULT NULL,
  `otherN` tinyint(1) DEFAULT NULL,
  `otherAbN` tinyint(1) DEFAULT NULL,
  `other` text,
  `eyesN` tinyint(1) DEFAULT NULL,
  `eyesAbN` tinyint(1) DEFAULT NULL,
  `eyes` varchar(100) DEFAULT NULL,
  `earsN` tinyint(1) DEFAULT NULL,
  `earsAbN` tinyint(1) DEFAULT NULL,
  `ears` varchar(100) DEFAULT NULL,
  `oropharynxN` tinyint(1) DEFAULT NULL,
  `oropharynxAbN` tinyint(1) DEFAULT NULL,
  `oropharynx` varchar(100) DEFAULT NULL,
  `thyroidN` tinyint(1) DEFAULT NULL,
  `thyroidAbN` tinyint(1) DEFAULT NULL,
  `thyroid` varchar(100) DEFAULT NULL,
  `lnodesN` tinyint(1) DEFAULT NULL,
  `lnodesAbN` tinyint(1) DEFAULT NULL,
  `lnodes` varchar(100) DEFAULT NULL,
  `clearN` tinyint(1) DEFAULT NULL,
  `clearAbN` tinyint(1) DEFAULT NULL,
  `clear` varchar(100) DEFAULT NULL,
  `bilatN` tinyint(1) DEFAULT NULL,
  `bilatAbN` tinyint(1) DEFAULT NULL,
  `bilat` varchar(100) DEFAULT NULL,
  `wheezesN` tinyint(1) DEFAULT NULL,
  `wheezesAbN` tinyint(1) DEFAULT NULL,
  `wheezes` varchar(100) DEFAULT NULL,
  `cracklesN` tinyint(1) DEFAULT NULL,
  `cracklesAbN` tinyint(1) DEFAULT NULL,
  `crackles` varchar(100) DEFAULT NULL,
  `chestOther` varchar(100) DEFAULT NULL,
  `s1s2N` tinyint(1) DEFAULT NULL,
  `s1s2AbN` tinyint(1) DEFAULT NULL,
  `s1s2` varchar(100) DEFAULT NULL,
  `murmurN` tinyint(1) DEFAULT NULL,
  `murmurAbN` tinyint(1) DEFAULT NULL,
  `murmur` varchar(100) DEFAULT NULL,
  `periphPulseN` tinyint(1) DEFAULT NULL,
  `periphPulseAbN` tinyint(1) DEFAULT NULL,
  `periphPulse` varchar(100) DEFAULT NULL,
  `edemaN` tinyint(1) DEFAULT NULL,
  `edemaAbN` tinyint(1) DEFAULT NULL,
  `edema` varchar(100) DEFAULT NULL,
  `jvpN` tinyint(1) DEFAULT NULL,
  `jvpAbN` tinyint(1) DEFAULT NULL,
  `jvp` varchar(100) DEFAULT NULL,
  `rhythmN` tinyint(1) DEFAULT NULL,
  `rhythmAbN` tinyint(1) DEFAULT NULL,
  `rhythm` varchar(100) DEFAULT NULL,
  `chestbpN` tinyint(1) DEFAULT NULL,
  `chestbpAbN` tinyint(1) DEFAULT NULL,
  `chestbp` varchar(100) DEFAULT NULL,
  `cvsOther` varchar(100) DEFAULT NULL,
  `breastLeftN` tinyint(1) DEFAULT NULL,
  `breastLeftAbN` tinyint(1) DEFAULT NULL,
  `breastLeft` varchar(100) DEFAULT NULL,
  `breastRightN` tinyint(1) DEFAULT NULL,
  `breastRightAbN` tinyint(1) DEFAULT NULL,
  `breastRight` varchar(100) DEFAULT NULL,
  `softN` tinyint(1) DEFAULT NULL,
  `softAbN` tinyint(1) DEFAULT NULL,
  `soft` varchar(100) DEFAULT NULL,
  `tenderN` tinyint(1) DEFAULT NULL,
  `tenderAbN` tinyint(1) DEFAULT NULL,
  `tender` varchar(100) DEFAULT NULL,
  `bsN` tinyint(1) DEFAULT NULL,
  `bsAbN` tinyint(1) DEFAULT NULL,
  `bs` varchar(100) DEFAULT NULL,
  `hepatomegN` tinyint(1) DEFAULT NULL,
  `hepatomegAbN` tinyint(1) DEFAULT NULL,
  `hepatomeg` varchar(100) DEFAULT NULL,
  `splenomegN` tinyint(1) DEFAULT NULL,
  `splenomegAbN` tinyint(1) DEFAULT NULL,
  `splenomeg` varchar(100) DEFAULT NULL,
  `massesN` tinyint(1) DEFAULT NULL,
  `massesAbN` tinyint(1) DEFAULT NULL,
  `masses` varchar(100) DEFAULT NULL,
  `rectalN` tinyint(1) DEFAULT NULL,
  `rectalAbN` tinyint(1) DEFAULT NULL,
  `rectal` varchar(100) DEFAULT NULL,
  `cxN` tinyint(1) DEFAULT NULL,
  `cxAbN` tinyint(1) DEFAULT NULL,
  `cx` varchar(100) DEFAULT NULL,
  `bimanualN` tinyint(1) DEFAULT NULL,
  `bimanualAbN` tinyint(1) DEFAULT NULL,
  `bimanual` varchar(100) DEFAULT NULL,
  `adnexaN` tinyint(1) DEFAULT NULL,
  `adnexaAbN` tinyint(1) DEFAULT NULL,
  `adnexa` varchar(100) DEFAULT NULL,
  `papN` tinyint(1) DEFAULT NULL,
  `papAbN` tinyint(1) DEFAULT NULL,
  `pap` varchar(100) DEFAULT NULL,
  `exammskN` tinyint(1) DEFAULT NULL,
  `exammskAbN` tinyint(1) DEFAULT NULL,
  `exammsk` varchar(100) DEFAULT NULL,
  `examskinN` tinyint(1) DEFAULT NULL,
  `examskinAbN` tinyint(1) DEFAULT NULL,
  `examskin` varchar(100) DEFAULT NULL,
  `examcnsN` tinyint(1) DEFAULT NULL,
  `examcnsAbN` tinyint(1) DEFAULT NULL,
  `examcns` text,
  `impressionPlan` text,
  `toDoSexualHealth` text,
  `toDoObesity` text,
  `toDoCholesterol` text,
  `toDoOsteoporosis` text,
  `toDoPAPs` text,
  `toDoMammogram` text,
  `toDoColorectal` text,
  `toDoElderly` text,
  `immunizationtd` tinyint(1) DEFAULT NULL,
  `immunizationPneumovax` tinyint(1) DEFAULT NULL,
  `immunizationFlu` tinyint(1) DEFAULT NULL,
  `immunizationMenjugate` tinyint(1) DEFAULT NULL,
  `toDoImmunization` text,
  `signature` varchar(60) DEFAULT NULL,
  `examGenitaliaN` tinyint(1) DEFAULT NULL,
  `examGenitaliaAbN` tinyint(1) DEFAULT NULL,
  `examGenitalia` varchar(100) DEFAULT NULL,
  `toDoProstateCancer` text,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formBCHP`
--


CREATE TABLE `formBCHP` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE CURRENT_TIMESTAMP,
  `c_lastVisited` char(3) DEFAULT NULL,
  `pg1_formDate` date DEFAULT NULL,
  `pg1_patientName` varchar(40) DEFAULT NULL,
  `pg1_phn` varchar(20) DEFAULT NULL,
  `pg1_phone` varchar(15) DEFAULT NULL,
  `pg1_emergContact` varchar(40) DEFAULT NULL,
  `pg1_emergContactPhone` varchar(15) DEFAULT NULL,
  `pg1_allergies` varchar(90) DEFAULT NULL,
  `pg1_md` varchar(40) DEFAULT NULL,
  `pg1_msp` varchar(9) DEFAULT NULL,
  `pg1_mdPhone` varchar(15) DEFAULT NULL,
  `pg1_livingWillY` tinyint(1) DEFAULT NULL,
  `pg1_livingWillN` tinyint(1) DEFAULT NULL,
  `pg1_diabetes` tinyint(1) DEFAULT NULL,
  `pg1_atrialFib` tinyint(1) DEFAULT NULL,
  `pg1_coronary` tinyint(1) DEFAULT NULL,
  `pg1_highBP` tinyint(1) DEFAULT NULL,
  `pg1_chf` tinyint(1) DEFAULT NULL,
  `pg1_stroke` tinyint(1) DEFAULT NULL,
  `pg1_kidneyDisease` tinyint(1) DEFAULT NULL,
  `pg1_lowGFR` varchar(10) DEFAULT NULL,
  `pg1_asthma` tinyint(1) DEFAULT NULL,
  `pg1_copd` tinyint(1) DEFAULT NULL,
  `pg1_co2retainer` tinyint(1) DEFAULT NULL,
  `pg1_cancer` tinyint(1) DEFAULT NULL,
  `pg1_cancerSpec` varchar(40) DEFAULT NULL,
  `pg1_other` tinyint(1) DEFAULT NULL,
  `pg1_otherSpec` varchar(90) DEFAULT NULL,
  `pg1_majorSurg` tinyint(1) DEFAULT NULL,
  `pg1_majorSurgSpec` varchar(80) DEFAULT NULL,
  `pg1_date1` date DEFAULT NULL,
  `pg1_medName1` varchar(30) DEFAULT NULL,
  `pg1_dose1` varchar(10) DEFAULT NULL,
  `pg1_howOften1` varchar(10) DEFAULT NULL,
  `pg1_reason1` varchar(20) DEFAULT NULL,
  `pg1_date2` date DEFAULT NULL,
  `pg1_medName2` varchar(30) DEFAULT NULL,
  `pg1_dose2` varchar(10) DEFAULT NULL,
  `pg1_howOften2` varchar(10) DEFAULT NULL,
  `pg1_reason2` varchar(20) DEFAULT NULL,
  `pg1_date3` date DEFAULT NULL,
  `pg1_medName3` varchar(30) DEFAULT NULL,
  `pg1_dose3` varchar(10) DEFAULT NULL,
  `pg1_howOften3` varchar(10) DEFAULT NULL,
  `pg1_reason3` varchar(20) DEFAULT NULL,
  `pg1_date4` date DEFAULT NULL,
  `pg1_medName4` varchar(30) DEFAULT NULL,
  `pg1_dose4` varchar(10) DEFAULT NULL,
  `pg1_howOften4` varchar(10) DEFAULT NULL,
  `pg1_reason4` varchar(20) DEFAULT NULL,
  `pg1_date5` date DEFAULT NULL,
  `pg1_medName5` varchar(30) DEFAULT NULL,
  `pg1_dose5` varchar(10) DEFAULT NULL,
  `pg1_howOften5` varchar(10) DEFAULT NULL,
  `pg1_reason5` varchar(20) DEFAULT NULL,
  `pg1_date6` date DEFAULT NULL,
  `pg1_medName6` varchar(30) DEFAULT NULL,
  `pg1_dose6` varchar(10) DEFAULT NULL,
  `pg1_howOften6` varchar(10) DEFAULT NULL,
  `pg1_reason6` varchar(20) DEFAULT NULL,
  `pg1_date7` date DEFAULT NULL,
  `pg1_medName7` varchar(30) DEFAULT NULL,
  `pg1_dose7` varchar(10) DEFAULT NULL,
  `pg1_howOften7` varchar(10) DEFAULT NULL,
  `pg1_reason7` varchar(20) DEFAULT NULL,
  `pg1_date8` date DEFAULT NULL,
  `pg1_medName8` varchar(30) DEFAULT NULL,
  `pg1_dose8` varchar(10) DEFAULT NULL,
  `pg1_howOften8` varchar(10) DEFAULT NULL,
  `pg1_reason8` varchar(20) DEFAULT NULL,
  `pg1_date9` date DEFAULT NULL,
  `pg1_medName9` varchar(30) DEFAULT NULL,
  `pg1_dose9` varchar(10) DEFAULT NULL,
  `pg1_howOften9` varchar(10) DEFAULT NULL,
  `pg1_reason9` varchar(20) DEFAULT NULL,
  `pg1_date10` date DEFAULT NULL,
  `pg1_medName10` varchar(30) DEFAULT NULL,
  `pg1_dose10` varchar(10) DEFAULT NULL,
  `pg1_howOften10` varchar(10) DEFAULT NULL,
  `pg1_reason10` varchar(20) DEFAULT NULL,
  `pg1_date11` date DEFAULT NULL,
  `pg1_medName11` varchar(30) DEFAULT NULL,
  `pg1_dose11` varchar(10) DEFAULT NULL,
  `pg1_howOften11` varchar(10) DEFAULT NULL,
  `pg1_reason11` varchar(20) DEFAULT NULL,
  `pg1_date12` date DEFAULT NULL,
  `pg1_medName12` varchar(30) DEFAULT NULL,
  `pg1_dose12` varchar(10) DEFAULT NULL,
  `pg1_howOften12` varchar(10) DEFAULT NULL,
  `pg1_reason12` varchar(20) DEFAULT NULL,
  `pg1_date13` date DEFAULT NULL,
  `pg1_medName13` varchar(30) DEFAULT NULL,
  `pg1_dose13` varchar(10) DEFAULT NULL,
  `pg1_howOften13` varchar(10) DEFAULT NULL,
  `pg1_reason13` varchar(20) DEFAULT NULL,
  `pg1_date14` date DEFAULT NULL,
  `pg1_medName14` varchar(30) DEFAULT NULL,
  `pg1_dose14` varchar(10) DEFAULT NULL,
  `pg1_howOften14` varchar(10) DEFAULT NULL,
  `pg1_reason14` varchar(20) DEFAULT NULL,
  `pg1_fluDate1` date DEFAULT NULL,
  `pg1_fluDate2` date DEFAULT NULL,
  `pg1_fluDate3` date DEFAULT NULL,
  `pg1_fluDate4` date DEFAULT NULL,
  `pg1_fluDate5` date DEFAULT NULL,
  `pg1_fluDate6` date DEFAULT NULL,
  `pg1_fluDate7` date DEFAULT NULL,
  `pg1_pneumoVaccDate1` date DEFAULT NULL,
  `pg1_pneumoVaccDate2` date DEFAULT NULL,
  `pg1_pneumoVaccDate3` date DEFAULT NULL,
  `pg1_pneumoVaccDate4` date DEFAULT NULL,
  `pg1_pneumoVaccDate5` date DEFAULT NULL,
  `pg1_pneumoVaccDate6` date DEFAULT NULL,
  `pg1_pneumoVaccDate7` date DEFAULT NULL,
  `pg1_tdDate1` date DEFAULT NULL,
  `pg1_tdDate2` date DEFAULT NULL,
  `pg1_tdDate3` date DEFAULT NULL,
  `pg1_tdDate4` date DEFAULT NULL,
  `pg1_tdDate5` date DEFAULT NULL,
  `pg1_tdDate6` date DEFAULT NULL,
  `pg1_tdDate7` date DEFAULT NULL,
  `pg1_hepaDate1` date DEFAULT NULL,
  `pg1_hepaDate2` date DEFAULT NULL,
  `pg1_hepaDate3` date DEFAULT NULL,
  `pg1_hepaDate4` date DEFAULT NULL,
  `pg1_hepaDate5` date DEFAULT NULL,
  `pg1_hepaDate6` date DEFAULT NULL,
  `pg1_hepaDate7` date DEFAULT NULL,
  `pg1_hepbDate1` date DEFAULT NULL,
  `pg1_hepbDate2` date DEFAULT NULL,
  `pg1_hepbDate3` date DEFAULT NULL,
  `pg1_hepbDate4` date DEFAULT NULL,
  `pg1_hepbDate5` date DEFAULT NULL,
  `pg1_hepbDate6` date DEFAULT NULL,
  `pg1_hepbDate7` date DEFAULT NULL,
  `pg1_otherVac` varchar(30) DEFAULT NULL,
  `pg1_otherDate1` date DEFAULT NULL,
  `pg1_otherDate2` date DEFAULT NULL,
  `pg1_otherDate3` date DEFAULT NULL,
  `pg1_otherDate4` date DEFAULT NULL,
  `pg1_otherDate5` date DEFAULT NULL,
  `pg1_otherDate6` date DEFAULT NULL,
  `pg1_otherDate7` date DEFAULT NULL,
  `pg2_date1` date DEFAULT NULL,
  `pg2_medName1` varchar(30) DEFAULT NULL,
  `pg2_dose1` varchar(10) DEFAULT NULL,
  `pg2_howOften1` varchar(10) DEFAULT NULL,
  `pg2_reason1` varchar(20) DEFAULT NULL,
  `pg2_date2` date DEFAULT NULL,
  `pg2_medName2` varchar(30) DEFAULT NULL,
  `pg2_dose2` varchar(10) DEFAULT NULL,
  `pg2_howOften2` varchar(10) DEFAULT NULL,
  `pg2_reason2` varchar(20) DEFAULT NULL,
  `pg2_date3` date DEFAULT NULL,
  `pg2_medName3` varchar(30) DEFAULT NULL,
  `pg2_dose3` varchar(10) DEFAULT NULL,
  `pg2_howOften3` varchar(10) DEFAULT NULL,
  `pg2_reason3` varchar(20) DEFAULT NULL,
  `pg2_date4` date DEFAULT NULL,
  `pg2_medName4` varchar(30) DEFAULT NULL,
  `pg2_dose4` varchar(10) DEFAULT NULL,
  `pg2_howOften4` varchar(10) DEFAULT NULL,
  `pg2_reason4` varchar(20) DEFAULT NULL,
  `pg2_date5` date DEFAULT NULL,
  `pg2_medName5` varchar(30) DEFAULT NULL,
  `pg2_dose5` varchar(10) DEFAULT NULL,
  `pg2_howOften5` varchar(10) DEFAULT NULL,
  `pg2_reason5` varchar(20) DEFAULT NULL,
  `pg2_date6` date DEFAULT NULL,
  `pg2_medName6` varchar(30) DEFAULT NULL,
  `pg2_dose6` varchar(10) DEFAULT NULL,
  `pg2_howOften6` varchar(10) DEFAULT NULL,
  `pg2_reason6` varchar(20) DEFAULT NULL,
  `pg2_date7` date DEFAULT NULL,
  `pg2_medName7` varchar(30) DEFAULT NULL,
  `pg2_dose7` varchar(10) DEFAULT NULL,
  `pg2_howOften7` varchar(10) DEFAULT NULL,
  `pg2_reason7` varchar(20) DEFAULT NULL,
  `pg2_date8` date DEFAULT NULL,
  `pg2_medName8` varchar(30) DEFAULT NULL,
  `pg2_dose8` varchar(10) DEFAULT NULL,
  `pg2_howOften8` varchar(10) DEFAULT NULL,
  `pg2_reason8` varchar(20) DEFAULT NULL,
  `pg2_date9` date DEFAULT NULL,
  `pg2_medName9` varchar(30) DEFAULT NULL,
  `pg2_dose9` varchar(10) DEFAULT NULL,
  `pg2_howOften9` varchar(10) DEFAULT NULL,
  `pg2_reason9` varchar(20) DEFAULT NULL,
  `pg2_date10` date DEFAULT NULL,
  `pg2_medName10` varchar(30) DEFAULT NULL,
  `pg2_dose10` varchar(10) DEFAULT NULL,
  `pg2_howOften10` varchar(10) DEFAULT NULL,
  `pg2_reason10` varchar(20) DEFAULT NULL,
  `pg2_date11` date DEFAULT NULL,
  `pg2_medName11` varchar(30) DEFAULT NULL,
  `pg2_dose11` varchar(10) DEFAULT NULL,
  `pg2_howOften11` varchar(10) DEFAULT NULL,
  `pg2_reason11` varchar(20) DEFAULT NULL,
  `pg2_date12` date DEFAULT NULL,
  `pg2_medName12` varchar(30) DEFAULT NULL,
  `pg2_dose12` varchar(10) DEFAULT NULL,
  `pg2_howOften12` varchar(10) DEFAULT NULL,
  `pg2_reason12` varchar(20) DEFAULT NULL,
  `pg2_date13` date DEFAULT NULL,
  `pg2_medName13` varchar(30) DEFAULT NULL,
  `pg2_dose13` varchar(10) DEFAULT NULL,
  `pg2_howOften13` varchar(10) DEFAULT NULL,
  `pg2_reason13` varchar(20) DEFAULT NULL,
  `pg2_date14` date DEFAULT NULL,
  `pg2_medName14` varchar(30) DEFAULT NULL,
  `pg2_dose14` varchar(10) DEFAULT NULL,
  `pg2_howOften14` varchar(10) DEFAULT NULL,
  `pg2_reason14` varchar(20) DEFAULT NULL,
  `pg2_fluDate1` date DEFAULT NULL,
  `pg2_fluDate2` date DEFAULT NULL,
  `pg2_fluDate3` date DEFAULT NULL,
  `pg2_fluDate4` date DEFAULT NULL,
  `pg2_fluDate5` date DEFAULT NULL,
  `pg2_fluDate6` date DEFAULT NULL,
  `pg2_fluDate7` date DEFAULT NULL,
  `pg2_otherVac1` varchar(30) DEFAULT NULL,
  `pg2_other1Date1` date DEFAULT NULL,
  `pg2_other1Date2` date DEFAULT NULL,
  `pg2_other1Date3` date DEFAULT NULL,
  `pg2_other1Date4` date DEFAULT NULL,
  `pg2_other1Date5` date DEFAULT NULL,
  `pg2_other1Date6` date DEFAULT NULL,
  `pg2_other1Date7` date DEFAULT NULL,
  `pg2_otherVac2` varchar(30) DEFAULT NULL,
  `pg2_other2Date1` date DEFAULT NULL,
  `pg2_other2Date2` date DEFAULT NULL,
  `pg2_other2Date3` date DEFAULT NULL,
  `pg2_other2Date4` date DEFAULT NULL,
  `pg2_other2Date5` date DEFAULT NULL,
  `pg2_other2Date6` date DEFAULT NULL,
  `pg2_other2Date7` date DEFAULT NULL,
  `pg2_otherVac3` varchar(30) DEFAULT NULL,
  `pg2_other3Date1` date DEFAULT NULL,
  `pg2_other3Date2` date DEFAULT NULL,
  `pg2_other3Date3` date DEFAULT NULL,
  `pg2_other3Date4` date DEFAULT NULL,
  `pg2_other3Date5` date DEFAULT NULL,
  `pg2_other3Date6` date DEFAULT NULL,
  `pg2_other3Date7` date DEFAULT NULL,
  `pg2_otherVac4` varchar(30) DEFAULT NULL,
  `pg2_other4Date1` date DEFAULT NULL,
  `pg2_other4Date2` date DEFAULT NULL,
  `pg2_other4Date3` date DEFAULT NULL,
  `pg2_other4Date4` date DEFAULT NULL,
  `pg2_other4Date5` date DEFAULT NULL,
  `pg2_other4Date6` date DEFAULT NULL,
  `pg2_other4Date7` date DEFAULT NULL,
  `pg2_otherVac5` varchar(30) DEFAULT NULL,
  `pg2_other5Date1` date DEFAULT NULL,
  `pg2_other5Date2` date DEFAULT NULL,
  `pg2_other5Date3` date DEFAULT NULL,
  `pg2_other5Date4` date DEFAULT NULL,
  `pg2_other5Date5` date DEFAULT NULL,
  `pg2_other5Date6` date DEFAULT NULL,
  `pg2_other5Date7` date DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `form_boolean_value`
--

CREATE TABLE IF NOT EXISTS `form_boolean_value` (
   `form_name` varchar(50) NOT NULL,
   `form_id` int(10) NOT NULL,
   `field_name` varchar(50) NOT NULL,
   `value` tinyint(1),
   PRIMARY KEY (`form_name`,`form_id`,`field_name`)
 );

--
-- Table structure for table `formCESD`
--


CREATE TABLE `formCESD` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `Q1Rare` tinyint(1) DEFAULT NULL,
  `Q1Some` tinyint(1) DEFAULT NULL,
  `Q1Occ` tinyint(1) DEFAULT NULL,
  `Q1Most` tinyint(1) DEFAULT NULL,
  `Q2Rare` tinyint(1) DEFAULT NULL,
  `Q2Some` tinyint(1) DEFAULT NULL,
  `Q2Occ` tinyint(1) DEFAULT NULL,
  `Q2Most` tinyint(1) DEFAULT NULL,
  `Q3Rare` tinyint(1) DEFAULT NULL,
  `Q3Some` tinyint(1) DEFAULT NULL,
  `Q3Occ` tinyint(1) DEFAULT NULL,
  `Q3Most` tinyint(1) DEFAULT NULL,
  `Q4Rare` tinyint(1) DEFAULT NULL,
  `Q4Some` tinyint(1) DEFAULT NULL,
  `Q4Occ` tinyint(1) DEFAULT NULL,
  `Q4Most` tinyint(1) DEFAULT NULL,
  `Q5Rare` tinyint(1) DEFAULT NULL,
  `Q5Some` tinyint(1) DEFAULT NULL,
  `Q5Occ` tinyint(1) DEFAULT NULL,
  `Q5Most` tinyint(1) DEFAULT NULL,
  `Q6Rare` tinyint(1) DEFAULT NULL,
  `Q6Some` tinyint(1) DEFAULT NULL,
  `Q6Occ` tinyint(1) DEFAULT NULL,
  `Q6Most` tinyint(1) DEFAULT NULL,
  `Q7Rare` tinyint(1) DEFAULT NULL,
  `Q7Some` tinyint(1) DEFAULT NULL,
  `Q7Occ` tinyint(1) DEFAULT NULL,
  `Q7Most` tinyint(1) DEFAULT NULL,
  `Q8Rare` tinyint(1) DEFAULT NULL,
  `Q8Some` tinyint(1) DEFAULT NULL,
  `Q8Occ` tinyint(1) DEFAULT NULL,
  `Q8Most` tinyint(1) DEFAULT NULL,
  `Q9Rare` tinyint(1) DEFAULT NULL,
  `Q9Some` tinyint(1) DEFAULT NULL,
  `Q9Occ` tinyint(1) DEFAULT NULL,
  `Q9Most` tinyint(1) DEFAULT NULL,
  `Q10Rare` tinyint(1) DEFAULT NULL,
  `Q10Some` tinyint(1) DEFAULT NULL,
  `Q10Occ` tinyint(1) DEFAULT NULL,
  `Q10Most` tinyint(1) DEFAULT NULL,
  `Q11Rare` tinyint(1) DEFAULT NULL,
  `Q11Some` tinyint(1) DEFAULT NULL,
  `Q11Occ` tinyint(1) DEFAULT NULL,
  `Q11Most` tinyint(1) DEFAULT NULL,
  `Q12Rare` tinyint(1) DEFAULT NULL,
  `Q12Some` tinyint(1) DEFAULT NULL,
  `Q12Occ` tinyint(1) DEFAULT NULL,
  `Q12Most` tinyint(1) DEFAULT NULL,
  `Q13Rare` tinyint(1) DEFAULT NULL,
  `Q13Some` tinyint(1) DEFAULT NULL,
  `Q13Occ` tinyint(1) DEFAULT NULL,
  `Q13Most` tinyint(1) DEFAULT NULL,
  `Q14Rare` tinyint(1) DEFAULT NULL,
  `Q14Some` tinyint(1) DEFAULT NULL,
  `Q14Occ` tinyint(1) DEFAULT NULL,
  `Q14Most` tinyint(1) DEFAULT NULL,
  `Q15Rare` tinyint(1) DEFAULT NULL,
  `Q15Some` tinyint(1) DEFAULT NULL,
  `Q15Occ` tinyint(1) DEFAULT NULL,
  `Q15Most` tinyint(1) DEFAULT NULL,
  `Q16Rare` tinyint(1) DEFAULT NULL,
  `Q16Some` tinyint(1) DEFAULT NULL,
  `Q16Occ` tinyint(1) DEFAULT NULL,
  `Q16Most` tinyint(1) DEFAULT NULL,
  `Q17Rare` tinyint(1) DEFAULT NULL,
  `Q17Some` tinyint(1) DEFAULT NULL,
  `Q17Occ` tinyint(1) DEFAULT NULL,
  `Q17Most` tinyint(1) DEFAULT NULL,
  `Q18Rare` tinyint(1) DEFAULT NULL,
  `Q18Some` tinyint(1) DEFAULT NULL,
  `Q18Occ` tinyint(1) DEFAULT NULL,
  `Q18Most` tinyint(1) DEFAULT NULL,
  `Q19Rare` tinyint(1) DEFAULT NULL,
  `Q19Some` tinyint(1) DEFAULT NULL,
  `Q19Occ` tinyint(1) DEFAULT NULL,
  `Q19Most` tinyint(1) DEFAULT NULL,
  `Q20Rare` tinyint(1) DEFAULT NULL,
  `Q20Some` tinyint(1) DEFAULT NULL,
  `Q20Occ` tinyint(1) DEFAULT NULL,
  `Q20Most` tinyint(1) DEFAULT NULL,
  `score` int(2) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formCaregiver`
--


CREATE TABLE `formCaregiver` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `sexM` tinyint(1) DEFAULT NULL,
  `sexF` tinyint(1) DEFAULT NULL,
  `dobYear` varchar(4) DEFAULT NULL,
  `dobMonth` varchar(2) DEFAULT NULL,
  `dobDay` varchar(2) DEFAULT NULL,
  `spouseY` tinyint(1) DEFAULT NULL,
  `childY` tinyint(1) DEFAULT NULL,
  `grandchildY` tinyint(1) DEFAULT NULL,
  `siblingY` tinyint(1) DEFAULT NULL,
  `friendY` tinyint(1) DEFAULT NULL,
  `otherY` tinyint(1) DEFAULT NULL,
  `otherRelation` varchar(255) DEFAULT NULL,
  `resideY` tinyint(1) DEFAULT NULL,
  `resideN` tinyint(1) DEFAULT NULL,
  `healthEx` tinyint(1) DEFAULT NULL,
  `healthVG` tinyint(1) DEFAULT NULL,
  `healthG` tinyint(1) DEFAULT NULL,
  `healthF` tinyint(1) DEFAULT NULL,
  `healthP` tinyint(1) DEFAULT NULL,
  `Q1Y` tinyint(1) DEFAULT NULL,
  `Q1N` tinyint(1) DEFAULT NULL,
  `Q2Y` tinyint(1) DEFAULT NULL,
  `Q2N` tinyint(1) DEFAULT NULL,
  `Q3Y` tinyint(1) DEFAULT NULL,
  `Q3N` tinyint(1) DEFAULT NULL,
  `Q4Y` tinyint(1) DEFAULT NULL,
  `Q4N` tinyint(1) DEFAULT NULL,
  `Q5Y` tinyint(1) DEFAULT NULL,
  `Q5N` tinyint(1) DEFAULT NULL,
  `Q6Y` tinyint(1) DEFAULT NULL,
  `Q6N` tinyint(1) DEFAULT NULL,
  `Q7Y` tinyint(1) DEFAULT NULL,
  `Q7N` tinyint(1) DEFAULT NULL,
  `Q8Y` tinyint(1) DEFAULT NULL,
  `Q8N` tinyint(1) DEFAULT NULL,
  `Q9Y` tinyint(1) DEFAULT NULL,
  `Q9N` tinyint(1) DEFAULT NULL,
  `Q10Y` tinyint(1) DEFAULT NULL,
  `Q10N` tinyint(1) DEFAULT NULL,
  `Q11Y` tinyint(1) DEFAULT NULL,
  `Q11N` tinyint(1) DEFAULT NULL,
  `Q12Y` tinyint(1) DEFAULT NULL,
  `Q12N` tinyint(1) DEFAULT NULL,
  `Q13Y` tinyint(1) DEFAULT NULL,
  `Q13N` tinyint(1) DEFAULT NULL,
  `score1` int(2) DEFAULT NULL,
  `SRBScore` int(3) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formConsult`
--


CREATE TABLE `formConsult` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` int(10) DEFAULT NULL,
  `doc_name` varchar(60) DEFAULT NULL,
  `cl_name` varchar(60) DEFAULT NULL,
  `cl_address1` varchar(170) DEFAULT NULL,
  `cl_address2` varchar(170) DEFAULT NULL,
  `cl_phone` varchar(16) DEFAULT NULL,
  `cl_fax` varchar(16) DEFAULT NULL,
  `billingreferral_no` int(10) DEFAULT NULL,
  `t_name` varchar(60) DEFAULT NULL,
  `t_name2` varchar(60) DEFAULT NULL,
  `t_address1` varchar(170) DEFAULT NULL,
  `t_address2` varchar(170) DEFAULT NULL,
  `t_phone` varchar(16) DEFAULT NULL,
  `t_fax` varchar(16) DEFAULT NULL,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `p_name` varchar(60) DEFAULT NULL,
  `p_address1` varchar(170) DEFAULT NULL,
  `p_address2` varchar(170) DEFAULT NULL,
  `p_phone` varchar(16) DEFAULT NULL,
  `p_birthdate` varchar(30) DEFAULT NULL,
  `p_healthcard` varchar(20) DEFAULT NULL,
  `comments` text,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `consultTime` date DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formCostQuestionnaire`
--


CREATE TABLE `formCostQuestionnaire` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `seenDoctorY` tinyint(1) DEFAULT NULL,
  `seenDoctorN` tinyint(1) DEFAULT NULL,
  `familyPhyVisits` int(3) DEFAULT NULL,
  `specialistVisits` int(3) DEFAULT NULL,
  `otherProviderY` tinyint(1) DEFAULT NULL,
  `otherProviderN` tinyint(1) DEFAULT NULL,
  `visitNurse` int(3) DEFAULT NULL,
  `homeMaker` int(3) DEFAULT NULL,
  `physiotherapist` int(3) DEFAULT NULL,
  `therapist` int(3) DEFAULT NULL,
  `psychologist` int(3) DEFAULT NULL,
  `socialWorker` int(3) DEFAULT NULL,
  `supportGroup` int(3) DEFAULT NULL,
  `mealOnWheels` int(3) DEFAULT NULL,
  `other` int(3) DEFAULT NULL,
  `paidService1` varchar(255) DEFAULT NULL,
  `paidServiceHour1` int(5) DEFAULT NULL,
  `paidServiceCost1` double DEFAULT NULL,
  `paidService2` varchar(255) DEFAULT NULL,
  `paidServiceHour2` int(5) DEFAULT NULL,
  `paidServiceCost2` double DEFAULT NULL,
  `paidService3` varchar(255) DEFAULT NULL,
  `paidServiceHour3` int(5) DEFAULT NULL,
  `paidServiceCost3` double DEFAULT NULL,
  `plannedHospN` tinyint(1) DEFAULT NULL,
  `plannedHospY` tinyint(1) DEFAULT NULL,
  `plannedHospAdmitted` int(3) DEFAULT NULL,
  `plannedHospDays` int(3) DEFAULT NULL,
  `nursingHomeN` tinyint(1) DEFAULT NULL,
  `nursingHomeY` tinyint(1) DEFAULT NULL,
  `nursingHomeDays` int(3) DEFAULT NULL,
  `emergencyN` tinyint(1) DEFAULT NULL,
  `emergencyY` tinyint(1) DEFAULT NULL,
  `emergency911` int(3) DEFAULT NULL,
  `emergency` int(3) DEFAULT NULL,
  `emergencyAmbulance` int(3) DEFAULT NULL,
  `walkinN` tinyint(1) DEFAULT NULL,
  `walkinY` tinyint(1) DEFAULT NULL,
  `walkin` int(3) DEFAULT NULL,
  `itemPurchased1` varchar(255) DEFAULT NULL,
  `itemCost1` double DEFAULT NULL,
  `itemPurchased2` varchar(255) DEFAULT NULL,
  `itemCost2` double DEFAULT NULL,
  `itemPurchased3` varchar(255) DEFAULT NULL,
  `itemCost3` double DEFAULT NULL,
  `employed` tinyint(1) DEFAULT NULL,
  `employedFullTime` tinyint(1) DEFAULT NULL,
  `employedPartTime` tinyint(1) DEFAULT NULL,
  `selfEmployed` tinyint(1) DEFAULT NULL,
  `selfEmployedFullTime` tinyint(1) DEFAULT NULL,
  `selfEmployedPartTime` tinyint(1) DEFAULT NULL,
  `unemployed` tinyint(1) DEFAULT NULL,
  `unemployedAble` tinyint(1) DEFAULT NULL,
  `unemployedUnable` tinyint(1) DEFAULT NULL,
  `disability` tinyint(1) DEFAULT NULL,
  `disabilityShortTerm` tinyint(1) DEFAULT NULL,
  `disabilityLongTerm` tinyint(1) DEFAULT NULL,
  `retired` tinyint(1) DEFAULT NULL,
  `homemakerWithOutPaid` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formCounseling`
--


CREATE TABLE `formCounseling` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` int(10) DEFAULT NULL,
  `doc_name` varchar(60) DEFAULT NULL,
  `cl_name` varchar(60) DEFAULT NULL,
  `cl_address1` varchar(170) DEFAULT NULL,
  `cl_address2` varchar(170) DEFAULT NULL,
  `cl_phone` varchar(16) DEFAULT NULL,
  `cl_fax` varchar(16) DEFAULT NULL,
  `billingreferral_no` int(10) DEFAULT NULL,
  `t_name` varchar(60) DEFAULT NULL,
  `t_name2` varchar(60) DEFAULT NULL,
  `t_address1` varchar(170) DEFAULT NULL,
  `t_address2` varchar(170) DEFAULT NULL,
  `t_phone` varchar(16) DEFAULT NULL,
  `t_fax` varchar(16) DEFAULT NULL,
  `demographic_no` int(10) NOT NULL,
  `p_name` varchar(60) DEFAULT NULL,
  `p_address1` varchar(170) DEFAULT NULL,
  `p_address2` varchar(170) DEFAULT NULL,
  `p_phone` varchar(16) DEFAULT NULL,
  `p_birthdate` varchar(30) DEFAULT NULL,
  `p_healthcard` varchar(20) DEFAULT NULL,
  `comments` text,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `consultTime` date DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formFalls`
--


CREATE TABLE `formFalls` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `fallenLast12MY` tinyint(1) DEFAULT NULL,
  `fallenLast12MN` tinyint(1) DEFAULT NULL,
  `fallenLast12MNotRemember` tinyint(1) DEFAULT NULL,
  `injuredY` tinyint(1) DEFAULT NULL,
  `injuredN` tinyint(1) DEFAULT NULL,
  `medAttnY` tinyint(1) DEFAULT NULL,
  `medAttnN` tinyint(1) DEFAULT NULL,
  `hospitalizedY` tinyint(1) DEFAULT NULL,
  `hospitalizedN` tinyint(1) DEFAULT NULL,
  `limitActY` tinyint(1) DEFAULT NULL,
  `limitActN` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formGripStrength`
--


CREATE TABLE `formGripStrength` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `dom1` varchar(5) DEFAULT NULL,
  `nonDom1` varchar(5) DEFAULT NULL,
  `dom2` varchar(5) DEFAULT NULL,
  `nonDom2` varchar(5) DEFAULT NULL,
  `dom3` varchar(5) DEFAULT NULL,
  `nonDom3` varchar(5) DEFAULT NULL,
  `domAvg` varchar(5) DEFAULT NULL,
  `nonDomAvg` varchar(5) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formGrowth0_36`
--


CREATE TABLE `formGrowth0_36` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `patientName` varchar(80) DEFAULT NULL,
  `recordNo` varchar(10) DEFAULT NULL,
  `motherStature` varchar(80) DEFAULT NULL,
  `gestationalAge` varchar(5) DEFAULT NULL,
  `fatherStature` varchar(80) DEFAULT NULL,
  `edc` varchar(10) DEFAULT NULL,
  `date_1` date DEFAULT NULL,
  `age_1` varchar(5) DEFAULT NULL,
  `weight_1` varchar(6) DEFAULT NULL,
  `length_1` varchar(6) DEFAULT NULL,
  `headCirc_1` varchar(6) DEFAULT NULL,
  `comment_1` varchar(25) DEFAULT NULL,
  `date_2` date DEFAULT NULL,
  `age_2` varchar(5) DEFAULT NULL,
  `weight_2` varchar(6) DEFAULT NULL,
  `length_2` varchar(6) DEFAULT NULL,
  `headCirc_2` varchar(6) DEFAULT NULL,
  `comment_2` varchar(25) DEFAULT NULL,
  `date_3` date DEFAULT NULL,
  `age_3` varchar(5) DEFAULT NULL,
  `weight_3` varchar(6) DEFAULT NULL,
  `length_3` varchar(6) DEFAULT NULL,
  `headCirc_3` varchar(6) DEFAULT NULL,
  `comment_3` varchar(25) DEFAULT NULL,
  `date_4` date DEFAULT NULL,
  `age_4` varchar(5) DEFAULT NULL,
  `weight_4` varchar(6) DEFAULT NULL,
  `length_4` varchar(6) DEFAULT NULL,
  `headCirc_4` varchar(6) DEFAULT NULL,
  `comment_4` varchar(25) DEFAULT NULL,
  `date_5` date DEFAULT NULL,
  `age_5` varchar(5) DEFAULT NULL,
  `weight_5` varchar(6) DEFAULT NULL,
  `length_5` varchar(6) DEFAULT NULL,
  `headCirc_5` varchar(6) DEFAULT NULL,
  `comment_5` varchar(25) DEFAULT NULL,
  `date_6` date DEFAULT NULL,
  `age_6` varchar(5) DEFAULT NULL,
  `weight_6` varchar(6) DEFAULT NULL,
  `length_6` varchar(6) DEFAULT NULL,
  `headCirc_6` varchar(6) DEFAULT NULL,
  `comment_6` varchar(25) DEFAULT NULL,
  `date_7` date DEFAULT NULL,
  `age_7` varchar(5) DEFAULT NULL,
  `weight_7` varchar(6) DEFAULT NULL,
  `length_7` varchar(6) DEFAULT NULL,
  `headCirc_7` varchar(6) DEFAULT NULL,
  `comment_7` varchar(25) DEFAULT NULL,
  `date_8` date DEFAULT NULL,
  `age_8` varchar(5) DEFAULT NULL,
  `weight_8` varchar(6) DEFAULT NULL,
  `length_8` varchar(6) DEFAULT NULL,
  `headCirc_8` varchar(6) DEFAULT NULL,
  `comment_8` varchar(25) DEFAULT NULL,
  `date_9` date DEFAULT NULL,
  `age_9` varchar(5) DEFAULT NULL,
  `weight_9` varchar(6) DEFAULT NULL,
  `length_9` varchar(6) DEFAULT NULL,
  `headCirc_9` varchar(6) DEFAULT NULL,
  `comment_9` varchar(25) DEFAULT NULL,
  `date_10` date DEFAULT NULL,
  `age_10` varchar(5) DEFAULT NULL,
  `weight_10` varchar(6) DEFAULT NULL,
  `length_10` varchar(6) DEFAULT NULL,
  `headCirc_10` varchar(6) DEFAULT NULL,
  `comment_10` varchar(25) DEFAULT NULL,
  `date_11` date DEFAULT NULL,
  `age_11` varchar(5) DEFAULT NULL,
  `weight_11` varchar(6) DEFAULT NULL,
  `length_11` varchar(6) DEFAULT NULL,
  `headCirc_11` varchar(6) DEFAULT NULL,
  `comment_11` varchar(25) DEFAULT NULL,
  `date_12` date DEFAULT NULL,
  `age_12` varchar(5) DEFAULT NULL,
  `weight_12` varchar(6) DEFAULT NULL,
  `length_12` varchar(6) DEFAULT NULL,
  `headCirc_12` varchar(6) DEFAULT NULL,
  `comment_12` varchar(25) DEFAULT NULL,
  `date_13` date DEFAULT NULL,
  `age_13` varchar(5) DEFAULT NULL,
  `weight_13` varchar(6) DEFAULT NULL,
  `length_13` varchar(6) DEFAULT NULL,
  `headCirc_13` varchar(6) DEFAULT NULL,
  `comment_13` varchar(25) DEFAULT NULL,
  `date_14` date DEFAULT NULL,
  `age_14` varchar(5) DEFAULT NULL,
  `weight_14` varchar(6) DEFAULT NULL,
  `length_14` varchar(6) DEFAULT NULL,
  `headCirc_14` varchar(6) DEFAULT NULL,
  `comment_14` varchar(25) DEFAULT NULL,
  `date_15` date DEFAULT NULL,
  `age_15` varchar(5) DEFAULT NULL,
  `weight_15` varchar(6) DEFAULT NULL,
  `length_15` varchar(6) DEFAULT NULL,
  `headCirc_15` varchar(6) DEFAULT NULL,
  `comment_15` varchar(25) DEFAULT NULL,
  `date_16` date DEFAULT NULL,
  `age_16` varchar(5) DEFAULT NULL,
  `weight_16` varchar(6) DEFAULT NULL,
  `length_16` varchar(6) DEFAULT NULL,
  `headCirc_16` varchar(6) DEFAULT NULL,
  `comment_16` varchar(25) DEFAULT NULL,
  `date_17` date DEFAULT NULL,
  `age_17` varchar(5) DEFAULT NULL,
  `weight_17` varchar(6) DEFAULT NULL,
  `length_17` varchar(6) DEFAULT NULL,
  `headCirc_17` varchar(6) DEFAULT NULL,
  `comment_17` varchar(25) DEFAULT NULL,
  `date_18` date DEFAULT NULL,
  `age_18` varchar(5) DEFAULT NULL,
  `weight_18` varchar(6) DEFAULT NULL,
  `length_18` varchar(6) DEFAULT NULL,
  `headCirc_18` varchar(6) DEFAULT NULL,
  `comment_18` varchar(25) DEFAULT NULL,
  `date_19` date DEFAULT NULL,
  `age_19` varchar(5) DEFAULT NULL,
  `weight_19` varchar(6) DEFAULT NULL,
  `length_19` varchar(6) DEFAULT NULL,
  `headCirc_19` varchar(6) DEFAULT NULL,
  `comment_19` varchar(25) DEFAULT NULL,
  `date_20` date DEFAULT NULL,
  `age_20` varchar(5) DEFAULT NULL,
  `weight_20` varchar(6) DEFAULT NULL,
  `length_20` varchar(6) DEFAULT NULL,
  `headCirc_20` varchar(6) DEFAULT NULL,
  `comment_20` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `demographic_no` (`demographic_no`)
);

--
-- Table structure for table `formGrowthChart`
--


CREATE TABLE `formGrowthChart` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `patientName` varchar(80) DEFAULT NULL,
  `recordNo` varchar(10) DEFAULT NULL,
  `motherStature` varchar(80) DEFAULT NULL,
  `fatherStature` varchar(80) DEFAULT NULL,
  `date_1` date DEFAULT NULL,
  `age_1` varchar(5) DEFAULT NULL,
  `stature_1` varchar(6) DEFAULT NULL,
  `weight_1` varchar(6) DEFAULT NULL,
  `comment_1` varchar(25) DEFAULT NULL,
  `bmi_1` varchar(5) DEFAULT NULL,
  `date_2` date DEFAULT NULL,
  `age_2` varchar(5) DEFAULT NULL,
  `stature_2` varchar(6) DEFAULT NULL,
  `weight_2` varchar(6) DEFAULT NULL,
  `comment_2` varchar(25) DEFAULT NULL,
  `bmi_2` varchar(5) DEFAULT NULL,
  `date_3` date DEFAULT NULL,
  `age_3` varchar(5) DEFAULT NULL,
  `stature_3` varchar(6) DEFAULT NULL,
  `weight_3` varchar(6) DEFAULT NULL,
  `comment_3` varchar(25) DEFAULT NULL,
  `bmi_3` varchar(5) DEFAULT NULL,
  `date_4` date DEFAULT NULL,
  `age_4` varchar(5) DEFAULT NULL,
  `stature_4` varchar(6) DEFAULT NULL,
  `weight_4` varchar(6) DEFAULT NULL,
  `comment_4` varchar(25) DEFAULT NULL,
  `bmi_4` varchar(5) DEFAULT NULL,
  `date_5` date DEFAULT NULL,
  `age_5` varchar(5) DEFAULT NULL,
  `stature_5` varchar(6) DEFAULT NULL,
  `weight_5` varchar(6) DEFAULT NULL,
  `comment_5` varchar(25) DEFAULT NULL,
  `bmi_5` varchar(5) DEFAULT NULL,
  `date_6` date DEFAULT NULL,
  `age_6` varchar(5) DEFAULT NULL,
  `stature_6` varchar(6) DEFAULT NULL,
  `weight_6` varchar(6) DEFAULT NULL,
  `comment_6` varchar(25) DEFAULT NULL,
  `bmi_6` varchar(5) DEFAULT NULL,
  `date_7` date DEFAULT NULL,
  `age_7` varchar(5) DEFAULT NULL,
  `stature_7` varchar(6) DEFAULT NULL,
  `weight_7` varchar(6) DEFAULT NULL,
  `comment_7` varchar(25) DEFAULT NULL,
  `bmi_7` varchar(5) DEFAULT NULL,
  `date_8` date DEFAULT NULL,
  `age_8` varchar(5) DEFAULT NULL,
  `stature_8` varchar(6) DEFAULT NULL,
  `weight_8` varchar(6) DEFAULT NULL,
  `comment_8` varchar(25) DEFAULT NULL,
  `bmi_8` varchar(5) DEFAULT NULL,
  `date_9` date DEFAULT NULL,
  `age_9` varchar(5) DEFAULT NULL,
  `stature_9` varchar(6) DEFAULT NULL,
  `weight_9` varchar(6) DEFAULT NULL,
  `comment_9` varchar(25) DEFAULT NULL,
  `bmi_9` varchar(5) DEFAULT NULL,
  `date_10` date DEFAULT NULL,
  `age_10` varchar(5) DEFAULT NULL,
  `stature_10` varchar(6) DEFAULT NULL,
  `weight_10` varchar(6) DEFAULT NULL,
  `comment_10` varchar(25) DEFAULT NULL,
  `bmi_10` varchar(5) DEFAULT NULL,
  `date_11` date DEFAULT NULL,
  `age_11` varchar(5) DEFAULT NULL,
  `stature_11` varchar(6) DEFAULT NULL,
  `weight_11` varchar(6) DEFAULT NULL,
  `comment_11` varchar(25) DEFAULT NULL,
  `bmi_11` varchar(5) DEFAULT NULL,
  `date_12` date DEFAULT NULL,
  `age_12` varchar(5) DEFAULT NULL,
  `stature_12` varchar(6) DEFAULT NULL,
  `weight_12` varchar(6) DEFAULT NULL,
  `comment_12` varchar(25) DEFAULT NULL,
  `bmi_12` varchar(5) DEFAULT NULL,
  `date_13` date DEFAULT NULL,
  `age_13` varchar(5) DEFAULT NULL,
  `stature_13` varchar(6) DEFAULT NULL,
  `weight_13` varchar(6) DEFAULT NULL,
  `comment_13` varchar(25) DEFAULT NULL,
  `bmi_13` varchar(5) DEFAULT NULL,
  `date_14` date DEFAULT NULL,
  `age_14` varchar(5) DEFAULT NULL,
  `stature_14` varchar(6) DEFAULT NULL,
  `weight_14` varchar(6) DEFAULT NULL,
  `comment_14` varchar(25) DEFAULT NULL,
  `bmi_14` varchar(5) DEFAULT NULL,
  `date_15` date DEFAULT NULL,
  `age_15` varchar(5) DEFAULT NULL,
  `stature_15` varchar(6) DEFAULT NULL,
  `weight_15` varchar(6) DEFAULT NULL,
  `comment_15` varchar(25) DEFAULT NULL,
  `bmi_15` varchar(5) DEFAULT NULL,
  `date_16` date DEFAULT NULL,
  `age_16` varchar(5) DEFAULT NULL,
  `stature_16` varchar(6) DEFAULT NULL,
  `weight_16` varchar(6) DEFAULT NULL,
  `comment_16` varchar(25) DEFAULT NULL,
  `bmi_16` varchar(5) DEFAULT NULL,
  `date_17` date DEFAULT NULL,
  `age_17` varchar(5) DEFAULT NULL,
  `stature_17` varchar(6) DEFAULT NULL,
  `weight_17` varchar(6) DEFAULT NULL,
  `comment_17` varchar(25) DEFAULT NULL,
  `bmi_17` varchar(5) DEFAULT NULL,
  `date_18` date DEFAULT NULL,
  `age_18` varchar(5) DEFAULT NULL,
  `stature_18` varchar(6) DEFAULT NULL,
  `weight_18` varchar(6) DEFAULT NULL,
  `comment_18` varchar(25) DEFAULT NULL,
  `bmi_18` varchar(5) DEFAULT NULL,
  `date_19` date DEFAULT NULL,
  `age_19` varchar(5) DEFAULT NULL,
  `stature_19` varchar(6) DEFAULT NULL,
  `weight_19` varchar(6) DEFAULT NULL,
  `comment_19` varchar(25) DEFAULT NULL,
  `bmi_19` varchar(5) DEFAULT NULL,
  `date_20` date DEFAULT NULL,
  `age_20` varchar(5) DEFAULT NULL,
  `stature_20` varchar(6) DEFAULT NULL,
  `weight_20` varchar(6) DEFAULT NULL,
  `comment_20` varchar(25) DEFAULT NULL,
  `bmi_20` varchar(5) DEFAULT NULL,
  `date_21` date DEFAULT NULL,
  `age_21` varchar(5) DEFAULT NULL,
  `stature_21` varchar(6) DEFAULT NULL,
  `weight_21` varchar(6) DEFAULT NULL,
  `comment_21` varchar(25) DEFAULT NULL,
  `bmi_21` varchar(5) DEFAULT NULL,
  `date_22` date DEFAULT NULL,
  `age_22` varchar(5) DEFAULT NULL,
  `stature_22` varchar(6) DEFAULT NULL,
  `weight_22` varchar(6) DEFAULT NULL,
  `comment_22` varchar(25) DEFAULT NULL,
  `bmi_22` varchar(5) DEFAULT NULL,
  `date_23` date DEFAULT NULL,
  `age_23` varchar(5) DEFAULT NULL,
  `stature_23` varchar(6) DEFAULT NULL,
  `weight_23` varchar(6) DEFAULT NULL,
  `comment_23` varchar(25) DEFAULT NULL,
  `bmi_23` varchar(5) DEFAULT NULL,
  `date_24` date DEFAULT NULL,
  `age_24` varchar(5) DEFAULT NULL,
  `stature_24` varchar(6) DEFAULT NULL,
  `weight_24` varchar(6) DEFAULT NULL,
  `comment_24` varchar(25) DEFAULT NULL,
  `bmi_24` varchar(5) DEFAULT NULL,
  `date_25` date DEFAULT NULL,
  `age_25` varchar(5) DEFAULT NULL,
  `stature_25` varchar(6) DEFAULT NULL,
  `weight_25` varchar(6) DEFAULT NULL,
  `comment_25` varchar(25) DEFAULT NULL,
  `bmi_25` varchar(5) DEFAULT NULL,
  `date_26` date DEFAULT NULL,
  `age_26` varchar(5) DEFAULT NULL,
  `stature_26` varchar(6) DEFAULT NULL,
  `weight_26` varchar(6) DEFAULT NULL,
  `comment_26` varchar(25) DEFAULT NULL,
  `bmi_26` varchar(5) DEFAULT NULL,
  `date_27` date DEFAULT NULL,
  `age_27` varchar(5) DEFAULT NULL,
  `stature_27` varchar(6) DEFAULT NULL,
  `weight_27` varchar(6) DEFAULT NULL,
  `comment_27` varchar(25) DEFAULT NULL,
  `bmi_27` varchar(5) DEFAULT NULL,
  `date_28` date DEFAULT NULL,
  `age_28` varchar(5) DEFAULT NULL,
  `stature_28` varchar(6) DEFAULT NULL,
  `weight_28` varchar(6) DEFAULT NULL,
  `comment_28` varchar(25) DEFAULT NULL,
  `bmi_28` varchar(5) DEFAULT NULL,
  `date_29` date DEFAULT NULL,
  `age_29` varchar(5) DEFAULT NULL,
  `stature_29` varchar(6) DEFAULT NULL,
  `weight_29` varchar(6) DEFAULT NULL,
  `comment_29` varchar(25) DEFAULT NULL,
  `bmi_29` varchar(5) DEFAULT NULL,
  `date_30` date DEFAULT NULL,
  `age_30` varchar(5) DEFAULT NULL,
  `stature_30` varchar(6) DEFAULT NULL,
  `weight_30` varchar(6) DEFAULT NULL,
  `comment_30` varchar(25) DEFAULT NULL,
  `bmi_30` varchar(5) DEFAULT NULL,
  `date_31` date DEFAULT NULL,
  `age_31` varchar(5) DEFAULT NULL,
  `stature_31` varchar(6) DEFAULT NULL,
  `weight_31` varchar(6) DEFAULT NULL,
  `comment_31` varchar(25) DEFAULT NULL,
  `bmi_31` varchar(5) DEFAULT NULL,
  `date_32` date DEFAULT NULL,
  `age_32` varchar(5) DEFAULT NULL,
  `stature_32` varchar(6) DEFAULT NULL,
  `weight_32` varchar(6) DEFAULT NULL,
  `comment_32` varchar(25) DEFAULT NULL,
  `bmi_32` varchar(5) DEFAULT NULL,
  `date_33` date DEFAULT NULL,
  `age_33` varchar(5) DEFAULT NULL,
  `stature_33` varchar(6) DEFAULT NULL,
  `weight_33` varchar(6) DEFAULT NULL,
  `comment_33` varchar(25) DEFAULT NULL,
  `bmi_33` varchar(5) DEFAULT NULL,
  `date_34` date DEFAULT NULL,
  `age_34` varchar(5) DEFAULT NULL,
  `stature_34` varchar(6) DEFAULT NULL,
  `weight_34` varchar(6) DEFAULT NULL,
  `comment_34` varchar(25) DEFAULT NULL,
  `bmi_34` varchar(5) DEFAULT NULL,
  `date_35` date DEFAULT NULL,
  `age_35` varchar(5) DEFAULT NULL,
  `stature_35` varchar(6) DEFAULT NULL,
  `weight_35` varchar(6) DEFAULT NULL,
  `comment_35` varchar(25) DEFAULT NULL,
  `bmi_35` varchar(5) DEFAULT NULL,
  `date_36` date DEFAULT NULL,
  `age_36` varchar(5) DEFAULT NULL,
  `stature_36` varchar(6) DEFAULT NULL,
  `weight_36` varchar(6) DEFAULT NULL,
  `comment_36` varchar(25) DEFAULT NULL,
  `bmi_36` varchar(5) DEFAULT NULL,
  `date_37` date DEFAULT NULL,
  `age_37` varchar(5) DEFAULT NULL,
  `stature_37` varchar(6) DEFAULT NULL,
  `weight_37` varchar(6) DEFAULT NULL,
  `comment_37` varchar(25) DEFAULT NULL,
  `bmi_37` varchar(5) DEFAULT NULL,
  `date_38` date DEFAULT NULL,
  `age_38` varchar(5) DEFAULT NULL,
  `stature_38` varchar(6) DEFAULT NULL,
  `weight_38` varchar(6) DEFAULT NULL,
  `comment_38` varchar(25) DEFAULT NULL,
  `bmi_38` varchar(5) DEFAULT NULL,
  `date_39` date DEFAULT NULL,
  `age_39` varchar(5) DEFAULT NULL,
  `stature_39` varchar(6) DEFAULT NULL,
  `weight_39` varchar(6) DEFAULT NULL,
  `comment_39` varchar(25) DEFAULT NULL,
  `bmi_39` varchar(5) DEFAULT NULL,
  `date_40` date DEFAULT NULL,
  `age_40` varchar(5) DEFAULT NULL,
  `stature_40` varchar(6) DEFAULT NULL,
  `weight_40` varchar(6) DEFAULT NULL,
  `comment_40` varchar(25) DEFAULT NULL,
  `bmi_40` varchar(5) DEFAULT NULL,
  `date_41` date DEFAULT NULL,
  `age_41` varchar(5) DEFAULT NULL,
  `stature_41` varchar(6) DEFAULT NULL,
  `weight_41` varchar(6) DEFAULT NULL,
  `comment_41` varchar(25) DEFAULT NULL,
  `bmi_41` varchar(5) DEFAULT NULL,
  `date_42` date DEFAULT NULL,
  `age_42` varchar(5) DEFAULT NULL,
  `stature_42` varchar(6) DEFAULT NULL,
  `weight_42` varchar(6) DEFAULT NULL,
  `comment_42` varchar(25) DEFAULT NULL,
  `bmi_42` varchar(5) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formHomeFalls`
--


CREATE TABLE `formHomeFalls` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `floor1Y` tinyint(1) DEFAULT NULL,
  `floor1N` tinyint(1) DEFAULT NULL,
  `floor2Y` tinyint(1) DEFAULT NULL,
  `floor2N` tinyint(1) DEFAULT NULL,
  `floor3Y` tinyint(1) DEFAULT NULL,
  `floor3N` tinyint(1) DEFAULT NULL,
  `floor4Y` tinyint(1) DEFAULT NULL,
  `floor4N` tinyint(1) DEFAULT NULL,
  `floor4NA` tinyint(1) DEFAULT NULL,
  `furniture5Y` tinyint(1) DEFAULT NULL,
  `furniture5N` tinyint(1) DEFAULT NULL,
  `furniture5NA` tinyint(1) DEFAULT NULL,
  `furniture6Y` tinyint(1) DEFAULT NULL,
  `furniture6N` tinyint(1) DEFAULT NULL,
  `furniture6NA` tinyint(1) DEFAULT NULL,
  `lighting7Y` tinyint(1) DEFAULT NULL,
  `lighting7N` tinyint(1) DEFAULT NULL,
  `lighting8Y` tinyint(1) DEFAULT NULL,
  `lighting8N` tinyint(1) DEFAULT NULL,
  `lighting9Y` tinyint(1) DEFAULT NULL,
  `lighting9N` tinyint(1) DEFAULT NULL,
  `lighting9NA` tinyint(1) DEFAULT NULL,
  `bathroom10Y` tinyint(1) DEFAULT NULL,
  `bathroom10N` tinyint(1) DEFAULT NULL,
  `bathroom10NA` tinyint(1) DEFAULT NULL,
  `bathroom11Y` tinyint(1) DEFAULT NULL,
  `bathroom11N` tinyint(1) DEFAULT NULL,
  `bathroom11NA` tinyint(1) DEFAULT NULL,
  `bathroom12Y` tinyint(1) DEFAULT NULL,
  `bathroom12N` tinyint(1) DEFAULT NULL,
  `bathroom12NA` tinyint(1) DEFAULT NULL,
  `bathroom13Y` tinyint(1) DEFAULT NULL,
  `bathroom13N` tinyint(1) DEFAULT NULL,
  `bathroom14Y` tinyint(1) DEFAULT NULL,
  `bathroom14N` tinyint(1) DEFAULT NULL,
  `bathroom15Y` tinyint(1) DEFAULT NULL,
  `bathroom15N` tinyint(1) DEFAULT NULL,
  `storage16Y` tinyint(1) DEFAULT NULL,
  `storage16N` tinyint(1) DEFAULT NULL,
  `storage17Y` tinyint(1) DEFAULT NULL,
  `storage17N` tinyint(1) DEFAULT NULL,
  `stairway18Y` tinyint(1) DEFAULT NULL,
  `stairway18N` tinyint(1) DEFAULT NULL,
  `stairway18NA` tinyint(1) DEFAULT NULL,
  `stairway19Y` tinyint(1) DEFAULT NULL,
  `stairway19N` tinyint(1) DEFAULT NULL,
  `stairway19NA` tinyint(1) DEFAULT NULL,
  `stairway20Y` tinyint(1) DEFAULT NULL,
  `stairway20N` tinyint(1) DEFAULT NULL,
  `stairway20NA` tinyint(1) DEFAULT NULL,
  `stairway21Y` tinyint(1) DEFAULT NULL,
  `stairway21N` tinyint(1) DEFAULT NULL,
  `stairway21NA` tinyint(1) DEFAULT NULL,
  `stairway22Y` tinyint(1) DEFAULT NULL,
  `stairway22N` tinyint(1) DEFAULT NULL,
  `mobility23Y` tinyint(1) DEFAULT NULL,
  `mobility23N` tinyint(1) DEFAULT NULL,
  `mobility23NA` tinyint(1) DEFAULT NULL,
  `mobility24Y` tinyint(1) DEFAULT NULL,
  `mobility24N` tinyint(1) DEFAULT NULL,
  `mobility25Y` tinyint(1) DEFAULT NULL,
  `mobility25N` tinyint(1) DEFAULT NULL,
  `mobility25NA` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formImmunAllergy`
--


CREATE TABLE `formImmunAllergy` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `c_surname` varchar(30) DEFAULT NULL,
  `c_givenName` varchar(30) DEFAULT NULL,
  `dateAdmin` date DEFAULT NULL,
  `tradeName` varchar(50) DEFAULT NULL,
  `manufacturer` varchar(50) DEFAULT NULL,
  `lot` varchar(50) DEFAULT NULL,
  `expiDate` date DEFAULT NULL,
  `doseAdminSC` tinyint(1) DEFAULT NULL,
  `doseAdminIM` tinyint(1) DEFAULT NULL,
  `doseAdminml` tinyint(1) DEFAULT NULL,
  `doseAdminTxtml` varchar(10) DEFAULT NULL,
  `locLtDel` tinyint(1) DEFAULT NULL,
  `locRtDel` tinyint(1) DEFAULT NULL,
  `locLtDelOUQ` tinyint(1) DEFAULT NULL,
  `locRtDelOUQ` tinyint(1) DEFAULT NULL,
  `locOther` tinyint(1) DEFAULT NULL,
  `InstrStay20` tinyint(1) DEFAULT NULL,
  `InstrExpectLoc` tinyint(1) DEFAULT NULL,
  `InstrFU` tinyint(1) DEFAULT NULL,
  `disChNoComp` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formIntakeHx`
--


CREATE TABLE `formIntakeHx` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `student_number` varchar(50) DEFAULT NULL,
  `student_surname` varchar(50) DEFAULT NULL,
  `student_firstname` varchar(50) DEFAULT NULL,
  `student_dob` varchar(50) DEFAULT NULL,
  `student_sex` varchar(50) DEFAULT NULL,
  `student_ercontact_name` varchar(50) DEFAULT NULL,
  `student_ercontact_phone` varchar(50) DEFAULT NULL,
  `student_ercontact_address` varchar(50) DEFAULT NULL,
  `student_ercontact_address2` varchar(50) DEFAULT NULL,
  `student_physician_name` varchar(50) DEFAULT NULL,
  `student_physician_address` varchar(50) DEFAULT NULL,
  `student_physician_address2` varchar(50) DEFAULT NULL,
  `student_physician_phone` varchar(50) DEFAULT NULL,
  `student_faculty_phone` varchar(50) DEFAULT NULL,
  `academic_year` varchar(50) DEFAULT NULL,
  `pt_ft` varchar(50) DEFAULT NULL,
  `AllergicYesNo` varchar(50) DEFAULT NULL,
  `AllergicNonDrugYesNo` varchar(50) DEFAULT NULL,
  `DrugAllergy1` varchar(50) DEFAULT NULL,
  `DrugAllergyRS1` varchar(50) DEFAULT NULL,
  `DrugAllergy2` varchar(50) DEFAULT NULL,
  `DrugAllergyRS2` varchar(50) DEFAULT NULL,
  `DrugAllergy3` varchar(50) DEFAULT NULL,
  `DrugAllergyRS3` varchar(50) DEFAULT NULL,
  `DrugAllergy4` varchar(50) DEFAULT NULL,
  `DrugAllergyRS4` varchar(50) DEFAULT NULL,
  `DrugAllergy5` varchar(50) DEFAULT NULL,
  `DrugAllergyRS5` varchar(50) DEFAULT NULL,
  `DrugAllergy6` varchar(50) DEFAULT NULL,
  `DrugAllergyRS6` varchar(50) DEFAULT NULL,
  `DrugAllergy7` varchar(50) DEFAULT NULL,
  `DrugAllergyRS7` varchar(50) DEFAULT NULL,
  `DrugAllergy8` varchar(50) DEFAULT NULL,
  `DrugAllergyRS8` varchar(50) DEFAULT NULL,
  `AllergicShotsYesNo` varchar(50) DEFAULT NULL,
  `allergicbee` tinyint(1) DEFAULT NULL,
  `allergicragweed` tinyint(1) DEFAULT NULL,
  `allergicOtherPollens` tinyint(1) DEFAULT NULL,
  `allergicgrasses` tinyint(1) DEFAULT NULL,
  `allergicdust` tinyint(1) DEFAULT NULL,
  `allergicanimal` tinyint(1) DEFAULT NULL,
  `allergicother` tinyint(1) DEFAULT NULL,
  `allergicfood` tinyint(1) DEFAULT NULL,
  `TakeOtherDrugs` varchar(50) DEFAULT NULL,
  `CurrentDrug1` varchar(50) DEFAULT NULL,
  `CurrentDrug2` varchar(50) DEFAULT NULL,
  `CurrentDrug3` varchar(50) DEFAULT NULL,
  `CurrentDrug4` varchar(50) DEFAULT NULL,
  `CurrentDrug5` varchar(50) DEFAULT NULL,
  `CurrentDrug6` varchar(50) DEFAULT NULL,
  `CurrentDrug7` varchar(50) DEFAULT NULL,
  `SeriousIllness` varchar(50) DEFAULT NULL,
  `PastIllness1` varchar(50) DEFAULT NULL,
  `IllnessAge1` varchar(50) DEFAULT NULL,
  `PastIllness2` varchar(50) DEFAULT NULL,
  `IllnessAge2` varchar(50) DEFAULT NULL,
  `PastIllness3` varchar(50) DEFAULT NULL,
  `IllnessAge3` varchar(50) DEFAULT NULL,
  `PastIllness4` varchar(50) DEFAULT NULL,
  `IllnessAge4` varchar(50) DEFAULT NULL,
  `PastIllness5` varchar(50) DEFAULT NULL,
  `IllnessAge5` varchar(50) DEFAULT NULL,
  `PastIllness6` varchar(50) DEFAULT NULL,
  `IllnessAge6` varchar(50) DEFAULT NULL,
  `operations` varchar(50) DEFAULT NULL,
  `NameofOperation1` varchar(50) DEFAULT NULL,
  `NameofOperationAge1` varchar(50) DEFAULT NULL,
  `NameofOperation2` varchar(50) DEFAULT NULL,
  `NameofOperationAge2` varchar(50) DEFAULT NULL,
  `NameofOperation3` varchar(50) DEFAULT NULL,
  `NameofOperationAge3` varchar(50) DEFAULT NULL,
  `NameofOperation4` varchar(50) DEFAULT NULL,
  `NameofOperationAge4` varchar(50) DEFAULT NULL,
  `NameofOperation5` varchar(50) DEFAULT NULL,
  `NameofOperationAge5` varchar(50) DEFAULT NULL,
  `NameofOperation6` varchar(50) DEFAULT NULL,
  `NameofOperationAge6` varchar(50) DEFAULT NULL,
  `Conditionsbrokenbones` varchar(50) DEFAULT NULL,
  `ConditionsDescbrokenbones` varchar(50) DEFAULT NULL,
  `Conditionsmigraine` varchar(50) DEFAULT NULL,
  `ConditionsDescmigraine` varchar(50) DEFAULT NULL,
  `Conditionsneurologicdisorder` varchar(50) DEFAULT NULL,
  `ConditionsDescneurologicdisorder` varchar(50) DEFAULT NULL,
  `Conditionsasthma` varchar(50) DEFAULT NULL,
  `ConditionsDescasthma` varchar(50) DEFAULT NULL,
  `Conditionspneumonia` varchar(50) DEFAULT NULL,
  `ConditionsDescpneumonia` varchar(50) DEFAULT NULL,
  `Conditionslungdisease` varchar(50) DEFAULT NULL,
  `ConditionsDesclungdisease` varchar(50) DEFAULT NULL,
  `Conditionsheartdisease` varchar(50) DEFAULT NULL,
  `ConditionsDescheartdisease` varchar(50) DEFAULT NULL,
  `Conditionsulcer` varchar(50) DEFAULT NULL,
  `ConditionsDesculcer` varchar(50) DEFAULT NULL,
  `Conditionsboweldisease` varchar(50) DEFAULT NULL,
  `ConditionsDescboweldisease` varchar(50) DEFAULT NULL,
  `Conditionshepatitis` varchar(50) DEFAULT NULL,
  `ConditionsDeschepatitis` varchar(50) DEFAULT NULL,
  `ConditionsHIV` varchar(50) DEFAULT NULL,
  `ConditionsDescHIV` varchar(50) DEFAULT NULL,
  `Conditionsthyroid` varchar(50) DEFAULT NULL,
  `ConditionsDescthyroid` varchar(50) DEFAULT NULL,
  `Conditionsblooddisorder` varchar(50) DEFAULT NULL,
  `ConditionsDescblooddisorder` varchar(50) DEFAULT NULL,
  `Conditionsdiabetes` varchar(50) DEFAULT NULL,
  `ConditionsDescdiabetes` varchar(50) DEFAULT NULL,
  `Conditionsbloodtransfusion` varchar(50) DEFAULT NULL,
  `ConditionsDescbloodtransfusion` varchar(50) DEFAULT NULL,
  `Conditionscancerorleukemia` varchar(50) DEFAULT NULL,
  `ConditionsDesccancerorleukemia` varchar(50) DEFAULT NULL,
  `Conditionssexualdisease` varchar(50) DEFAULT NULL,
  `ConditionsDescsexualdisease` varchar(50) DEFAULT NULL,
  `ConditionsURI` varchar(50) DEFAULT NULL,
  `ConditionsDescURI` varchar(50) DEFAULT NULL,
  `Conditionsemotional` varchar(50) DEFAULT NULL,
  `ConditionsDescemotional` varchar(50) DEFAULT NULL,
  `Conditionsarthritis` varchar(50) DEFAULT NULL,
  `ConditionsDescarthritis` varchar(50) DEFAULT NULL,
  `Conditionseatingdisorder` varchar(50) DEFAULT NULL,
  `ConditionsDesceatingdisorder` varchar(50) DEFAULT NULL,
  `Conditionsosteoporosis` varchar(50) DEFAULT NULL,
  `ConditionsDescosteoporosis` varchar(50) DEFAULT NULL,
  `Conditionsskin` varchar(50) DEFAULT NULL,
  `ConditionsDescskin` varchar(50) DEFAULT NULL,
  `ConditionsHighbloodpressure` varchar(50) DEFAULT NULL,
  `ConditionsDescHighbloodpressure` varchar(50) DEFAULT NULL,
  `Conditionslearningdisability` varchar(50) DEFAULT NULL,
  `ConditionsDesclearningdisability` varchar(50) DEFAULT NULL,
  `Conditionsschizophrenia` varchar(50) DEFAULT NULL,
  `ConditionsDescschizophrenia` varchar(50) DEFAULT NULL,
  `Conditionsalcohol` varchar(50) DEFAULT NULL,
  `ConditionsDescalcohol` varchar(50) DEFAULT NULL,
  `ConditionsMS` varchar(50) DEFAULT NULL,
  `ConditionsDescMS` varchar(50) DEFAULT NULL,
  `Conditionsstroke` varchar(50) DEFAULT NULL,
  `ConditionsDescstroke` varchar(50) DEFAULT NULL,
  `ConditionsHighcholesterol` varchar(50) DEFAULT NULL,
  `ConditionsDescHighcholesterol` varchar(50) DEFAULT NULL,
  `Conditionsdepression` varchar(50) DEFAULT NULL,
  `ConditionsDescdepression` varchar(50) DEFAULT NULL,
  `ConditionsDrugdependency` varchar(50) DEFAULT NULL,
  `ConditionsDescDrugdependency` varchar(50) DEFAULT NULL,
  `ConditionsOtherdisease` text,
  `ConditionsDescOtherdisease` varchar(50) DEFAULT NULL,
  `ImmunizationHepatitisB` varchar(50) DEFAULT NULL,
  `ImmunizationYearHepatitisB` varchar(50) DEFAULT NULL,
  `ImmunizationHadTetanus` varchar(50) DEFAULT NULL,
  `ImmunizationYearTetanus` varchar(50) DEFAULT NULL,
  `ImmunizationHadPolio` varchar(50) DEFAULT NULL,
  `ImmunizationYearPolio` varchar(50) DEFAULT NULL,
  `ImmunizationHadMMR` varchar(50) DEFAULT NULL,
  `ImmunizationYearMMR` varchar(50) DEFAULT NULL,
  `ImmunizationHadTB` varchar(50) DEFAULT NULL,
  `ImmunizationYearTB` varchar(50) DEFAULT NULL,
  `ImmunizationHadRubella` varchar(50) DEFAULT NULL,
  `ImmunizationYearRubella` varchar(50) DEFAULT NULL,
  `ImmunizationHadVaricella` varchar(50) DEFAULT NULL,
  `ImmunizationYearVaricella` varchar(50) DEFAULT NULL,
  `ImmunizationHadMeningitis` varchar(50) DEFAULT NULL,
  `ImmunizationYearMeningitis` varchar(50) DEFAULT NULL,
  `ImmunizationHadPneumococcus` varchar(50) DEFAULT NULL,
  `ImmunizationYearPneumococcus` varchar(50) DEFAULT NULL,
  `HaveImmunizationCard` varchar(50) DEFAULT NULL,
  `SeatBelt` varchar(50) DEFAULT NULL,
  `smoker` varchar(50) DEFAULT NULL,
  `HowMuchSmoke` varchar(50) DEFAULT NULL,
  `smokeInPast` varchar(50) DEFAULT NULL,
  `UseDrugs` varchar(50) DEFAULT NULL,
  `Alcohol` varchar(50) DEFAULT NULL,
  `HowManyDrinks` varchar(50) DEFAULT NULL,
  `HowManyDrinksWeek` varchar(50) DEFAULT NULL,
  `exercise` varchar(50) DEFAULT NULL,
  `biologicalmigraine` varchar(50) DEFAULT NULL,
  `biologicalDescmigraine` varchar(50) DEFAULT NULL,
  `biologicalneurologic` varchar(50) DEFAULT NULL,
  `biologicalDescneurologic` varchar(50) DEFAULT NULL,
  `biologicalasthma` varchar(50) DEFAULT NULL,
  `biologicalDescasthma` varchar(50) DEFAULT NULL,
  `biologicalpneumonia` varchar(50) DEFAULT NULL,
  `biologicalDescpneumonia` varchar(50) DEFAULT NULL,
  `biologicallungdisease` varchar(50) DEFAULT NULL,
  `biologicalDesclungdisease` varchar(50) DEFAULT NULL,
  `biologicalheartdisease` varchar(50) DEFAULT NULL,
  `biologicalDescheartdisease` varchar(50) DEFAULT NULL,
  `biologicalulcer` varchar(50) DEFAULT NULL,
  `biologicalDesculcer` varchar(50) DEFAULT NULL,
  `biologicalboweldisease` varchar(50) DEFAULT NULL,
  `biologicalDescboweldisease` varchar(50) DEFAULT NULL,
  `biologicalhepatitis` varchar(50) DEFAULT NULL,
  `biologicalDeschepatitis` varchar(50) DEFAULT NULL,
  `biologicalthyroid` varchar(50) DEFAULT NULL,
  `biologicalDescthyroid` varchar(50) DEFAULT NULL,
  `biologicalblooddisorder` varchar(50) DEFAULT NULL,
  `biologicalDescblooddisorder` varchar(50) DEFAULT NULL,
  `biologicaldiabetes` varchar(50) DEFAULT NULL,
  `biologicalDescdiabetes` varchar(50) DEFAULT NULL,
  `biologicalbloodtransfusion` varchar(50) DEFAULT NULL,
  `biologicalDescbloodtransfusion` varchar(50) DEFAULT NULL,
  `biologicalcancerorleukemia` varchar(50) DEFAULT NULL,
  `biologicalDesccancerorleukemia` varchar(50) DEFAULT NULL,
  `biologicalURI` varchar(50) DEFAULT NULL,
  `biologicalDescURI` varchar(50) DEFAULT NULL,
  `biologicalemotional` varchar(50) DEFAULT NULL,
  `biologicalDescemotional` varchar(50) DEFAULT NULL,
  `biologicalarthritis` varchar(50) DEFAULT NULL,
  `biologicalDescarthritis` varchar(50) DEFAULT NULL,
  `biologicalosteoporosis` varchar(50) DEFAULT NULL,
  `biologicalDescosteoporosis` varchar(50) DEFAULT NULL,
  `biologicalskin` varchar(50) DEFAULT NULL,
  `biologicalDescskin` varchar(50) DEFAULT NULL,
  `biologicalHBP` varchar(50) DEFAULT NULL,
  `biologicalDescHBP` varchar(50) DEFAULT NULL,
  `biologicallearningdisability` varchar(50) DEFAULT NULL,
  `biologicalDesclearningdisability` varchar(50) DEFAULT NULL,
  `biologicalschizophrenia` varchar(50) DEFAULT NULL,
  `biologicalDescschizophrenia` varchar(50) DEFAULT NULL,
  `biologicalalcohol` varchar(50) DEFAULT NULL,
  `biologicalDescalcohol` varchar(50) DEFAULT NULL,
  `biologicalMS` varchar(50) DEFAULT NULL,
  `biologicalDescMS` varchar(50) DEFAULT NULL,
  `biologicalstroke` varchar(50) DEFAULT NULL,
  `biologicalDescstroke` varchar(50) DEFAULT NULL,
  `biologicalhighcholesterol` varchar(50) DEFAULT NULL,
  `biologicalDeschighcholesterol` varchar(50) DEFAULT NULL,
  `biologicaldepression` varchar(50) DEFAULT NULL,
  `biologicalDescdepression` varchar(50) DEFAULT NULL,
  `biologicaldrug` varchar(50) DEFAULT NULL,
  `biologicalDescdrug` varchar(50) DEFAULT NULL,
  `General` varchar(250) DEFAULT NULL,
  `Nervous` varchar(250) DEFAULT NULL,
  `HEENT` varchar(250) DEFAULT NULL,
  `Neck` varchar(250) DEFAULT NULL,
  `Chest` varchar(250) DEFAULT NULL,
  `Heart` varchar(250) DEFAULT NULL,
  `Gastrointestinal` varchar(250) DEFAULT NULL,
  `GenitalsUrinary` varchar(250) DEFAULT NULL,
  `GeneralPsychiatric` varchar(250) DEFAULT NULL,
  `firstPeriod` varchar(50) DEFAULT NULL,
  `monthlyPeriod` text,
  `periodLength` text,
  `severeCramps` text,
  `unusualBleeding` text,
  `PID` text,
  `ovarianCyst` text,
  `breastCancer` text,
  `hadBreastLump` text,
  `BeenPregnant` text,
  `TherapeuticAbortion` text,
  `AgeHadAbortion` text,
  `HadPap` text,
  `AbnormalPap` text,
  `LastPap` text,
  `usedBirthControl` text,
  `birthcontrolUsed1` varchar(50) DEFAULT NULL,
  `birthcontrolUsed2` varchar(50) DEFAULT NULL,
  `birthcontrolUsed3` varchar(50) DEFAULT NULL,
  `birthcontrolUsed4` varchar(50) DEFAULT NULL,
  `onbirthcontrol` varchar(50) DEFAULT NULL,
  `problemsBirthControl` varchar(50) DEFAULT NULL,
  `monthlyBreastSelfExam` varchar(50) DEFAULT NULL,
  `hadSexualIntercourse` varchar(50) DEFAULT NULL,
  `sexWithMale` varchar(50) DEFAULT NULL,
  `sexWithFemale` varchar(50) DEFAULT NULL,
  `ageHadSex` varchar(50) DEFAULT NULL,
  `partnersLastYear` varchar(50) DEFAULT NULL,
  `HowOftenUseCondoms` varchar(50) DEFAULT NULL,
  `hadSTD` varchar(50) DEFAULT NULL,
  `hadHPV` varchar(50) DEFAULT NULL,
  `hadchlamydia` varchar(50) DEFAULT NULL,
  `hadgonorrhea` varchar(50) DEFAULT NULL,
  `hadHSV2` varchar(50) DEFAULT NULL,
  `hadsyphilis` varchar(50) DEFAULT NULL,
  `immunizationDiseasePneumococcus` text,
  `immunizationDiseaseYearPneumococcus` text,
  `immunizationDiseaseMeningitis` text,
  `immunizationDiseaseYearMeningitis` text,
  `immunizationDiseaseVaricella` text,
  `immunizationDiseaseYearVaricella` text,
  `immunizationDiseaseTb` text,
  `immunizationDiseaseYearTb` text,
  `immunizationDiseaseRubella` text,
  `immunizationDiseaseYearRubella` text,
  `immunizationDiseaseMMR` text,
  `immunizationDiseaseYearMMR` text,
  `immunizationDiseasePolio` text,
  `immunizationDiseaseYearPolio` text,
  `immunizationDiseaseTetanus` text,
  `immunizationDiseaseYearTetanus` text,
  `immunizationDiseaseYearHepatitisB` text,
  `immunizationDiseaseHepatitisB` text,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formIntakeInfo`
--


CREATE TABLE `formIntakeInfo` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `sex` varchar(1) DEFAULT NULL,
  `dob` date DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `ethnoCulturalGr` varchar(255) DEFAULT NULL,
  `accommodationHouse` tinyint(1) DEFAULT NULL,
  `accommodationApt` tinyint(1) DEFAULT NULL,
  `accommodationSen` tinyint(1) DEFAULT NULL,
  `accommodationNur` tinyint(1) DEFAULT NULL,
  `accommodationLTC` tinyint(1) DEFAULT NULL,
  `maritalStMarried` tinyint(1) DEFAULT NULL,
  `maritalStLivingTogether` tinyint(1) DEFAULT NULL,
  `maritalStSeparated` tinyint(1) DEFAULT NULL,
  `maritalStDivorced` tinyint(1) DEFAULT NULL,
  `maritalStWidowed` tinyint(1) DEFAULT NULL,
  `maritalStRemarried` tinyint(1) DEFAULT NULL,
  `maritalStNeverMarried` tinyint(1) DEFAULT NULL,
  `nbpplInHousehold` int(3) DEFAULT NULL,
  `helpY` tinyint(1) DEFAULT NULL,
  `helpN` tinyint(1) DEFAULT NULL,
  `helpNoNeed` tinyint(1) DEFAULT NULL,
  `helpRelationshipSpouse` tinyint(1) DEFAULT NULL,
  `helpRelationshipSibling` tinyint(1) DEFAULT NULL,
  `helpRelationshipFriend` tinyint(1) DEFAULT NULL,
  `helpRelationshipChildren` tinyint(1) DEFAULT NULL,
  `helpRelationshipGChildren` tinyint(1) DEFAULT NULL,
  `otherSupportFriends` tinyint(1) DEFAULT NULL,
  `otherSupportSiblings` tinyint(1) DEFAULT NULL,
  `otherSupportNeighbour` tinyint(1) DEFAULT NULL,
  `otherSupportChildren` tinyint(1) DEFAULT NULL,
  `otherSupportGChildren` tinyint(1) DEFAULT NULL,
  `eduNoSchool` tinyint(1) DEFAULT NULL,
  `eduSomeCommunity` tinyint(1) DEFAULT NULL,
  `eduSomeElementary` tinyint(1) DEFAULT NULL,
  `eduCompletedCommunity` tinyint(1) DEFAULT NULL,
  `eduCompletedElementary` tinyint(1) DEFAULT NULL,
  `eduSomeUni` tinyint(1) DEFAULT NULL,
  `eduSomeSec` tinyint(1) DEFAULT NULL,
  `eduCompletedUni` tinyint(1) DEFAULT NULL,
  `eduCompletedSec` tinyint(1) DEFAULT NULL,
  `incomeBelow10` tinyint(1) DEFAULT NULL,
  `income40To50` tinyint(1) DEFAULT NULL,
  `income10To20` tinyint(1) DEFAULT NULL,
  `incomeOver50` tinyint(1) DEFAULT NULL,
  `income20To30` tinyint(1) DEFAULT NULL,
  `incomeDoNotKnow` tinyint(1) DEFAULT NULL,
  `income30To40` tinyint(1) DEFAULT NULL,
  `incomeRefusedToAns` tinyint(1) DEFAULT NULL,
  `financialDifficult` tinyint(1) DEFAULT NULL,
  `financialEnough` tinyint(1) DEFAULT NULL,
  `financialComfortable` tinyint(1) DEFAULT NULL,
  `ActPaidWk` int(4) DEFAULT NULL,
  `ActUnpaidWk` int(4) DEFAULT NULL,
  `ActVolunteering` int(4) DEFAULT NULL,
  `ActCaregiving` int(4) DEFAULT NULL,
  `anyHealthPb` varchar(255) DEFAULT NULL,
  `smkY` tinyint(1) DEFAULT NULL,
  `smkN` tinyint(1) DEFAULT NULL,
  `nbCigarettes` int(5) DEFAULT NULL,
  `howLongSmk` varchar(20) DEFAULT NULL,
  `didSmkY` tinyint(1) DEFAULT NULL,
  `didSmkN` tinyint(1) DEFAULT NULL,
  `didNbCigarettes` int(5) DEFAULT NULL,
  `didHowLongSmk` varchar(20) DEFAULT NULL,
  `alcoholY` tinyint(1) DEFAULT NULL,
  `alcoholN` tinyint(1) DEFAULT NULL,
  `more12DrinksY` tinyint(1) DEFAULT NULL,
  `more12DrinksN` tinyint(1) DEFAULT NULL,
  `heartAttackY` tinyint(1) DEFAULT NULL,
  `heartAttackRefused` tinyint(1) DEFAULT NULL,
  `heartAttackN` tinyint(1) DEFAULT NULL,
  `heartAttackDoNotKnow` tinyint(1) DEFAULT NULL,
  `anginaY` tinyint(1) DEFAULT NULL,
  `anginaRefused` tinyint(1) DEFAULT NULL,
  `anginaN` tinyint(1) DEFAULT NULL,
  `anginaDoNotKnow` tinyint(1) DEFAULT NULL,
  `heartFailureY` tinyint(1) DEFAULT NULL,
  `heartFailureRefused` tinyint(1) DEFAULT NULL,
  `heartFailureN` tinyint(1) DEFAULT NULL,
  `heartFailureDoNotKnow` tinyint(1) DEFAULT NULL,
  `highBPY` tinyint(1) DEFAULT NULL,
  `highBPRefused` tinyint(1) DEFAULT NULL,
  `highBPN` tinyint(1) DEFAULT NULL,
  `highBPDoNotKnow` tinyint(1) DEFAULT NULL,
  `otherHeartDiseaseY` tinyint(1) DEFAULT NULL,
  `otherHeartDiseaseRefused` tinyint(1) DEFAULT NULL,
  `otherHeartDiseaseN` tinyint(1) DEFAULT NULL,
  `otherHeartDiseaseDoNotKnow` tinyint(1) DEFAULT NULL,
  `diabetesY` tinyint(1) DEFAULT NULL,
  `diabetesRefused` tinyint(1) DEFAULT NULL,
  `diabetesN` tinyint(1) DEFAULT NULL,
  `diabetesDoNotKnow` tinyint(1) DEFAULT NULL,
  `arthritisY` tinyint(1) DEFAULT NULL,
  `arthritisRefused` tinyint(1) DEFAULT NULL,
  `arthritisN` tinyint(1) DEFAULT NULL,
  `arthritisDoNotKnow` tinyint(1) DEFAULT NULL,
  `strokeY` tinyint(1) DEFAULT NULL,
  `strokeRefused` tinyint(1) DEFAULT NULL,
  `strokeN` tinyint(1) DEFAULT NULL,
  `strokeDoNotKnow` tinyint(1) DEFAULT NULL,
  `cancerY` tinyint(1) DEFAULT NULL,
  `cancerRefused` tinyint(1) DEFAULT NULL,
  `cancerN` tinyint(1) DEFAULT NULL,
  `cancerDoNotKnow` tinyint(1) DEFAULT NULL,
  `brokenHipY` tinyint(1) DEFAULT NULL,
  `brokenHipRefused` tinyint(1) DEFAULT NULL,
  `brokenHipN` tinyint(1) DEFAULT NULL,
  `brokenHipDoNotKnow` tinyint(1) DEFAULT NULL,
  `parkinsonY` tinyint(1) DEFAULT NULL,
  `parkinsonRefused` tinyint(1) DEFAULT NULL,
  `parkinsonN` tinyint(1) DEFAULT NULL,
  `parkinsonDoNotKnow` tinyint(1) DEFAULT NULL,
  `lungDiseaseY` tinyint(1) DEFAULT NULL,
  `lungDiseaseRefused` tinyint(1) DEFAULT NULL,
  `lungDiseaseN` tinyint(1) DEFAULT NULL,
  `lungDiseaseDoNotKnow` tinyint(1) DEFAULT NULL,
  `hearingPbY` tinyint(1) DEFAULT NULL,
  `hearingPbRefused` tinyint(1) DEFAULT NULL,
  `hearingPbN` tinyint(1) DEFAULT NULL,
  `hearingPbDoNotKnow` tinyint(1) DEFAULT NULL,
  `visionPbY` tinyint(1) DEFAULT NULL,
  `visionPbRefused` tinyint(1) DEFAULT NULL,
  `visionPbN` tinyint(1) DEFAULT NULL,
  `visionPbDoNotKnow` tinyint(1) DEFAULT NULL,
  `osteoporosisY` tinyint(1) DEFAULT NULL,
  `osteoporosisRefused` tinyint(1) DEFAULT NULL,
  `osteoporosisN` tinyint(1) DEFAULT NULL,
  `osteoporosisDoNotKnow` tinyint(1) DEFAULT NULL,
  `fibromyalgiaY` tinyint(1) DEFAULT NULL,
  `fibromyalgiaRefused` tinyint(1) DEFAULT NULL,
  `fibromyalgiaN` tinyint(1) DEFAULT NULL,
  `fibromyalgiaDoNotKnow` tinyint(1) DEFAULT NULL,
  `multiplesclerosisY` tinyint(1) DEFAULT NULL,
  `multiplesclerosisRefused` tinyint(1) DEFAULT NULL,
  `multiplesclerosisN` tinyint(1) DEFAULT NULL,
  `multiplesclerosisDoNotKnow` tinyint(1) DEFAULT NULL,
  `asthmaY` tinyint(1) DEFAULT NULL,
  `asthmaRefused` tinyint(1) DEFAULT NULL,
  `asthmaN` tinyint(1) DEFAULT NULL,
  `asthmaDoNotKnow` tinyint(1) DEFAULT NULL,
  `backpainY` tinyint(1) DEFAULT NULL,
  `backpainRefused` tinyint(1) DEFAULT NULL,
  `backpainN` tinyint(1) DEFAULT NULL,
  `backpainDoNotKnow` tinyint(1) DEFAULT NULL,
  `weightY` tinyint(1) DEFAULT NULL,
  `weightRefused` tinyint(1) DEFAULT NULL,
  `weightN` tinyint(1) DEFAULT NULL,
  `weightDoNotKnow` tinyint(1) DEFAULT NULL,
  `weight` varchar(10) DEFAULT NULL,
  `height` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formInternetAccess`
--


CREATE TABLE `formInternetAccess` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `computerY` tinyint(1) DEFAULT NULL,
  `computerN` tinyint(1) DEFAULT NULL,
  `internetY` tinyint(1) DEFAULT NULL,
  `internetN` tinyint(1) DEFAULT NULL,
  `internetHome` tinyint(1) DEFAULT NULL,
  `internetWork` tinyint(1) DEFAULT NULL,
  `internetOther` tinyint(1) DEFAULT NULL,
  `internetOtherTx` varchar(255) DEFAULT NULL,
  `timeDaily` varchar(2) DEFAULT NULL,
  `timeWeekly` varchar(3) DEFAULT NULL,
  `infoY` tinyint(1) DEFAULT NULL,
  `infoN` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formLabReq`
--


CREATE TABLE `formLabReq` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `provName` varchar(60) DEFAULT NULL,
  `reqProvName` varchar(60) DEFAULT '',
  `clinicAddress` varchar(30) DEFAULT NULL,
  `clinicCity` varchar(20) DEFAULT NULL,
  `clinicPC` varchar(7) DEFAULT NULL,
  `practitionerNo` varchar(14) DEFAULT NULL,
  `ohip` tinyint(1) DEFAULT NULL,
  `thirdParty` tinyint(1) DEFAULT NULL,
  `wcb` tinyint(1) DEFAULT NULL,
  `aci` text,
  `healthNumber` varchar(10) DEFAULT NULL,
  `version` char(2) DEFAULT NULL,
  `birthDate` date DEFAULT NULL,
  `paymentProgram` varchar(4) DEFAULT NULL,
  `province` varchar(15) DEFAULT NULL,
  `orn` varchar(12) DEFAULT NULL,
  `phoneNumber` varchar(20) DEFAULT NULL,
  `patientName` varchar(40) DEFAULT NULL,
  `sex` varchar(6) DEFAULT NULL,
  `patientAddress` varchar(20) DEFAULT NULL,
  `patientCity` varchar(20) DEFAULT NULL,
  `patientPC` varchar(7) DEFAULT NULL,
  `b_glucose` tinyint(1) DEFAULT NULL,
  `b_creatine` tinyint(1) DEFAULT NULL,
  `b_uricAcid` tinyint(1) DEFAULT NULL,
  `b_sodium` tinyint(1) DEFAULT NULL,
  `b_potassium` tinyint(1) DEFAULT NULL,
  `b_chloride` tinyint(1) DEFAULT NULL,
  `b_ast` tinyint(1) DEFAULT NULL,
  `b_alkPhosphate` tinyint(1) DEFAULT NULL,
  `b_bilirubin` tinyint(1) DEFAULT NULL,
  `b_cholesterol` tinyint(1) DEFAULT NULL,
  `b_triglyceride` tinyint(1) DEFAULT NULL,
  `b_urinalysis` tinyint(1) DEFAULT NULL,
  `v_acuteHepatitis` tinyint(1) DEFAULT NULL,
  `v_chronicHepatitis` tinyint(1) DEFAULT NULL,
  `v_immune` tinyint(1) DEFAULT NULL,
  `v_hepA` varchar(20) DEFAULT NULL,
  `v_hepB` varchar(20) DEFAULT NULL,
  `h_bloodFilmExam` tinyint(1) DEFAULT NULL,
  `h_hemoglobin` tinyint(1) DEFAULT NULL,
  `h_wcbCount` tinyint(1) DEFAULT NULL,
  `h_hematocrit` tinyint(1) DEFAULT NULL,
  `h_prothrombTime` tinyint(1) DEFAULT NULL,
  `h_otherC` tinyint(1) DEFAULT NULL,
  `h_other` varchar(20) DEFAULT NULL,
  `i_pregnancyTest` tinyint(1) DEFAULT NULL,
  `i_heterophile` tinyint(1) DEFAULT NULL,
  `i_rubella` tinyint(1) DEFAULT NULL,
  `i_prenatal` tinyint(1) DEFAULT NULL,
  `i_repeatPrenatal` tinyint(1) DEFAULT NULL,
  `i_prenatalHepatitisB` tinyint(1) DEFAULT NULL,
  `i_vdrl` tinyint(1) DEFAULT NULL,
  `i_otherC` tinyint(1) DEFAULT NULL,
  `i_other` varchar(20) DEFAULT NULL,
  `m_cervicalVaginal` tinyint(1) DEFAULT NULL,
  `m_sputum` tinyint(1) DEFAULT NULL,
  `m_throat` tinyint(1) DEFAULT NULL,
  `m_urine` tinyint(1) DEFAULT NULL,
  `m_stoolCulture` tinyint(1) DEFAULT NULL,
  `m_otherSwabs` tinyint(1) DEFAULT NULL,
  `m_other` varchar(20) DEFAULT NULL,
  `otherTest` text,
  `formDate` date DEFAULT NULL,
  `signature` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formLateLifeFDIDisability`
--


CREATE TABLE `formLateLifeFDIDisability` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `D1VeryOften` tinyint(1) DEFAULT NULL,
  `D1Often` tinyint(1) DEFAULT NULL,
  `D1OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D1AlmostNever` tinyint(1) DEFAULT NULL,
  `D1Never` tinyint(1) DEFAULT NULL,
  `D1Not` tinyint(1) DEFAULT NULL,
  `D1Little` tinyint(1) DEFAULT NULL,
  `D1Somewhat` tinyint(1) DEFAULT NULL,
  `D1Alot` tinyint(1) DEFAULT NULL,
  `D1Completely` tinyint(1) DEFAULT NULL,
  `D2VeryOften` tinyint(1) DEFAULT NULL,
  `D2Often` tinyint(1) DEFAULT NULL,
  `D2OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D2AlmostNever` tinyint(1) DEFAULT NULL,
  `D2Never` tinyint(1) DEFAULT NULL,
  `D2Not` tinyint(1) DEFAULT NULL,
  `D2Little` tinyint(1) DEFAULT NULL,
  `D2Somewhat` tinyint(1) DEFAULT NULL,
  `D2Alot` tinyint(1) DEFAULT NULL,
  `D2Completely` tinyint(1) DEFAULT NULL,
  `D3VeryOften` tinyint(1) DEFAULT NULL,
  `D3Often` tinyint(1) DEFAULT NULL,
  `D3OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D3AlmostNever` tinyint(1) DEFAULT NULL,
  `D3Never` tinyint(1) DEFAULT NULL,
  `D3Not` tinyint(1) DEFAULT NULL,
  `D3Little` tinyint(1) DEFAULT NULL,
  `D3Somewhat` tinyint(1) DEFAULT NULL,
  `D3Alot` tinyint(1) DEFAULT NULL,
  `D3Completely` tinyint(1) DEFAULT NULL,
  `D4VeryOften` tinyint(1) DEFAULT NULL,
  `D4Often` tinyint(1) DEFAULT NULL,
  `D4OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D4AlmostNever` tinyint(1) DEFAULT NULL,
  `D4Never` tinyint(1) DEFAULT NULL,
  `D4Not` tinyint(1) DEFAULT NULL,
  `D4Little` tinyint(1) DEFAULT NULL,
  `D4Somewhat` tinyint(1) DEFAULT NULL,
  `D4Alot` tinyint(1) DEFAULT NULL,
  `D4Completely` tinyint(1) DEFAULT NULL,
  `D5VeryOften` tinyint(1) DEFAULT NULL,
  `D5Often` tinyint(1) DEFAULT NULL,
  `D5OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D5AlmostNever` tinyint(1) DEFAULT NULL,
  `D5Never` tinyint(1) DEFAULT NULL,
  `D5Not` tinyint(1) DEFAULT NULL,
  `D5Little` tinyint(1) DEFAULT NULL,
  `D5Somewhat` tinyint(1) DEFAULT NULL,
  `D5Alot` tinyint(1) DEFAULT NULL,
  `D5Completely` tinyint(1) DEFAULT NULL,
  `D6VeryOften` tinyint(1) DEFAULT NULL,
  `D6Often` tinyint(1) DEFAULT NULL,
  `D6OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D6AlmostNever` tinyint(1) DEFAULT NULL,
  `D6Never` tinyint(1) DEFAULT NULL,
  `D6Not` tinyint(1) DEFAULT NULL,
  `D6Little` tinyint(1) DEFAULT NULL,
  `D6Somewhat` tinyint(1) DEFAULT NULL,
  `D6Alot` tinyint(1) DEFAULT NULL,
  `D6Completely` tinyint(1) DEFAULT NULL,
  `D7VeryOften` tinyint(1) DEFAULT NULL,
  `D7Often` tinyint(1) DEFAULT NULL,
  `D7OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D7AlmostNever` tinyint(1) DEFAULT NULL,
  `D7Never` tinyint(1) DEFAULT NULL,
  `D7Not` tinyint(1) DEFAULT NULL,
  `D7Little` tinyint(1) DEFAULT NULL,
  `D7Somewhat` tinyint(1) DEFAULT NULL,
  `D7Alot` tinyint(1) DEFAULT NULL,
  `D7Completely` tinyint(1) DEFAULT NULL,
  `D8VeryOften` tinyint(1) DEFAULT NULL,
  `D8Often` tinyint(1) DEFAULT NULL,
  `D8OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D8AlmostNever` tinyint(1) DEFAULT NULL,
  `D8Never` tinyint(1) DEFAULT NULL,
  `D8Not` tinyint(1) DEFAULT NULL,
  `D8Little` tinyint(1) DEFAULT NULL,
  `D8Somewhat` tinyint(1) DEFAULT NULL,
  `D8Alot` tinyint(1) DEFAULT NULL,
  `D8Completely` tinyint(1) DEFAULT NULL,
  `D9VeryOften` tinyint(1) DEFAULT NULL,
  `D9Often` tinyint(1) DEFAULT NULL,
  `D9OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D9AlmostNever` tinyint(1) DEFAULT NULL,
  `D9Never` tinyint(1) DEFAULT NULL,
  `D9Not` tinyint(1) DEFAULT NULL,
  `D9Little` tinyint(1) DEFAULT NULL,
  `D9Somewhat` tinyint(1) DEFAULT NULL,
  `D9Alot` tinyint(1) DEFAULT NULL,
  `D9Completely` tinyint(1) DEFAULT NULL,
  `D10VeryOften` tinyint(1) DEFAULT NULL,
  `D10Often` tinyint(1) DEFAULT NULL,
  `D10OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D10AlmostNever` tinyint(1) DEFAULT NULL,
  `D10Never` tinyint(1) DEFAULT NULL,
  `D10Not` tinyint(1) DEFAULT NULL,
  `D10Little` tinyint(1) DEFAULT NULL,
  `D10Somewhat` tinyint(1) DEFAULT NULL,
  `D10Alot` tinyint(1) DEFAULT NULL,
  `D10Completely` tinyint(1) DEFAULT NULL,
  `D11VeryOften` tinyint(1) DEFAULT NULL,
  `D11Often` tinyint(1) DEFAULT NULL,
  `D11OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D11AlmostNever` tinyint(1) DEFAULT NULL,
  `D11Never` tinyint(1) DEFAULT NULL,
  `D11Not` tinyint(1) DEFAULT NULL,
  `D11Little` tinyint(1) DEFAULT NULL,
  `D11Somewhat` tinyint(1) DEFAULT NULL,
  `D11Alot` tinyint(1) DEFAULT NULL,
  `D11Completely` tinyint(1) DEFAULT NULL,
  `D12VeryOften` tinyint(1) DEFAULT NULL,
  `D12Often` tinyint(1) DEFAULT NULL,
  `D12OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D12AlmostNever` tinyint(1) DEFAULT NULL,
  `D12Never` tinyint(1) DEFAULT NULL,
  `D12Not` tinyint(1) DEFAULT NULL,
  `D12Little` tinyint(1) DEFAULT NULL,
  `D12Somewhat` tinyint(1) DEFAULT NULL,
  `D12Alot` tinyint(1) DEFAULT NULL,
  `D12Completely` tinyint(1) DEFAULT NULL,
  `D13VeryOften` tinyint(1) DEFAULT NULL,
  `D13Often` tinyint(1) DEFAULT NULL,
  `D13OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D13AlmostNever` tinyint(1) DEFAULT NULL,
  `D13Never` tinyint(1) DEFAULT NULL,
  `D13Not` tinyint(1) DEFAULT NULL,
  `D13Little` tinyint(1) DEFAULT NULL,
  `D13Somewhat` tinyint(1) DEFAULT NULL,
  `D13Alot` tinyint(1) DEFAULT NULL,
  `D13Completely` tinyint(1) DEFAULT NULL,
  `D14VeryOften` tinyint(1) DEFAULT NULL,
  `D14Often` tinyint(1) DEFAULT NULL,
  `D14OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D14AlmostNever` tinyint(1) DEFAULT NULL,
  `D14Never` tinyint(1) DEFAULT NULL,
  `D14Not` tinyint(1) DEFAULT NULL,
  `D14Little` tinyint(1) DEFAULT NULL,
  `D14Somewhat` tinyint(1) DEFAULT NULL,
  `D14Alot` tinyint(1) DEFAULT NULL,
  `D14Completely` tinyint(1) DEFAULT NULL,
  `D15VeryOften` tinyint(1) DEFAULT NULL,
  `D15Often` tinyint(1) DEFAULT NULL,
  `D15OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D15AlmostNever` tinyint(1) DEFAULT NULL,
  `D15Never` tinyint(1) DEFAULT NULL,
  `D15Not` tinyint(1) DEFAULT NULL,
  `D15Little` tinyint(1) DEFAULT NULL,
  `D15Somewhat` tinyint(1) DEFAULT NULL,
  `D15Alot` tinyint(1) DEFAULT NULL,
  `D15Completely` tinyint(1) DEFAULT NULL,
  `D16VeryOften` tinyint(1) DEFAULT NULL,
  `D16Often` tinyint(1) DEFAULT NULL,
  `D16OnceInAWhile` tinyint(1) DEFAULT NULL,
  `D16AlmostNever` tinyint(1) DEFAULT NULL,
  `D16Never` tinyint(1) DEFAULT NULL,
  `D16Not` tinyint(1) DEFAULT NULL,
  `D16Little` tinyint(1) DEFAULT NULL,
  `D16Somewhat` tinyint(1) DEFAULT NULL,
  `D16Alot` tinyint(1) DEFAULT NULL,
  `D16Completely` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formLateLifeFDIFunction`
--


CREATE TABLE `formLateLifeFDIFunction` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `F1None` tinyint(1) DEFAULT NULL,
  `F1ALittle` tinyint(1) DEFAULT NULL,
  `F1Some` tinyint(1) DEFAULT NULL,
  `F1ALot` tinyint(1) DEFAULT NULL,
  `F1Cannot` tinyint(1) DEFAULT NULL,
  `F2None` tinyint(1) DEFAULT NULL,
  `F2ALittle` tinyint(1) DEFAULT NULL,
  `F2Some` tinyint(1) DEFAULT NULL,
  `F2ALot` tinyint(1) DEFAULT NULL,
  `F2Cannot` tinyint(1) DEFAULT NULL,
  `F3None` tinyint(1) DEFAULT NULL,
  `F3ALittle` tinyint(1) DEFAULT NULL,
  `F3Some` tinyint(1) DEFAULT NULL,
  `F3ALot` tinyint(1) DEFAULT NULL,
  `F3Cannot` tinyint(1) DEFAULT NULL,
  `F4None` tinyint(1) DEFAULT NULL,
  `F4ALittle` tinyint(1) DEFAULT NULL,
  `F4Some` tinyint(1) DEFAULT NULL,
  `F4ALot` tinyint(1) DEFAULT NULL,
  `F4Cannot` tinyint(1) DEFAULT NULL,
  `F5None` tinyint(1) DEFAULT NULL,
  `F5ALittle` tinyint(1) DEFAULT NULL,
  `F5Some` tinyint(1) DEFAULT NULL,
  `F5ALot` tinyint(1) DEFAULT NULL,
  `F5Cannot` tinyint(1) DEFAULT NULL,
  `F6None` tinyint(1) DEFAULT NULL,
  `F6ALittle` tinyint(1) DEFAULT NULL,
  `F6Some` tinyint(1) DEFAULT NULL,
  `F6ALot` tinyint(1) DEFAULT NULL,
  `F6Cannot` tinyint(1) DEFAULT NULL,
  `F7None` tinyint(1) DEFAULT NULL,
  `F7ALittle` tinyint(1) DEFAULT NULL,
  `F7Some` tinyint(1) DEFAULT NULL,
  `F7ALot` tinyint(1) DEFAULT NULL,
  `F7Cannot` tinyint(1) DEFAULT NULL,
  `F8None` tinyint(1) DEFAULT NULL,
  `F8ALittle` tinyint(1) DEFAULT NULL,
  `F8Some` tinyint(1) DEFAULT NULL,
  `F8ALot` tinyint(1) DEFAULT NULL,
  `F8Cannot` tinyint(1) DEFAULT NULL,
  `F9None` tinyint(1) DEFAULT NULL,
  `F9ALittle` tinyint(1) DEFAULT NULL,
  `F9Some` tinyint(1) DEFAULT NULL,
  `F9ALot` tinyint(1) DEFAULT NULL,
  `F9Cannot` tinyint(1) DEFAULT NULL,
  `F10None` tinyint(1) DEFAULT NULL,
  `F10ALittle` tinyint(1) DEFAULT NULL,
  `F10Some` tinyint(1) DEFAULT NULL,
  `F10ALot` tinyint(1) DEFAULT NULL,
  `F10Cannot` tinyint(1) DEFAULT NULL,
  `F11None` tinyint(1) DEFAULT NULL,
  `F11ALittle` tinyint(1) DEFAULT NULL,
  `F11Some` tinyint(1) DEFAULT NULL,
  `F11ALot` tinyint(1) DEFAULT NULL,
  `F11Cannot` tinyint(1) DEFAULT NULL,
  `F12None` tinyint(1) DEFAULT NULL,
  `F12ALittle` tinyint(1) DEFAULT NULL,
  `F12Some` tinyint(1) DEFAULT NULL,
  `F12ALot` tinyint(1) DEFAULT NULL,
  `F12Cannot` tinyint(1) DEFAULT NULL,
  `F13None` tinyint(1) DEFAULT NULL,
  `F13ALittle` tinyint(1) DEFAULT NULL,
  `F13Some` tinyint(1) DEFAULT NULL,
  `F13ALot` tinyint(1) DEFAULT NULL,
  `F13Cannot` tinyint(1) DEFAULT NULL,
  `F14None` tinyint(1) DEFAULT NULL,
  `F14ALittle` tinyint(1) DEFAULT NULL,
  `F14Some` tinyint(1) DEFAULT NULL,
  `F14ALot` tinyint(1) DEFAULT NULL,
  `F14Cannot` tinyint(1) DEFAULT NULL,
  `F15None` tinyint(1) DEFAULT NULL,
  `F15ALittle` tinyint(1) DEFAULT NULL,
  `F15Some` tinyint(1) DEFAULT NULL,
  `F15ALot` tinyint(1) DEFAULT NULL,
  `F15Cannot` tinyint(1) DEFAULT NULL,
  `F16None` tinyint(1) DEFAULT NULL,
  `F16ALittle` tinyint(1) DEFAULT NULL,
  `F16Some` tinyint(1) DEFAULT NULL,
  `F16ALot` tinyint(1) DEFAULT NULL,
  `F16Cannot` tinyint(1) DEFAULT NULL,
  `F17None` tinyint(1) DEFAULT NULL,
  `F17ALittle` tinyint(1) DEFAULT NULL,
  `F17Some` tinyint(1) DEFAULT NULL,
  `F17ALot` tinyint(1) DEFAULT NULL,
  `F17Cannot` tinyint(1) DEFAULT NULL,
  `F18None` tinyint(1) DEFAULT NULL,
  `F18ALittle` tinyint(1) DEFAULT NULL,
  `F18Some` tinyint(1) DEFAULT NULL,
  `F18ALot` tinyint(1) DEFAULT NULL,
  `F18Cannot` tinyint(1) DEFAULT NULL,
  `F19None` tinyint(1) DEFAULT NULL,
  `F19ALittle` tinyint(1) DEFAULT NULL,
  `F19Some` tinyint(1) DEFAULT NULL,
  `F19ALot` tinyint(1) DEFAULT NULL,
  `F19Cannot` tinyint(1) DEFAULT NULL,
  `F20None` tinyint(1) DEFAULT NULL,
  `F20ALittle` tinyint(1) DEFAULT NULL,
  `F20Some` tinyint(1) DEFAULT NULL,
  `F20ALot` tinyint(1) DEFAULT NULL,
  `F20Cannot` tinyint(1) DEFAULT NULL,
  `F21None` tinyint(1) DEFAULT NULL,
  `F21ALittle` tinyint(1) DEFAULT NULL,
  `F21Some` tinyint(1) DEFAULT NULL,
  `F21ALot` tinyint(1) DEFAULT NULL,
  `F21Cannot` tinyint(1) DEFAULT NULL,
  `F22None` tinyint(1) DEFAULT NULL,
  `F22ALittle` tinyint(1) DEFAULT NULL,
  `F22Some` tinyint(1) DEFAULT NULL,
  `F22ALot` tinyint(1) DEFAULT NULL,
  `F22Cannot` tinyint(1) DEFAULT NULL,
  `F23None` tinyint(1) DEFAULT NULL,
  `F23ALittle` tinyint(1) DEFAULT NULL,
  `F23Some` tinyint(1) DEFAULT NULL,
  `F23ALot` tinyint(1) DEFAULT NULL,
  `F23Cannot` tinyint(1) DEFAULT NULL,
  `F24None` tinyint(1) DEFAULT NULL,
  `F24ALittle` tinyint(1) DEFAULT NULL,
  `F24Some` tinyint(1) DEFAULT NULL,
  `F24ALot` tinyint(1) DEFAULT NULL,
  `F24Cannot` tinyint(1) DEFAULT NULL,
  `F25None` tinyint(1) DEFAULT NULL,
  `F25ALittle` tinyint(1) DEFAULT NULL,
  `F25Some` tinyint(1) DEFAULT NULL,
  `F25ALot` tinyint(1) DEFAULT NULL,
  `F25Cannot` tinyint(1) DEFAULT NULL,
  `F26None` tinyint(1) DEFAULT NULL,
  `F26ALittle` tinyint(1) DEFAULT NULL,
  `F26Some` tinyint(1) DEFAULT NULL,
  `F26ALot` tinyint(1) DEFAULT NULL,
  `F26Cannot` tinyint(1) DEFAULT NULL,
  `F27None` tinyint(1) DEFAULT NULL,
  `F27ALittle` tinyint(1) DEFAULT NULL,
  `F27Some` tinyint(1) DEFAULT NULL,
  `F27ALot` tinyint(1) DEFAULT NULL,
  `F27Cannot` tinyint(1) DEFAULT NULL,
  `F28None` tinyint(1) DEFAULT NULL,
  `F28ALittle` tinyint(1) DEFAULT NULL,
  `F28Some` tinyint(1) DEFAULT NULL,
  `F28ALot` tinyint(1) DEFAULT NULL,
  `F28Cannot` tinyint(1) DEFAULT NULL,
  `F29None` tinyint(1) DEFAULT NULL,
  `F29ALittle` tinyint(1) DEFAULT NULL,
  `F29Some` tinyint(1) DEFAULT NULL,
  `F29ALot` tinyint(1) DEFAULT NULL,
  `F29Cannot` tinyint(1) DEFAULT NULL,
  `F30None` tinyint(1) DEFAULT NULL,
  `F30ALittle` tinyint(1) DEFAULT NULL,
  `F30Some` tinyint(1) DEFAULT NULL,
  `F30ALot` tinyint(1) DEFAULT NULL,
  `F30Cannot` tinyint(1) DEFAULT NULL,
  `F31None` tinyint(1) DEFAULT NULL,
  `F31ALittle` tinyint(1) DEFAULT NULL,
  `F31Some` tinyint(1) DEFAULT NULL,
  `F31ALot` tinyint(1) DEFAULT NULL,
  `F31Cannot` tinyint(1) DEFAULT NULL,
  `F32None` tinyint(1) DEFAULT NULL,
  `F32ALittle` tinyint(1) DEFAULT NULL,
  `F32Some` tinyint(1) DEFAULT NULL,
  `F32ALot` tinyint(1) DEFAULT NULL,
  `F32Cannot` tinyint(1) DEFAULT NULL,
  `FD7None` tinyint(1) DEFAULT NULL,
  `FD7ALittle` tinyint(1) DEFAULT NULL,
  `FD7Some` tinyint(1) DEFAULT NULL,
  `FD7ALot` tinyint(1) DEFAULT NULL,
  `FD7Cannot` tinyint(1) DEFAULT NULL,
  `FD8None` tinyint(1) DEFAULT NULL,
  `FD8ALittle` tinyint(1) DEFAULT NULL,
  `FD8Some` tinyint(1) DEFAULT NULL,
  `FD8ALot` tinyint(1) DEFAULT NULL,
  `FD8Cannot` tinyint(1) DEFAULT NULL,
  `FD14None` tinyint(1) DEFAULT NULL,
  `FD14ALittle` tinyint(1) DEFAULT NULL,
  `FD14Some` tinyint(1) DEFAULT NULL,
  `FD14ALot` tinyint(1) DEFAULT NULL,
  `FD14Cannot` tinyint(1) DEFAULT NULL,
  `FD15None` tinyint(1) DEFAULT NULL,
  `FD15ALittle` tinyint(1) DEFAULT NULL,
  `FD15Some` tinyint(1) DEFAULT NULL,
  `FD15ALot` tinyint(1) DEFAULT NULL,
  `FD15Cannot` tinyint(1) DEFAULT NULL,
  `FD26None` tinyint(1) DEFAULT NULL,
  `FD26ALittle` tinyint(1) DEFAULT NULL,
  `FD26Some` tinyint(1) DEFAULT NULL,
  `FD26ALot` tinyint(1) DEFAULT NULL,
  `FD26Cannot` tinyint(1) DEFAULT NULL,
  `FD29None` tinyint(1) DEFAULT NULL,
  `FD29ALittle` tinyint(1) DEFAULT NULL,
  `FD29Some` tinyint(1) DEFAULT NULL,
  `FD29ALot` tinyint(1) DEFAULT NULL,
  `FD29Cannot` tinyint(1) DEFAULT NULL,
  `FD30None` tinyint(1) DEFAULT NULL,
  `FD30ALittle` tinyint(1) DEFAULT NULL,
  `FD30Some` tinyint(1) DEFAULT NULL,
  `FD30ALot` tinyint(1) DEFAULT NULL,
  `FD30Cannot` tinyint(1) DEFAULT NULL,
  `FD32None` tinyint(1) DEFAULT NULL,
  `FD32ALittle` tinyint(1) DEFAULT NULL,
  `FD32Some` tinyint(1) DEFAULT NULL,
  `FD32ALot` tinyint(1) DEFAULT NULL,
  `FD32Cannot` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formMMSE`
--


CREATE TABLE `formMMSE` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `pName` varchar(50) DEFAULT NULL,
  `age` char(3) DEFAULT NULL,
  `sex` char(1) DEFAULT NULL,
  `formDate` date DEFAULT NULL,
  `diagnosis` text,
  `meds` text,
  `o_date` char(1) DEFAULT NULL,
  `o_place` char(1) DEFAULT NULL,
  `r_objects` char(1) DEFAULT NULL,
  `a_serial` char(1) DEFAULT NULL,
  `re_name` char(1) DEFAULT NULL,
  `l_name` char(1) DEFAULT NULL,
  `l_repeat` char(1) DEFAULT NULL,
  `l_follow` char(1) DEFAULT NULL,
  `l_read` char(1) DEFAULT NULL,
  `l_write` char(1) DEFAULT NULL,
  `l_copy` char(1) DEFAULT NULL,
  `total` char(2) DEFAULT NULL,
  `lc_alert` tinyint(1) DEFAULT NULL,
  `lc_drowsy` tinyint(1) DEFAULT NULL,
  `lc_stupor` tinyint(1) DEFAULT NULL,
  `lc_coma` tinyint(1) DEFAULT NULL,
  `i_dementia` tinyint(1) DEFAULT NULL,
  `i_depression` tinyint(1) DEFAULT NULL,
  `i_normal` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formMentalHealth`
--


CREATE TABLE `formMentalHealth` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `c_lastVisited` varchar(15) DEFAULT NULL,
  `c_pName` varchar(60) DEFAULT NULL,
  `c_address` varchar(80) DEFAULT NULL,
  `c_birthDate` date DEFAULT NULL,
  `c_sex` varchar(6) DEFAULT NULL,
  `c_homePhone` varchar(10) DEFAULT NULL,
  `c_referralDate` date DEFAULT NULL,
  `c_referredBy` varchar(30) DEFAULT NULL,
  `r_rps1` char(2) DEFAULT NULL,
  `r_rps2` char(2) DEFAULT NULL,
  `r_rps3` char(2) DEFAULT NULL,
  `r_rpsOther` varchar(30) DEFAULT NULL,
  `r_rpi1` char(2) DEFAULT NULL,
  `r_rpi2` char(2) DEFAULT NULL,
  `r_rpi3` char(2) DEFAULT NULL,
  `r_rpiOther` varchar(30) DEFAULT NULL,
  `r_rmpi1` char(2) DEFAULT NULL,
  `r_rmpi2` char(2) DEFAULT NULL,
  `r_rmpi3` char(2) DEFAULT NULL,
  `r_rmpiOther` varchar(30) DEFAULT NULL,
  `r_ir1` char(2) DEFAULT NULL,
  `r_ir2` char(2) DEFAULT NULL,
  `r_ir3` char(2) DEFAULT NULL,
  `r_irOther` varchar(30) DEFAULT NULL,
  `r_arm1` char(2) DEFAULT NULL,
  `r_arm2` char(2) DEFAULT NULL,
  `r_arm3` char(2) DEFAULT NULL,
  `r_armOther` varchar(30) DEFAULT NULL,
  `r_refComments` text,
  `a_specialist` varchar(30) DEFAULT NULL,
  `a_aps1` char(2) DEFAULT NULL,
  `a_aps2` char(2) DEFAULT NULL,
  `a_aps3` char(2) DEFAULT NULL,
  `a_apsOther` varchar(30) DEFAULT NULL,
  `a_api1` char(2) DEFAULT NULL,
  `a_api2` char(2) DEFAULT NULL,
  `a_api3` char(2) DEFAULT NULL,
  `a_apiOther` varchar(30) DEFAULT NULL,
  `a_ampi1` char(2) DEFAULT NULL,
  `a_ampi2` char(2) DEFAULT NULL,
  `a_ampi3` char(2) DEFAULT NULL,
  `a_ampiOther` varchar(50) DEFAULT NULL,
  `a_assComments` text,
  `a_tp1` char(2) DEFAULT NULL,
  `a_tp2` char(2) DEFAULT NULL,
  `a_tp3` char(2) DEFAULT NULL,
  `a_tpOther` varchar(30) DEFAULT NULL,
  `o_specialist` varchar(30) DEFAULT NULL,
  `o_numVisits` varchar(5) DEFAULT NULL,
  `o_formDate` date DEFAULT NULL,
  `o_sp1` char(2) DEFAULT NULL,
  `o_sp2` char(2) DEFAULT NULL,
  `o_sp3` char(2) DEFAULT NULL,
  `o_spOther` varchar(30) DEFAULT NULL,
  `o_pe1` char(2) DEFAULT NULL,
  `o_pe2` char(2) DEFAULT NULL,
  `o_pe3` char(2) DEFAULT NULL,
  `o_peOther` varchar(30) DEFAULT NULL,
  `o_d1` char(2) DEFAULT NULL,
  `o_d2` char(2) DEFAULT NULL,
  `o_d3` char(2) DEFAULT NULL,
  `o_dOther` varchar(30) DEFAULT NULL,
  `o_pns1` char(2) DEFAULT NULL,
  `o_pns2` char(2) DEFAULT NULL,
  `o_pns3` char(2) DEFAULT NULL,
  `o_pnsOther` varchar(30) DEFAULT NULL,
  `o_outComments` text,
  `a_formDate` date DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formNoShowPolicy`
--


CREATE TABLE `formNoShowPolicy` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` int(10) DEFAULT NULL,
  `demographic_no` int(10) NOT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `formVersion` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formONAREnhancedRecord`
--


CREATE TABLE `formONAREnhancedRecord` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `episodeId` int(10) DEFAULT NULL,
  `sent_to_born` tinyint(1) DEFAULT '0',
  `obxhx_num` varchar(10) DEFAULT '0',
  `rf_num` varchar(10) DEFAULT '0',
  `sv_num` varchar(10) DEFAULT '0',
  `us_num` varchar(10) DEFAULT '0',
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` varchar(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `c_lastName` varchar(80) DEFAULT NULL,
  `c_firstName` varchar(80) DEFAULT NULL,
  `c_address` varchar(80) DEFAULT NULL,
  `c_apt` varchar(20) DEFAULT NULL,
  `c_city` varchar(80) DEFAULT NULL,
  `c_province` varchar(80) DEFAULT NULL,
  `c_postal` varchar(10) DEFAULT NULL,
  `c_partnerLastName` varchar(80) DEFAULT NULL,
  `c_partnerFirstName` varchar(80) DEFAULT NULL,
  `pg1_homePhone` varchar(20) DEFAULT NULL,
  `pg1_workPhone` varchar(20) DEFAULT NULL,
  `pg1_language` varchar(25) DEFAULT NULL,
  `pg1_partnerOccupation` varchar(25) DEFAULT NULL,
  `c_partnerOccupationOther` varchar(255) DEFAULT NULL,
  `pg1_partnerEduLevel` varchar(25) DEFAULT NULL,
  `pg1_partnerAge` varchar(5) DEFAULT NULL,
  `pg1_dateOfBirth` date DEFAULT NULL,
  `pg1_age` varchar(10) DEFAULT NULL,
  `pg1_occupation` varchar(25) DEFAULT NULL,
  `pg1_occupationOther` varchar(255) DEFAULT NULL,
  `pg1_eduLevel` varchar(25) DEFAULT NULL,
  `pg1_ethnicBgMother` varchar(200) DEFAULT NULL,
  `pg1_ethnicBgFather` varchar(200) DEFAULT NULL,
  `c_hin` varchar(20) DEFAULT NULL,
  `c_hinType` varchar(20) DEFAULT NULL,
  `c_fileNo` varchar(20) DEFAULT NULL,
  `pg1_maritalStatus` varchar(20) DEFAULT NULL,
  `pg1_msSingle` tinyint(1) DEFAULT NULL,
  `pg1_msCommonLaw` tinyint(1) DEFAULT NULL,
  `pg1_msMarried` tinyint(1) DEFAULT NULL,
  `pg1_baObs` tinyint(1) DEFAULT NULL,
  `pg1_baFP` tinyint(1) DEFAULT NULL,
  `pg1_baMidwife` tinyint(1) DEFAULT NULL,
  `c_ba` varchar(25) DEFAULT NULL,
  `pg1_ncPed` tinyint(1) DEFAULT NULL,
  `pg1_ncFP` tinyint(1) DEFAULT NULL,
  `pg1_ncMidwife` tinyint(1) DEFAULT NULL,
  `c_nc` varchar(25) DEFAULT NULL,
  `c_famPhys` varchar(80) DEFAULT NULL,
  `c_allergies` text,
  `c_meds` text,
  `pg1_menLMP` date DEFAULT NULL,
  `pg1_psCertY` tinyint(1) DEFAULT NULL,
  `pg1_psCertN` tinyint(1) DEFAULT NULL,
  `pg1_menCycle` varchar(7) DEFAULT NULL,
  `pg1_menReg` tinyint(1) DEFAULT NULL,
  `pg1_menRegN` tinyint(1) DEFAULT NULL,
  `pg1_contracep` varchar(25) DEFAULT NULL,
  `pg1_lastUsed` date DEFAULT NULL,
  `pg1_menEDB` date DEFAULT NULL,
  `c_finalEDB` date DEFAULT NULL,
  `pg1_edbByDate` tinyint(1) DEFAULT NULL,
  `pg1_edbByT1` tinyint(1) DEFAULT NULL,
  `pg1_edbByT2` tinyint(1) DEFAULT NULL,
  `pg1_edbByART` tinyint(1) DEFAULT NULL,
  `c_gravida` varchar(3) DEFAULT NULL,
  `c_term` varchar(3) DEFAULT NULL,
  `c_prem` varchar(3) DEFAULT NULL,
  `c_abort` varchar(3) DEFAULT NULL,
  `c_living` varchar(3) DEFAULT NULL,
  `pg1_year1` varchar(10) DEFAULT NULL,
  `pg1_sex1` char(1) DEFAULT NULL,
  `pg1_oh_gest1` varchar(5) DEFAULT NULL,
  `pg1_weight1` varchar(6) DEFAULT NULL,
  `pg1_length1` varchar(6) DEFAULT NULL,
  `pg1_place1` varchar(20) DEFAULT NULL,
  `pg1_svb1` tinyint(1) DEFAULT NULL,
  `pg1_cs1` tinyint(1) DEFAULT NULL,
  `pg1_ass1` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments1` varchar(80) DEFAULT NULL,
  `pg1_year2` varchar(10) DEFAULT NULL,
  `pg1_sex2` char(1) DEFAULT NULL,
  `pg1_oh_gest2` varchar(5) DEFAULT NULL,
  `pg1_weight2` varchar(6) DEFAULT NULL,
  `pg1_length2` varchar(6) DEFAULT NULL,
  `pg1_place2` varchar(20) DEFAULT NULL,
  `pg1_svb2` tinyint(1) DEFAULT NULL,
  `pg1_cs2` tinyint(1) DEFAULT NULL,
  `pg1_ass2` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments2` varchar(80) DEFAULT NULL,
  `pg1_year3` varchar(10) DEFAULT NULL,
  `pg1_sex3` char(1) DEFAULT NULL,
  `pg1_oh_gest3` varchar(5) DEFAULT NULL,
  `pg1_weight3` varchar(6) DEFAULT NULL,
  `pg1_length3` varchar(6) DEFAULT NULL,
  `pg1_place3` varchar(20) DEFAULT NULL,
  `pg1_svb3` tinyint(1) DEFAULT NULL,
  `pg1_cs3` tinyint(1) DEFAULT NULL,
  `pg1_ass3` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments3` varchar(80) DEFAULT NULL,
  `pg1_year4` varchar(10) DEFAULT NULL,
  `pg1_sex4` char(1) DEFAULT NULL,
  `pg1_oh_gest4` varchar(5) DEFAULT NULL,
  `pg1_weight4` varchar(6) DEFAULT NULL,
  `pg1_length4` varchar(6) DEFAULT NULL,
  `pg1_place4` varchar(20) DEFAULT NULL,
  `pg1_svb4` tinyint(1) DEFAULT NULL,
  `pg1_cs4` tinyint(1) DEFAULT NULL,
  `pg1_ass4` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments4` varchar(80) DEFAULT NULL,
  `pg1_year5` varchar(10) DEFAULT NULL,
  `pg1_sex5` char(1) DEFAULT NULL,
  `pg1_oh_gest5` varchar(5) DEFAULT NULL,
  `pg1_weight5` varchar(6) DEFAULT NULL,
  `pg1_length5` varchar(6) DEFAULT NULL,
  `pg1_place5` varchar(20) DEFAULT NULL,
  `pg1_svb5` tinyint(1) DEFAULT NULL,
  `pg1_cs5` tinyint(1) DEFAULT NULL,
  `pg1_ass5` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments5` varchar(80) DEFAULT NULL,
  `pg1_year6` varchar(10) DEFAULT NULL,
  `pg1_sex6` char(1) DEFAULT NULL,
  `pg1_oh_gest6` varchar(5) DEFAULT NULL,
  `pg1_weight6` varchar(6) DEFAULT NULL,
  `pg1_length6` varchar(6) DEFAULT NULL,
  `pg1_place6` varchar(20) DEFAULT NULL,
  `pg1_svb6` tinyint(1) DEFAULT NULL,
  `pg1_cs6` tinyint(1) DEFAULT NULL,
  `pg1_ass6` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments6` varchar(80) DEFAULT NULL,
  `pg1_year7` varchar(10) DEFAULT NULL,
  `pg1_sex7` char(1) DEFAULT NULL,
  `pg1_oh_gest7` varchar(5) DEFAULT NULL,
  `pg1_weight7` varchar(6) DEFAULT NULL,
  `pg1_length7` varchar(6) DEFAULT NULL,
  `pg1_place7` varchar(20) DEFAULT NULL,
  `pg1_svb7` tinyint(1) DEFAULT NULL,
  `pg1_cs7` tinyint(1) DEFAULT NULL,
  `pg1_ass7` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments7` varchar(80) DEFAULT NULL,
  `pg1_year8` varchar(10) DEFAULT NULL,
  `pg1_sex8` char(1) DEFAULT NULL,
  `pg1_oh_gest8` varchar(5) DEFAULT NULL,
  `pg1_weight8` varchar(6) DEFAULT NULL,
  `pg1_length8` varchar(6) DEFAULT NULL,
  `pg1_place8` varchar(20) DEFAULT NULL,
  `pg1_svb8` tinyint(1) DEFAULT NULL,
  `pg1_cs8` tinyint(1) DEFAULT NULL,
  `pg1_ass8` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments8` varchar(80) DEFAULT NULL,
  `pg1_year9` varchar(10) DEFAULT NULL,
  `pg1_sex9` char(1) DEFAULT NULL,
  `pg1_oh_gest9` varchar(5) DEFAULT NULL,
  `pg1_weight9` varchar(6) DEFAULT NULL,
  `pg1_length9` varchar(6) DEFAULT NULL,
  `pg1_place9` varchar(20) DEFAULT NULL,
  `pg1_svb9` tinyint(1) DEFAULT NULL,
  `pg1_cs9` tinyint(1) DEFAULT NULL,
  `pg1_ass9` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments9` varchar(80) DEFAULT NULL,
  `pg1_year10` varchar(10) DEFAULT NULL,
  `pg1_sex10` char(1) DEFAULT NULL,
  `pg1_oh_gest10` varchar(5) DEFAULT NULL,
  `pg1_weight10` varchar(6) DEFAULT NULL,
  `pg1_length10` varchar(6) DEFAULT NULL,
  `pg1_place10` varchar(20) DEFAULT NULL,
  `pg1_svb10` tinyint(1) DEFAULT NULL,
  `pg1_cs10` tinyint(1) DEFAULT NULL,
  `pg1_ass10` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments10` varchar(80) DEFAULT NULL,
  `pg1_year11` varchar(10) DEFAULT NULL,
  `pg1_sex11` char(1) DEFAULT NULL,
  `pg1_oh_gest11` varchar(5) DEFAULT NULL,
  `pg1_weight11` varchar(6) DEFAULT NULL,
  `pg1_length11` varchar(6) DEFAULT NULL,
  `pg1_place11` varchar(20) DEFAULT NULL,
  `pg1_svb11` tinyint(1) DEFAULT NULL,
  `pg1_cs11` tinyint(1) DEFAULT NULL,
  `pg1_ass11` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments11` varchar(80) DEFAULT NULL,
  `pg1_year12` varchar(10) DEFAULT NULL,
  `pg1_sex12` char(1) DEFAULT NULL,
  `pg1_oh_gest12` varchar(5) DEFAULT NULL,
  `pg1_weight12` varchar(6) DEFAULT NULL,
  `pg1_length12` varchar(6) DEFAULT NULL,
  `pg1_place12` varchar(20) DEFAULT NULL,
  `pg1_svb12` tinyint(1) DEFAULT NULL,
  `pg1_cs12` tinyint(1) DEFAULT NULL,
  `pg1_ass12` tinyint(1) DEFAULT NULL,
  `pg1_oh_comments12` varchar(80) DEFAULT NULL,
  `pg1_cp1` tinyint(1) DEFAULT NULL,
  `pg1_cp1N` tinyint(1) DEFAULT NULL,
  `pg1_cp2` tinyint(1) DEFAULT NULL,
  `pg1_cp2N` tinyint(1) DEFAULT NULL,
  `pg1_box3` varchar(10) DEFAULT NULL,
  `pg1_cp3` tinyint(1) DEFAULT NULL,
  `pg1_cp3N` tinyint(1) DEFAULT NULL,
  `pg1_cp4` tinyint(1) DEFAULT NULL,
  `pg1_cp4N` tinyint(1) DEFAULT NULL,
  `pg1_cp8` tinyint(1) DEFAULT NULL,
  `pg1_cp8N` tinyint(1) DEFAULT NULL,
  `pg1_naDiet` tinyint(1) DEFAULT NULL,
  `pg1_naDietN` tinyint(1) DEFAULT NULL,
  `pg1_naMilk` tinyint(1) DEFAULT NULL,
  `pg1_naMilkN` tinyint(1) DEFAULT NULL,
  `pg1_naFolic` tinyint(1) DEFAULT NULL,
  `pg1_naFolicN` tinyint(1) DEFAULT NULL,
  `pg1_yes9` tinyint(1) DEFAULT NULL,
  `pg1_no9` tinyint(1) DEFAULT NULL,
  `pg1_yes10` tinyint(1) DEFAULT NULL,
  `pg1_no10` tinyint(1) DEFAULT NULL,
  `pg1_yes12` tinyint(1) DEFAULT NULL,
  `pg1_no12` tinyint(1) DEFAULT NULL,
  `pg1_yes13` tinyint(1) DEFAULT NULL,
  `pg1_no13` tinyint(1) DEFAULT NULL,
  `pg1_yes14` tinyint(1) DEFAULT NULL,
  `pg1_no14` tinyint(1) DEFAULT NULL,
  `pg1_yes17` tinyint(1) DEFAULT NULL,
  `pg1_no17` tinyint(1) DEFAULT NULL,
  `pg1_yes22` tinyint(1) DEFAULT NULL,
  `pg1_no22` tinyint(1) DEFAULT NULL,
  `pg1_yes20` tinyint(1) DEFAULT NULL,
  `pg1_no20` tinyint(1) DEFAULT NULL,
  `pg1_bloodTranY` tinyint(1) DEFAULT NULL,
  `pg1_bloodTranN` tinyint(1) DEFAULT NULL,
  `pg1_yes21` tinyint(1) DEFAULT NULL,
  `pg1_no21` tinyint(1) DEFAULT NULL,
  `pg1_yes24` tinyint(1) DEFAULT NULL,
  `pg1_no24` tinyint(1) DEFAULT NULL,
  `pg1_yes15` tinyint(1) DEFAULT NULL,
  `pg1_no15` tinyint(1) DEFAULT NULL,
  `pg1_box25` varchar(25) DEFAULT NULL,
  `pg1_yes25` tinyint(1) DEFAULT NULL,
  `pg1_no25` tinyint(1) DEFAULT NULL,
  `pg1_yes27` tinyint(1) DEFAULT NULL,
  `pg1_no27` tinyint(1) DEFAULT NULL,
  `pg1_yes31` tinyint(1) DEFAULT NULL,
  `pg1_no31` tinyint(1) DEFAULT NULL,
  `pg1_yes32` tinyint(1) DEFAULT NULL,
  `pg1_no32` tinyint(1) DEFAULT NULL,
  `pg1_yes34` tinyint(1) DEFAULT NULL,
  `pg1_no34` tinyint(1) DEFAULT NULL,
  `pg1_yes35` tinyint(1) DEFAULT NULL,
  `pg1_no35` tinyint(1) DEFAULT NULL,
  `pg1_idt40` tinyint(1) DEFAULT NULL,
  `pg1_idt40N` tinyint(1) DEFAULT NULL,
  `pg1_idt38` tinyint(1) DEFAULT NULL,
  `pg1_idt38N` tinyint(1) DEFAULT NULL,
  `pg1_idt42` tinyint(1) DEFAULT NULL,
  `pg1_idt42N` tinyint(1) DEFAULT NULL,
  `pg1_infectDisOther` varchar(20) DEFAULT NULL,
  `pg1_infectDisOtherY` tinyint(1) DEFAULT NULL,
  `pg1_infectDisOtherN` tinyint(1) DEFAULT NULL,
  `pg1_pdt43` tinyint(1) DEFAULT NULL,
  `pg1_pdt43N` tinyint(1) DEFAULT NULL,
  `pg1_pdt44` tinyint(1) DEFAULT NULL,
  `pg1_pdt44N` tinyint(1) DEFAULT NULL,
  `pg1_pdt45` tinyint(1) DEFAULT NULL,
  `pg1_pdt45N` tinyint(1) DEFAULT NULL,
  `pg1_pdt46` tinyint(1) DEFAULT NULL,
  `pg1_pdt46N` tinyint(1) DEFAULT NULL,
  `pg1_pdt47` tinyint(1) DEFAULT NULL,
  `pg1_pdt47N` tinyint(1) DEFAULT NULL,
  `pg1_pdt48` tinyint(1) DEFAULT NULL,
  `pg1_pdt48N` tinyint(1) DEFAULT NULL,
  `pg1_reliCultY` tinyint(1) DEFAULT NULL,
  `pg1_reliCultN` tinyint(1) DEFAULT NULL,
  `pg1_fhRiskY` tinyint(1) DEFAULT NULL,
  `pg1_fhRiskN` tinyint(1) DEFAULT NULL,
  `pg1_ht` varchar(6) DEFAULT NULL,
  `pg1_wt` varchar(6) DEFAULT NULL,
  `c_bmi` varchar(6) DEFAULT NULL,
  `pg1_BP` varchar(10) DEFAULT NULL,
  `pg1_thyroid` tinyint(1) DEFAULT NULL,
  `pg1_thyroidA` tinyint(1) DEFAULT NULL,
  `pg1_chest` tinyint(1) DEFAULT NULL,
  `pg1_chestA` tinyint(1) DEFAULT NULL,
  `pg1_breasts` tinyint(1) DEFAULT NULL,
  `pg1_breastsA` tinyint(1) DEFAULT NULL,
  `pg1_cardio` tinyint(1) DEFAULT NULL,
  `pg1_cardioA` tinyint(1) DEFAULT NULL,
  `pg1_abdomen` tinyint(1) DEFAULT NULL,
  `pg1_abdomenA` tinyint(1) DEFAULT NULL,
  `pg1_vari` tinyint(1) DEFAULT NULL,
  `pg1_variA` tinyint(1) DEFAULT NULL,
  `pg1_extGen` tinyint(1) DEFAULT NULL,
  `pg1_extGenA` tinyint(1) DEFAULT NULL,
  `pg1_cervix` tinyint(1) DEFAULT NULL,
  `pg1_cervixA` tinyint(1) DEFAULT NULL,
  `pg1_uterus` tinyint(1) DEFAULT NULL,
  `pg1_uterusA` tinyint(1) DEFAULT NULL,
  `pg1_uterusBox` varchar(3) DEFAULT NULL,
  `pg1_adnexa` tinyint(1) DEFAULT NULL,
  `pg1_adnexaA` tinyint(1) DEFAULT NULL,
  `pg1_pExOtherDesc` varchar(20) DEFAULT NULL,
  `pg1_pExOther` tinyint(1) DEFAULT NULL,
  `pg1_pExOtherA` tinyint(1) DEFAULT NULL,
  `pg1_labHb` varchar(20) DEFAULT NULL,
  `pg1_labHIV` varchar(20) DEFAULT NULL,
  `pg1_labMCV` varchar(20) DEFAULT NULL,
  `pg1_labHIVCounsel` tinyint(1) DEFAULT NULL,
  `pg1_labABO` varchar(20) DEFAULT NULL,
  `pg1_labLastPapDate` varchar(10) DEFAULT NULL,
  `pg1_labLastPap` varchar(20) DEFAULT NULL,
  `pg1_labCustom1Label` varchar(40) DEFAULT NULL,
  `pg1_labCustom1Result` varchar(40) DEFAULT NULL,
  `pg1_labCustom2Label` varchar(40) DEFAULT NULL,
  `pg1_labCustom2Result` varchar(40) DEFAULT NULL,
  `pg1_labCustom3Label` varchar(40) DEFAULT NULL,
  `pg1_labCustom3Result` varchar(40) DEFAULT NULL,
  `pg1_labCustom4Label` varchar(40) DEFAULT NULL,
  `pg1_labCustom4Result` varchar(40) DEFAULT NULL,
  `pg1_labRh` varchar(20) DEFAULT NULL,
  `pg1_labAntiScr` varchar(20) DEFAULT NULL,
  `pg1_labGC` varchar(20) DEFAULT NULL,
  `pg1_labChlamydia` varchar(20) DEFAULT NULL,
  `pg1_labRubella` varchar(20) DEFAULT NULL,
  `pg1_labUrine` varchar(20) DEFAULT NULL,
  `pg1_labHBsAg` varchar(20) DEFAULT NULL,
  `pg1_labVDRL` varchar(20) DEFAULT NULL,
  `pg1_labSickle` varchar(20) DEFAULT NULL,
  `pg1_geneticA` varchar(20) DEFAULT NULL,
  `pg1_geneticB` varchar(20) DEFAULT NULL,
  `pg1_geneticC` varchar(20) DEFAULT NULL,
  `pg1_geneticD` varchar(20) DEFAULT NULL,
  `pg1_geneticD1` tinyint(1) DEFAULT NULL,
  `pg1_geneticD2` tinyint(1) DEFAULT NULL,
  `pg1_commentsAR1` text,
  `pg1_comments2AR1` text,
  `pg1_signature` varchar(50) DEFAULT NULL,
  `pg1_formDate` date DEFAULT NULL,
  `pg1_signature2` varchar(50) DEFAULT NULL,
  `pg1_formDate2` date DEFAULT NULL,
  `c_riskFactors1` varchar(50) DEFAULT NULL,
  `c_planManage1` varchar(100) DEFAULT NULL,
  `c_riskFactors2` varchar(50) DEFAULT NULL,
  `c_planManage2` varchar(100) DEFAULT NULL,
  `c_riskFactors3` varchar(50) DEFAULT NULL,
  `c_planManage3` varchar(100) DEFAULT NULL,
  `c_riskFactors4` varchar(50) DEFAULT NULL,
  `c_planManage4` varchar(100) DEFAULT NULL,
  `c_riskFactors5` varchar(50) DEFAULT NULL,
  `c_planManage5` varchar(100) DEFAULT NULL,
  `c_riskFactors6` varchar(50) DEFAULT NULL,
  `c_planManage6` varchar(100) DEFAULT NULL,
  `c_riskFactors7` varchar(50) DEFAULT NULL,
  `c_planManage7` varchar(100) DEFAULT NULL,
  `c_riskFactors8` varchar(50) DEFAULT NULL,
  `c_planManage8` varchar(100) DEFAULT NULL,
  `c_riskFactors9` varchar(50) DEFAULT NULL,
  `c_planManage9` varchar(100) DEFAULT NULL,
  `c_riskFactors10` varchar(50) DEFAULT NULL,
  `c_planManage10` varchar(100) DEFAULT NULL,
  `c_riskFactors11` varchar(50) DEFAULT NULL,
  `c_planManage11` varchar(100) DEFAULT NULL,
  `c_riskFactors12` varchar(50) DEFAULT NULL,
  `c_planManage12` varchar(100) DEFAULT NULL,
  `c_riskFactors13` varchar(50) DEFAULT NULL,
  `c_planManage13` varchar(100) DEFAULT NULL,
  `c_riskFactors14` varchar(50) DEFAULT NULL,
  `c_planManage14` varchar(100) DEFAULT NULL,
  `c_riskFactors15` varchar(50) DEFAULT NULL,
  `c_planManage15` varchar(100) DEFAULT NULL,
  `c_riskFactors16` varchar(50) DEFAULT NULL,
  `c_planManage16` varchar(100) DEFAULT NULL,
  `c_riskFactors17` varchar(50) DEFAULT NULL,
  `c_planManage17` varchar(100) DEFAULT NULL,
  `c_riskFactors18` varchar(50) DEFAULT NULL,
  `c_planManage18` varchar(100) DEFAULT NULL,
  `c_riskFactors19` varchar(50) DEFAULT NULL,
  `c_planManage19` varchar(100) DEFAULT NULL,
  `c_riskFactors20` varchar(50) DEFAULT NULL,
  `c_planManage20` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formONAREnhancedRecordExt1`
--


CREATE TABLE `formONAREnhancedRecordExt1` (
  `ID` int(10) NOT NULL,
  `ar2_rhNeg` tinyint(1) DEFAULT NULL,
  `ar2_rhIG` varchar(10) DEFAULT NULL,
  `ar2_rubella` tinyint(1) DEFAULT NULL,
  `ar2_hepBIG` tinyint(1) DEFAULT NULL,
  `ar2_hepBVac` tinyint(1) DEFAULT NULL,
  `pg2_date1` date DEFAULT NULL,
  `pg2_gest1` varchar(6) DEFAULT NULL,
  `pg2_wt1` varchar(6) DEFAULT NULL,
  `pg2_BP1` varchar(8) DEFAULT NULL,
  `pg2_urinePr1` char(3) DEFAULT NULL,
  `pg2_urineGl1` char(3) DEFAULT NULL,
  `pg2_ht1` varchar(6) DEFAULT NULL,
  `pg2_presn1` varchar(6) DEFAULT NULL,
  `pg2_FHR1` varchar(6) DEFAULT NULL,
  `pg2_comments1` varchar(80) DEFAULT NULL,
  `pg2_date2` date DEFAULT NULL,
  `pg2_gest2` varchar(6) DEFAULT NULL,
  `pg2_ht2` varchar(6) DEFAULT NULL,
  `pg2_wt2` varchar(6) DEFAULT NULL,
  `pg2_presn2` varchar(6) DEFAULT NULL,
  `pg2_FHR2` varchar(6) DEFAULT NULL,
  `pg2_urinePr2` char(3) DEFAULT NULL,
  `pg2_urineGl2` char(3) DEFAULT NULL,
  `pg2_BP2` varchar(8) DEFAULT NULL,
  `pg2_comments2` varchar(80) DEFAULT NULL,
  `pg2_date3` date DEFAULT NULL,
  `pg2_gest3` varchar(6) DEFAULT NULL,
  `pg2_ht3` varchar(6) DEFAULT NULL,
  `pg2_wt3` varchar(6) DEFAULT NULL,
  `pg2_presn3` varchar(6) DEFAULT NULL,
  `pg2_FHR3` varchar(6) DEFAULT NULL,
  `pg2_urinePr3` char(3) DEFAULT NULL,
  `pg2_urineGl3` char(3) DEFAULT NULL,
  `pg2_BP3` varchar(8) DEFAULT NULL,
  `pg2_comments3` varchar(80) DEFAULT NULL,
  `pg2_date4` date DEFAULT NULL,
  `pg2_gest4` varchar(6) DEFAULT NULL,
  `pg2_ht4` varchar(6) DEFAULT NULL,
  `pg2_wt4` varchar(6) DEFAULT NULL,
  `pg2_presn4` varchar(6) DEFAULT NULL,
  `pg2_FHR4` varchar(6) DEFAULT NULL,
  `pg2_urinePr4` char(3) DEFAULT NULL,
  `pg2_urineGl4` char(3) DEFAULT NULL,
  `pg2_BP4` varchar(8) DEFAULT NULL,
  `pg2_comments4` varchar(80) DEFAULT NULL,
  `pg2_date5` date DEFAULT NULL,
  `pg2_gest5` varchar(6) DEFAULT NULL,
  `pg2_ht5` varchar(6) DEFAULT NULL,
  `pg2_wt5` varchar(6) DEFAULT NULL,
  `pg2_presn5` varchar(6) DEFAULT NULL,
  `pg2_FHR5` varchar(6) DEFAULT NULL,
  `pg2_urinePr5` char(3) DEFAULT NULL,
  `pg2_urineGl5` char(3) DEFAULT NULL,
  `pg2_BP5` varchar(8) DEFAULT NULL,
  `pg2_comments5` varchar(80) DEFAULT NULL,
  `pg2_date6` date DEFAULT NULL,
  `pg2_gest6` varchar(6) DEFAULT NULL,
  `pg2_ht6` varchar(6) DEFAULT NULL,
  `pg2_wt6` varchar(6) DEFAULT NULL,
  `pg2_presn6` varchar(6) DEFAULT NULL,
  `pg2_FHR6` varchar(6) DEFAULT NULL,
  `pg2_urinePr6` char(3) DEFAULT NULL,
  `pg2_urineGl6` char(3) DEFAULT NULL,
  `pg2_BP6` varchar(8) DEFAULT NULL,
  `pg2_comments6` varchar(80) DEFAULT NULL,
  `pg2_date7` date DEFAULT NULL,
  `pg2_gest7` varchar(6) DEFAULT NULL,
  `pg2_ht7` varchar(6) DEFAULT NULL,
  `pg2_wt7` varchar(6) DEFAULT NULL,
  `pg2_presn7` varchar(6) DEFAULT NULL,
  `pg2_FHR7` varchar(6) DEFAULT NULL,
  `pg2_urinePr7` char(3) DEFAULT NULL,
  `pg2_urineGl7` char(3) DEFAULT NULL,
  `pg2_BP7` varchar(8) DEFAULT NULL,
  `pg2_comments7` varchar(80) DEFAULT NULL,
  `pg2_date8` date DEFAULT NULL,
  `pg2_gest8` varchar(6) DEFAULT NULL,
  `pg2_ht8` varchar(6) DEFAULT NULL,
  `pg2_wt8` varchar(6) DEFAULT NULL,
  `pg2_presn8` varchar(6) DEFAULT NULL,
  `pg2_FHR8` varchar(6) DEFAULT NULL,
  `pg2_urinePr8` char(3) DEFAULT NULL,
  `pg2_urineGl8` char(3) DEFAULT NULL,
  `pg2_BP8` varchar(8) DEFAULT NULL,
  `pg2_comments8` varchar(80) DEFAULT NULL,
  `pg2_date9` date DEFAULT NULL,
  `pg2_gest9` varchar(6) DEFAULT NULL,
  `pg2_ht9` varchar(6) DEFAULT NULL,
  `pg2_wt9` varchar(6) DEFAULT NULL,
  `pg2_presn9` varchar(6) DEFAULT NULL,
  `pg2_FHR9` varchar(6) DEFAULT NULL,
  `pg2_urinePr9` char(3) DEFAULT NULL,
  `pg2_urineGl9` char(3) DEFAULT NULL,
  `pg2_BP9` varchar(8) DEFAULT NULL,
  `pg2_comments9` varchar(80) DEFAULT NULL,
  `pg2_date10` date DEFAULT NULL,
  `pg2_gest10` varchar(6) DEFAULT NULL,
  `pg2_ht10` varchar(6) DEFAULT NULL,
  `pg2_wt10` varchar(6) DEFAULT NULL,
  `pg2_presn10` varchar(6) DEFAULT NULL,
  `pg2_FHR10` varchar(6) DEFAULT NULL,
  `pg2_urinePr10` char(3) DEFAULT NULL,
  `pg2_urineGl10` char(3) DEFAULT NULL,
  `pg2_BP10` varchar(8) DEFAULT NULL,
  `pg2_comments10` varchar(80) DEFAULT NULL,
  `pg2_date11` date DEFAULT NULL,
  `pg2_gest11` varchar(6) DEFAULT NULL,
  `pg2_ht11` varchar(6) DEFAULT NULL,
  `pg2_wt11` varchar(6) DEFAULT NULL,
  `pg2_presn11` varchar(6) DEFAULT NULL,
  `pg2_FHR11` varchar(6) DEFAULT NULL,
  `pg2_urinePr11` char(3) DEFAULT NULL,
  `pg2_urineGl11` char(3) DEFAULT NULL,
  `pg2_BP11` varchar(8) DEFAULT NULL,
  `pg2_comments11` varchar(80) DEFAULT NULL,
  `pg2_date12` date DEFAULT NULL,
  `pg2_gest12` varchar(6) DEFAULT NULL,
  `pg2_ht12` varchar(6) DEFAULT NULL,
  `pg2_wt12` varchar(6) DEFAULT NULL,
  `pg2_presn12` varchar(6) DEFAULT NULL,
  `pg2_FHR12` varchar(6) DEFAULT NULL,
  `pg2_urinePr12` char(3) DEFAULT NULL,
  `pg2_urineGl12` char(3) DEFAULT NULL,
  `pg2_BP12` varchar(8) DEFAULT NULL,
  `pg2_comments12` varchar(80) DEFAULT NULL,
  `pg2_date13` date DEFAULT NULL,
  `pg2_gest13` varchar(6) DEFAULT NULL,
  `pg2_ht13` varchar(6) DEFAULT NULL,
  `pg2_wt13` varchar(6) DEFAULT NULL,
  `pg2_presn13` varchar(6) DEFAULT NULL,
  `pg2_FHR13` varchar(6) DEFAULT NULL,
  `pg2_urinePr13` char(3) DEFAULT NULL,
  `pg2_urineGl13` char(3) DEFAULT NULL,
  `pg2_BP13` varchar(8) DEFAULT NULL,
  `pg2_comments13` varchar(80) DEFAULT NULL,
  `pg2_date14` date DEFAULT NULL,
  `pg2_gest14` varchar(6) DEFAULT NULL,
  `pg2_ht14` varchar(6) DEFAULT NULL,
  `pg2_wt14` varchar(6) DEFAULT NULL,
  `pg2_presn14` varchar(6) DEFAULT NULL,
  `pg2_FHR14` varchar(6) DEFAULT NULL,
  `pg2_urinePr14` char(3) DEFAULT NULL,
  `pg2_urineGl14` char(3) DEFAULT NULL,
  `pg2_BP14` varchar(8) DEFAULT NULL,
  `pg2_comments14` varchar(80) DEFAULT NULL,
  `pg2_date15` date DEFAULT NULL,
  `pg2_gest15` varchar(6) DEFAULT NULL,
  `pg2_ht15` varchar(6) DEFAULT NULL,
  `pg2_wt15` varchar(6) DEFAULT NULL,
  `pg2_presn15` varchar(6) DEFAULT NULL,
  `pg2_FHR15` varchar(6) DEFAULT NULL,
  `pg2_urinePr15` char(3) DEFAULT NULL,
  `pg2_urineGl15` char(3) DEFAULT NULL,
  `pg2_BP15` varchar(8) DEFAULT NULL,
  `pg2_comments15` varchar(80) DEFAULT NULL,
  `pg2_date16` date DEFAULT NULL,
  `pg2_gest16` varchar(6) DEFAULT NULL,
  `pg2_ht16` varchar(6) DEFAULT NULL,
  `pg2_wt16` varchar(6) DEFAULT NULL,
  `pg2_presn16` varchar(6) DEFAULT NULL,
  `pg2_FHR16` varchar(6) DEFAULT NULL,
  `pg2_urinePr16` char(3) DEFAULT NULL,
  `pg2_urineGl16` char(3) DEFAULT NULL,
  `pg2_BP16` varchar(8) DEFAULT NULL,
  `pg2_comments16` varchar(80) DEFAULT NULL,
  `pg2_date17` date DEFAULT NULL,
  `pg2_gest17` varchar(6) DEFAULT NULL,
  `pg2_ht17` varchar(6) DEFAULT NULL,
  `pg2_wt17` varchar(6) DEFAULT NULL,
  `pg2_presn17` varchar(6) DEFAULT NULL,
  `pg2_FHR17` varchar(6) DEFAULT NULL,
  `pg2_urinePr17` char(3) DEFAULT NULL,
  `pg2_urineGl17` char(3) DEFAULT NULL,
  `pg2_BP17` varchar(8) DEFAULT NULL,
  `pg2_comments17` varchar(80) DEFAULT NULL,
  `pg2_date18` date DEFAULT NULL,
  `pg2_gest18` varchar(6) DEFAULT NULL,
  `pg2_ht18` varchar(6) DEFAULT NULL,
  `pg2_wt18` varchar(6) DEFAULT NULL,
  `pg2_presn18` varchar(6) DEFAULT NULL,
  `pg2_FHR18` varchar(6) DEFAULT NULL,
  `pg2_urinePr18` char(3) DEFAULT NULL,
  `pg2_urineGl18` char(3) DEFAULT NULL,
  `pg2_BP18` varchar(8) DEFAULT NULL,
  `pg2_comments18` varchar(80) DEFAULT NULL,
  `pg2_date19` date DEFAULT NULL,
  `pg2_gest19` varchar(6) DEFAULT NULL,
  `pg2_ht19` varchar(6) DEFAULT NULL,
  `pg2_wt19` varchar(6) DEFAULT NULL,
  `pg2_presn19` varchar(6) DEFAULT NULL,
  `pg2_FHR19` varchar(6) DEFAULT NULL,
  `pg2_urinePr19` char(3) DEFAULT NULL,
  `pg2_urineGl19` char(3) DEFAULT NULL,
  `pg2_BP19` varchar(8) DEFAULT NULL,
  `pg2_comments19` varchar(80) DEFAULT NULL,
  `pg2_date20` date DEFAULT NULL,
  `pg2_gest20` varchar(6) DEFAULT NULL,
  `pg2_ht20` varchar(6) DEFAULT NULL,
  `pg2_wt20` varchar(6) DEFAULT NULL,
  `pg2_presn20` varchar(6) DEFAULT NULL,
  `pg2_FHR20` varchar(6) DEFAULT NULL,
  `pg2_urinePr20` char(3) DEFAULT NULL,
  `pg2_urineGl20` char(3) DEFAULT NULL,
  `pg2_BP20` varchar(8) DEFAULT NULL,
  `pg2_comments20` varchar(80) DEFAULT NULL,
  `pg2_date21` date DEFAULT NULL,
  `pg2_gest21` varchar(6) DEFAULT NULL,
  `pg2_ht21` varchar(6) DEFAULT NULL,
  `pg2_wt21` varchar(6) DEFAULT NULL,
  `pg2_presn21` varchar(6) DEFAULT NULL,
  `pg2_FHR21` varchar(6) DEFAULT NULL,
  `pg2_urinePr21` char(3) DEFAULT NULL,
  `pg2_urineGl21` char(3) DEFAULT NULL,
  `pg2_BP21` varchar(8) DEFAULT NULL,
  `pg2_comments21` varchar(80) DEFAULT NULL,
  `pg2_date22` date DEFAULT NULL,
  `pg2_gest22` varchar(6) DEFAULT NULL,
  `pg2_ht22` varchar(6) DEFAULT NULL,
  `pg2_wt22` varchar(6) DEFAULT NULL,
  `pg2_presn22` varchar(6) DEFAULT NULL,
  `pg2_FHR22` varchar(6) DEFAULT NULL,
  `pg2_urinePr22` char(3) DEFAULT NULL,
  `pg2_urineGl22` char(3) DEFAULT NULL,
  `pg2_BP22` varchar(8) DEFAULT NULL,
  `pg2_comments22` varchar(80) DEFAULT NULL,
  `pg2_date23` date DEFAULT NULL,
  `pg2_gest23` varchar(6) DEFAULT NULL,
  `pg2_ht23` varchar(6) DEFAULT NULL,
  `pg2_wt23` varchar(6) DEFAULT NULL,
  `pg2_presn23` varchar(6) DEFAULT NULL,
  `pg2_FHR23` varchar(6) DEFAULT NULL,
  `pg2_urinePr23` char(3) DEFAULT NULL,
  `pg2_urineGl23` char(3) DEFAULT NULL,
  `pg2_BP23` varchar(8) DEFAULT NULL,
  `pg2_comments23` varchar(80) DEFAULT NULL,
  `pg2_date24` date DEFAULT NULL,
  `pg2_gest24` varchar(6) DEFAULT NULL,
  `pg2_ht24` varchar(6) DEFAULT NULL,
  `pg2_wt24` varchar(6) DEFAULT NULL,
  `pg2_presn24` varchar(6) DEFAULT NULL,
  `pg2_FHR24` varchar(6) DEFAULT NULL,
  `pg2_urinePr24` char(3) DEFAULT NULL,
  `pg2_urineGl24` char(3) DEFAULT NULL,
  `pg2_BP24` varchar(8) DEFAULT NULL,
  `pg2_comments24` varchar(80) DEFAULT NULL,
  `pg2_date25` date DEFAULT NULL,
  `pg2_gest25` varchar(6) DEFAULT NULL,
  `pg2_ht25` varchar(6) DEFAULT NULL,
  `pg2_wt25` varchar(6) DEFAULT NULL,
  `pg2_presn25` varchar(6) DEFAULT NULL,
  `pg2_FHR25` varchar(6) DEFAULT NULL,
  `pg2_urinePr25` char(3) DEFAULT NULL,
  `pg2_urineGl25` char(3) DEFAULT NULL,
  `pg2_BP25` varchar(8) DEFAULT NULL,
  `pg2_comments25` varchar(80) DEFAULT NULL,
  `pg2_date26` date DEFAULT NULL,
  `pg2_gest26` varchar(6) DEFAULT NULL,
  `pg2_ht26` varchar(6) DEFAULT NULL,
  `pg2_wt26` varchar(6) DEFAULT NULL,
  `pg2_presn26` varchar(6) DEFAULT NULL,
  `pg2_FHR26` varchar(6) DEFAULT NULL,
  `pg2_urinePr26` char(3) DEFAULT NULL,
  `pg2_urineGl26` char(3) DEFAULT NULL,
  `pg2_BP26` varchar(8) DEFAULT NULL,
  `pg2_comments26` varchar(80) DEFAULT NULL,
  `pg2_date27` date DEFAULT NULL,
  `pg2_gest27` varchar(6) DEFAULT NULL,
  `pg2_ht27` varchar(6) DEFAULT NULL,
  `pg2_wt27` varchar(6) DEFAULT NULL,
  `pg2_presn27` varchar(6) DEFAULT NULL,
  `pg2_FHR27` varchar(6) DEFAULT NULL,
  `pg2_urinePr27` char(3) DEFAULT NULL,
  `pg2_urineGl27` char(3) DEFAULT NULL,
  `pg2_BP27` varchar(8) DEFAULT NULL,
  `pg2_comments27` varchar(80) DEFAULT NULL,
  `pg2_date28` date DEFAULT NULL,
  `pg2_gest28` varchar(6) DEFAULT NULL,
  `pg2_ht28` varchar(6) DEFAULT NULL,
  `pg2_wt28` varchar(6) DEFAULT NULL,
  `pg2_presn28` varchar(6) DEFAULT NULL,
  `pg2_FHR28` varchar(6) DEFAULT NULL,
  `pg2_urinePr28` char(3) DEFAULT NULL,
  `pg2_urineGl28` char(3) DEFAULT NULL,
  `pg2_BP28` varchar(8) DEFAULT NULL,
  `pg2_comments28` varchar(80) DEFAULT NULL,
  `pg2_date29` date DEFAULT NULL,
  `pg2_gest29` varchar(6) DEFAULT NULL,
  `pg2_ht29` varchar(6) DEFAULT NULL,
  `pg2_wt29` varchar(6) DEFAULT NULL,
  `pg2_presn29` varchar(6) DEFAULT NULL,
  `pg2_FHR29` varchar(6) DEFAULT NULL,
  `pg2_urinePr29` char(3) DEFAULT NULL,
  `pg2_urineGl29` char(3) DEFAULT NULL,
  `pg2_BP29` varchar(8) DEFAULT NULL,
  `pg2_comments29` varchar(80) DEFAULT NULL,
  `pg2_date30` date DEFAULT NULL,
  `pg2_gest30` varchar(6) DEFAULT NULL,
  `pg2_ht30` varchar(6) DEFAULT NULL,
  `pg2_wt30` varchar(6) DEFAULT NULL,
  `pg2_presn30` varchar(6) DEFAULT NULL,
  `pg2_FHR30` varchar(6) DEFAULT NULL,
  `pg2_urinePr30` char(3) DEFAULT NULL,
  `pg2_urineGl30` char(3) DEFAULT NULL,
  `pg2_BP30` varchar(8) DEFAULT NULL,
  `pg2_comments30` varchar(80) DEFAULT NULL,
  `pg2_date31` date DEFAULT NULL,
  `pg2_gest31` varchar(6) DEFAULT NULL,
  `pg2_ht31` varchar(6) DEFAULT NULL,
  `pg2_wt31` varchar(6) DEFAULT NULL,
  `pg2_presn31` varchar(6) DEFAULT NULL,
  `pg2_FHR31` varchar(6) DEFAULT NULL,
  `pg2_urinePr31` char(3) DEFAULT NULL,
  `pg2_urineGl31` char(3) DEFAULT NULL,
  `pg2_BP31` varchar(8) DEFAULT NULL,
  `pg2_comments31` varchar(80) DEFAULT NULL,
  `pg2_date32` date DEFAULT NULL,
  `pg2_gest32` varchar(6) DEFAULT NULL,
  `pg2_ht32` varchar(6) DEFAULT NULL,
  `pg2_wt32` varchar(6) DEFAULT NULL,
  `pg2_presn32` varchar(6) DEFAULT NULL,
  `pg2_FHR32` varchar(6) DEFAULT NULL,
  `pg2_urinePr32` char(3) DEFAULT NULL,
  `pg2_urineGl32` char(3) DEFAULT NULL,
  `pg2_BP32` varchar(8) DEFAULT NULL,
  `pg2_comments32` varchar(80) DEFAULT NULL,
  `pg2_date33` date DEFAULT NULL,
  `pg2_gest33` varchar(6) DEFAULT NULL,
  `pg2_ht33` varchar(6) DEFAULT NULL,
  `pg2_wt33` varchar(6) DEFAULT NULL,
  `pg2_presn33` varchar(6) DEFAULT NULL,
  `pg2_FHR33` varchar(6) DEFAULT NULL,
  `pg2_urinePr33` char(3) DEFAULT NULL,
  `pg2_urineGl33` char(3) DEFAULT NULL,
  `pg2_BP33` varchar(8) DEFAULT NULL,
  `pg2_comments33` varchar(80) DEFAULT NULL,
  `pg2_date34` date DEFAULT NULL,
  `pg2_gest34` varchar(6) DEFAULT NULL,
  `pg2_ht34` varchar(6) DEFAULT NULL,
  `pg2_wt34` varchar(6) DEFAULT NULL,
  `pg2_presn34` varchar(6) DEFAULT NULL,
  `pg2_FHR34` varchar(6) DEFAULT NULL,
  `pg2_urinePr34` char(3) DEFAULT NULL,
  `pg2_urineGl34` char(3) DEFAULT NULL,
  `pg2_BP34` varchar(8) DEFAULT NULL,
  `pg2_comments34` varchar(80) DEFAULT NULL,
  `pg2_date35` date DEFAULT NULL,
  `pg2_gest35` varchar(6) DEFAULT NULL,
  `pg2_ht35` varchar(6) DEFAULT NULL,
  `pg2_wt35` varchar(6) DEFAULT NULL,
  `pg2_presn35` varchar(6) DEFAULT NULL,
  `pg2_FHR35` varchar(6) DEFAULT NULL,
  `pg2_urinePr35` char(3) DEFAULT NULL,
  `pg2_urineGl35` char(3) DEFAULT NULL,
  `pg2_BP35` varchar(8) DEFAULT NULL,
  `pg2_comments35` varchar(80) DEFAULT NULL,
  `pg2_date36` date DEFAULT NULL,
  `pg2_gest36` varchar(6) DEFAULT NULL,
  `pg2_ht36` varchar(6) DEFAULT NULL,
  `pg2_wt36` varchar(6) DEFAULT NULL,
  `pg2_presn36` varchar(6) DEFAULT NULL,
  `pg2_FHR36` varchar(6) DEFAULT NULL,
  `pg2_urinePr36` char(3) DEFAULT NULL,
  `pg2_urineGl36` char(3) DEFAULT NULL,
  `pg2_BP36` varchar(8) DEFAULT NULL,
  `pg2_comments36` varchar(80) DEFAULT NULL,
  `pg2_date37` date DEFAULT NULL,
  `pg2_gest37` varchar(6) DEFAULT NULL,
  `pg2_ht37` varchar(6) DEFAULT NULL,
  `pg2_wt37` varchar(6) DEFAULT NULL,
  `pg2_presn37` varchar(6) DEFAULT NULL,
  `pg2_FHR37` varchar(6) DEFAULT NULL,
  `pg2_urinePr37` char(3) DEFAULT NULL,
  `pg2_urineGl37` char(3) DEFAULT NULL,
  `pg2_BP37` varchar(8) DEFAULT NULL,
  `pg2_comments37` varchar(80) DEFAULT NULL,
  `pg2_date38` date DEFAULT NULL,
  `pg2_gest38` varchar(6) DEFAULT NULL,
  `pg2_ht38` varchar(6) DEFAULT NULL,
  `pg2_wt38` varchar(6) DEFAULT NULL,
  `pg2_presn38` varchar(6) DEFAULT NULL,
  `pg2_FHR38` varchar(6) DEFAULT NULL,
  `pg2_urinePr38` char(3) DEFAULT NULL,
  `pg2_urineGl38` char(3) DEFAULT NULL,
  `pg2_BP38` varchar(8) DEFAULT NULL,
  `pg2_comments38` varchar(80) DEFAULT NULL,
  `pg2_date39` date DEFAULT NULL,
  `pg2_gest39` varchar(6) DEFAULT NULL,
  `pg2_ht39` varchar(6) DEFAULT NULL,
  `pg2_wt39` varchar(6) DEFAULT NULL,
  `pg2_presn39` varchar(6) DEFAULT NULL,
  `pg2_FHR39` varchar(6) DEFAULT NULL,
  `pg2_urinePr39` char(3) DEFAULT NULL,
  `pg2_urineGl39` char(3) DEFAULT NULL,
  `pg2_BP39` varchar(8) DEFAULT NULL,
  `pg2_comments39` varchar(80) DEFAULT NULL,
  `pg2_date40` date DEFAULT NULL,
  `pg2_gest40` varchar(6) DEFAULT NULL,
  `pg2_ht40` varchar(6) DEFAULT NULL,
  `pg2_wt40` varchar(6) DEFAULT NULL,
  `pg2_presn40` varchar(6) DEFAULT NULL,
  `pg2_FHR40` varchar(6) DEFAULT NULL,
  `pg2_urinePr40` char(3) DEFAULT NULL,
  `pg2_urineGl40` char(3) DEFAULT NULL,
  `pg2_BP40` varchar(8) DEFAULT NULL,
  `pg2_comments40` varchar(80) DEFAULT NULL
);

--
-- Table structure for table `formONAREnhancedRecordExt2`
--


CREATE TABLE `formONAREnhancedRecordExt2` (
  `ID` int(10) NOT NULL,
  `pg2_date41` date DEFAULT NULL,
  `pg2_gest41` varchar(6) DEFAULT NULL,
  `pg2_ht41` varchar(6) DEFAULT NULL,
  `pg2_wt41` varchar(6) DEFAULT NULL,
  `pg2_presn41` varchar(6) DEFAULT NULL,
  `pg2_FHR41` varchar(6) DEFAULT NULL,
  `pg2_urinePr41` char(3) DEFAULT NULL,
  `pg2_urineGl41` char(3) DEFAULT NULL,
  `pg2_BP41` varchar(8) DEFAULT NULL,
  `pg2_comments41` varchar(80) DEFAULT NULL,
  `pg2_date42` date DEFAULT NULL,
  `pg2_gest42` varchar(6) DEFAULT NULL,
  `pg2_ht42` varchar(6) DEFAULT NULL,
  `pg2_wt42` varchar(6) DEFAULT NULL,
  `pg2_presn42` varchar(6) DEFAULT NULL,
  `pg2_FHR42` varchar(6) DEFAULT NULL,
  `pg2_urinePr42` char(3) DEFAULT NULL,
  `pg2_urineGl42` char(3) DEFAULT NULL,
  `pg2_BP42` varchar(8) DEFAULT NULL,
  `pg2_comments42` varchar(80) DEFAULT NULL,
  `pg2_date43` date DEFAULT NULL,
  `pg2_gest43` varchar(6) DEFAULT NULL,
  `pg2_ht43` varchar(6) DEFAULT NULL,
  `pg2_wt43` varchar(6) DEFAULT NULL,
  `pg2_presn43` varchar(6) DEFAULT NULL,
  `pg2_FHR43` varchar(6) DEFAULT NULL,
  `pg2_urinePr43` char(3) DEFAULT NULL,
  `pg2_urineGl43` char(3) DEFAULT NULL,
  `pg2_BP43` varchar(8) DEFAULT NULL,
  `pg2_comments43` varchar(80) DEFAULT NULL,
  `pg2_date44` date DEFAULT NULL,
  `pg2_gest44` varchar(6) DEFAULT NULL,
  `pg2_ht44` varchar(6) DEFAULT NULL,
  `pg2_wt44` varchar(6) DEFAULT NULL,
  `pg2_presn44` varchar(6) DEFAULT NULL,
  `pg2_FHR44` varchar(6) DEFAULT NULL,
  `pg2_urinePr44` char(3) DEFAULT NULL,
  `pg2_urineGl44` char(3) DEFAULT NULL,
  `pg2_BP44` varchar(8) DEFAULT NULL,
  `pg2_comments44` varchar(80) DEFAULT NULL,
  `pg2_date45` date DEFAULT NULL,
  `pg2_gest45` varchar(6) DEFAULT NULL,
  `pg2_ht45` varchar(6) DEFAULT NULL,
  `pg2_wt45` varchar(6) DEFAULT NULL,
  `pg2_presn45` varchar(6) DEFAULT NULL,
  `pg2_FHR45` varchar(6) DEFAULT NULL,
  `pg2_urinePr45` char(3) DEFAULT NULL,
  `pg2_urineGl45` char(3) DEFAULT NULL,
  `pg2_BP45` varchar(8) DEFAULT NULL,
  `pg2_comments45` varchar(80) DEFAULT NULL,
  `pg2_date46` date DEFAULT NULL,
  `pg2_gest46` varchar(6) DEFAULT NULL,
  `pg2_ht46` varchar(6) DEFAULT NULL,
  `pg2_wt46` varchar(6) DEFAULT NULL,
  `pg2_presn46` varchar(6) DEFAULT NULL,
  `pg2_FHR46` varchar(6) DEFAULT NULL,
  `pg2_urinePr46` char(3) DEFAULT NULL,
  `pg2_urineGl46` char(3) DEFAULT NULL,
  `pg2_BP46` varchar(8) DEFAULT NULL,
  `pg2_comments46` varchar(80) DEFAULT NULL,
  `pg2_date47` date DEFAULT NULL,
  `pg2_gest47` varchar(6) DEFAULT NULL,
  `pg2_ht47` varchar(6) DEFAULT NULL,
  `pg2_wt47` varchar(6) DEFAULT NULL,
  `pg2_presn47` varchar(6) DEFAULT NULL,
  `pg2_FHR47` varchar(6) DEFAULT NULL,
  `pg2_urinePr47` char(3) DEFAULT NULL,
  `pg2_urineGl47` char(3) DEFAULT NULL,
  `pg2_BP47` varchar(8) DEFAULT NULL,
  `pg2_comments47` varchar(80) DEFAULT NULL,
  `pg2_date48` date DEFAULT NULL,
  `pg2_gest48` varchar(6) DEFAULT NULL,
  `pg2_ht48` varchar(6) DEFAULT NULL,
  `pg2_wt48` varchar(6) DEFAULT NULL,
  `pg2_presn48` varchar(6) DEFAULT NULL,
  `pg2_FHR48` varchar(6) DEFAULT NULL,
  `pg2_urinePr48` char(3) DEFAULT NULL,
  `pg2_urineGl48` char(3) DEFAULT NULL,
  `pg2_BP48` varchar(8) DEFAULT NULL,
  `pg2_comments48` varchar(80) DEFAULT NULL,
  `pg2_date49` date DEFAULT NULL,
  `pg2_gest49` varchar(6) DEFAULT NULL,
  `pg2_ht49` varchar(6) DEFAULT NULL,
  `pg2_wt49` varchar(6) DEFAULT NULL,
  `pg2_presn49` varchar(6) DEFAULT NULL,
  `pg2_FHR49` varchar(6) DEFAULT NULL,
  `pg2_urinePr49` char(3) DEFAULT NULL,
  `pg2_urineGl49` char(3) DEFAULT NULL,
  `pg2_BP49` varchar(8) DEFAULT NULL,
  `pg2_comments49` varchar(80) DEFAULT NULL,
  `pg2_date50` date DEFAULT NULL,
  `pg2_gest50` varchar(6) DEFAULT NULL,
  `pg2_ht50` varchar(6) DEFAULT NULL,
  `pg2_wt50` varchar(6) DEFAULT NULL,
  `pg2_presn50` varchar(6) DEFAULT NULL,
  `pg2_FHR50` varchar(6) DEFAULT NULL,
  `pg2_urinePr50` char(3) DEFAULT NULL,
  `pg2_urineGl50` char(3) DEFAULT NULL,
  `pg2_BP50` varchar(8) DEFAULT NULL,
  `pg2_comments50` varchar(80) DEFAULT NULL,
  `pg2_date51` date DEFAULT NULL,
  `pg2_gest51` varchar(6) DEFAULT NULL,
  `pg2_ht51` varchar(6) DEFAULT NULL,
  `pg2_wt51` varchar(6) DEFAULT NULL,
  `pg2_presn51` varchar(6) DEFAULT NULL,
  `pg2_FHR51` varchar(6) DEFAULT NULL,
  `pg2_urinePr51` char(3) DEFAULT NULL,
  `pg2_urineGl51` char(3) DEFAULT NULL,
  `pg2_BP51` varchar(8) DEFAULT NULL,
  `pg2_comments51` varchar(80) DEFAULT NULL,
  `pg2_date52` date DEFAULT NULL,
  `pg2_gest52` varchar(6) DEFAULT NULL,
  `pg2_ht52` varchar(6) DEFAULT NULL,
  `pg2_wt52` varchar(6) DEFAULT NULL,
  `pg2_presn52` varchar(6) DEFAULT NULL,
  `pg2_FHR52` varchar(6) DEFAULT NULL,
  `pg2_urinePr52` char(3) DEFAULT NULL,
  `pg2_urineGl52` char(3) DEFAULT NULL,
  `pg2_BP52` varchar(8) DEFAULT NULL,
  `pg2_comments52` varchar(80) DEFAULT NULL,
  `pg2_date53` date DEFAULT NULL,
  `pg2_gest53` varchar(6) DEFAULT NULL,
  `pg2_ht53` varchar(6) DEFAULT NULL,
  `pg2_wt53` varchar(6) DEFAULT NULL,
  `pg2_presn53` varchar(6) DEFAULT NULL,
  `pg2_FHR53` varchar(6) DEFAULT NULL,
  `pg2_urinePr53` char(3) DEFAULT NULL,
  `pg2_urineGl53` char(3) DEFAULT NULL,
  `pg2_BP53` varchar(8) DEFAULT NULL,
  `pg2_comments53` varchar(80) DEFAULT NULL,
  `pg2_date54` date DEFAULT NULL,
  `pg2_gest54` varchar(6) DEFAULT NULL,
  `pg2_ht54` varchar(6) DEFAULT NULL,
  `pg2_wt54` varchar(6) DEFAULT NULL,
  `pg2_presn54` varchar(6) DEFAULT NULL,
  `pg2_FHR54` varchar(6) DEFAULT NULL,
  `pg2_urinePr54` char(3) DEFAULT NULL,
  `pg2_urineGl54` char(3) DEFAULT NULL,
  `pg2_BP54` varchar(8) DEFAULT NULL,
  `pg2_comments54` varchar(80) DEFAULT NULL,
  `pg2_date55` date DEFAULT NULL,
  `pg2_gest55` varchar(6) DEFAULT NULL,
  `pg2_ht55` varchar(6) DEFAULT NULL,
  `pg2_wt55` varchar(6) DEFAULT NULL,
  `pg2_presn55` varchar(6) DEFAULT NULL,
  `pg2_FHR55` varchar(6) DEFAULT NULL,
  `pg2_urinePr55` char(3) DEFAULT NULL,
  `pg2_urineGl55` char(3) DEFAULT NULL,
  `pg2_BP55` varchar(8) DEFAULT NULL,
  `pg2_comments55` varchar(80) DEFAULT NULL,
  `pg2_date56` date DEFAULT NULL,
  `pg2_gest56` varchar(6) DEFAULT NULL,
  `pg2_ht56` varchar(6) DEFAULT NULL,
  `pg2_wt56` varchar(6) DEFAULT NULL,
  `pg2_presn56` varchar(6) DEFAULT NULL,
  `pg2_FHR56` varchar(6) DEFAULT NULL,
  `pg2_urinePr56` char(3) DEFAULT NULL,
  `pg2_urineGl56` char(3) DEFAULT NULL,
  `pg2_BP56` varchar(8) DEFAULT NULL,
  `pg2_comments56` varchar(80) DEFAULT NULL,
  `pg2_date57` date DEFAULT NULL,
  `pg2_gest57` varchar(6) DEFAULT NULL,
  `pg2_ht57` varchar(6) DEFAULT NULL,
  `pg2_wt57` varchar(6) DEFAULT NULL,
  `pg2_presn57` varchar(6) DEFAULT NULL,
  `pg2_FHR57` varchar(6) DEFAULT NULL,
  `pg2_urinePr57` char(3) DEFAULT NULL,
  `pg2_urineGl57` char(3) DEFAULT NULL,
  `pg2_BP57` varchar(8) DEFAULT NULL,
  `pg2_comments57` varchar(80) DEFAULT NULL,
  `pg2_date58` date DEFAULT NULL,
  `pg2_gest58` varchar(6) DEFAULT NULL,
  `pg2_ht58` varchar(6) DEFAULT NULL,
  `pg2_wt58` varchar(6) DEFAULT NULL,
  `pg2_presn58` varchar(6) DEFAULT NULL,
  `pg2_FHR58` varchar(6) DEFAULT NULL,
  `pg2_urinePr58` char(3) DEFAULT NULL,
  `pg2_urineGl58` char(3) DEFAULT NULL,
  `pg2_BP58` varchar(8) DEFAULT NULL,
  `pg2_comments58` varchar(80) DEFAULT NULL,
  `pg2_date59` date DEFAULT NULL,
  `pg2_gest59` varchar(6) DEFAULT NULL,
  `pg2_ht59` varchar(6) DEFAULT NULL,
  `pg2_wt59` varchar(6) DEFAULT NULL,
  `pg2_presn59` varchar(6) DEFAULT NULL,
  `pg2_FHR59` varchar(6) DEFAULT NULL,
  `pg2_urinePr59` char(3) DEFAULT NULL,
  `pg2_urineGl59` char(3) DEFAULT NULL,
  `pg2_BP59` varchar(8) DEFAULT NULL,
  `pg2_comments59` varchar(80) DEFAULT NULL,
  `pg2_date60` date DEFAULT NULL,
  `pg2_gest60` varchar(6) DEFAULT NULL,
  `pg2_ht60` varchar(6) DEFAULT NULL,
  `pg2_wt60` varchar(6) DEFAULT NULL,
  `pg2_presn60` varchar(6) DEFAULT NULL,
  `pg2_FHR60` varchar(6) DEFAULT NULL,
  `pg2_urinePr60` char(3) DEFAULT NULL,
  `pg2_urineGl60` char(3) DEFAULT NULL,
  `pg2_BP60` varchar(8) DEFAULT NULL,
  `pg2_comments60` varchar(80) DEFAULT NULL,
  `pg2_date61` date DEFAULT NULL,
  `pg2_gest61` varchar(6) DEFAULT NULL,
  `pg2_ht61` varchar(6) DEFAULT NULL,
  `pg2_wt61` varchar(6) DEFAULT NULL,
  `pg2_presn61` varchar(6) DEFAULT NULL,
  `pg2_FHR61` varchar(6) DEFAULT NULL,
  `pg2_urinePr61` char(3) DEFAULT NULL,
  `pg2_urineGl61` char(3) DEFAULT NULL,
  `pg2_BP61` varchar(8) DEFAULT NULL,
  `pg2_comments61` varchar(80) DEFAULT NULL,
  `pg2_date62` date DEFAULT NULL,
  `pg2_gest62` varchar(6) DEFAULT NULL,
  `pg2_ht62` varchar(6) DEFAULT NULL,
  `pg2_wt62` varchar(6) DEFAULT NULL,
  `pg2_presn62` varchar(6) DEFAULT NULL,
  `pg2_FHR62` varchar(6) DEFAULT NULL,
  `pg2_urinePr62` char(3) DEFAULT NULL,
  `pg2_urineGl62` char(3) DEFAULT NULL,
  `pg2_BP62` varchar(8) DEFAULT NULL,
  `pg2_comments62` varchar(80) DEFAULT NULL,
  `pg2_date63` date DEFAULT NULL,
  `pg2_gest63` varchar(6) DEFAULT NULL,
  `pg2_ht63` varchar(6) DEFAULT NULL,
  `pg2_wt63` varchar(6) DEFAULT NULL,
  `pg2_presn63` varchar(6) DEFAULT NULL,
  `pg2_FHR63` varchar(6) DEFAULT NULL,
  `pg2_urinePr63` char(3) DEFAULT NULL,
  `pg2_urineGl63` char(3) DEFAULT NULL,
  `pg2_BP63` varchar(8) DEFAULT NULL,
  `pg2_comments63` varchar(80) DEFAULT NULL,
  `pg2_date64` date DEFAULT NULL,
  `pg2_gest64` varchar(6) DEFAULT NULL,
  `pg2_ht64` varchar(6) DEFAULT NULL,
  `pg2_wt64` varchar(6) DEFAULT NULL,
  `pg2_presn64` varchar(6) DEFAULT NULL,
  `pg2_FHR64` varchar(6) DEFAULT NULL,
  `pg2_urinePr64` char(3) DEFAULT NULL,
  `pg2_urineGl64` char(3) DEFAULT NULL,
  `pg2_BP64` varchar(8) DEFAULT NULL,
  `pg2_comments64` varchar(80) DEFAULT NULL,
  `pg2_date65` date DEFAULT NULL,
  `pg2_gest65` varchar(6) DEFAULT NULL,
  `pg2_ht65` varchar(6) DEFAULT NULL,
  `pg2_wt65` varchar(6) DEFAULT NULL,
  `pg2_presn65` varchar(6) DEFAULT NULL,
  `pg2_FHR65` varchar(6) DEFAULT NULL,
  `pg2_urinePr65` char(3) DEFAULT NULL,
  `pg2_urineGl65` char(3) DEFAULT NULL,
  `pg2_BP65` varchar(8) DEFAULT NULL,
  `pg2_comments65` varchar(80) DEFAULT NULL,
  `pg2_date66` date DEFAULT NULL,
  `pg2_gest66` varchar(6) DEFAULT NULL,
  `pg2_ht66` varchar(6) DEFAULT NULL,
  `pg2_wt66` varchar(6) DEFAULT NULL,
  `pg2_presn66` varchar(6) DEFAULT NULL,
  `pg2_FHR66` varchar(6) DEFAULT NULL,
  `pg2_urinePr66` char(3) DEFAULT NULL,
  `pg2_urineGl66` char(3) DEFAULT NULL,
  `pg2_BP66` varchar(8) DEFAULT NULL,
  `pg2_comments66` varchar(80) DEFAULT NULL,
  `pg2_date67` date DEFAULT NULL,
  `pg2_gest67` varchar(6) DEFAULT NULL,
  `pg2_ht67` varchar(6) DEFAULT NULL,
  `pg2_wt67` varchar(6) DEFAULT NULL,
  `pg2_presn67` varchar(6) DEFAULT NULL,
  `pg2_FHR67` varchar(6) DEFAULT NULL,
  `pg2_urinePr67` char(3) DEFAULT NULL,
  `pg2_urineGl67` char(3) DEFAULT NULL,
  `pg2_BP67` varchar(8) DEFAULT NULL,
  `pg2_comments67` varchar(80) DEFAULT NULL,
  `pg2_date68` date DEFAULT NULL,
  `pg2_gest68` varchar(6) DEFAULT NULL,
  `pg2_ht68` varchar(6) DEFAULT NULL,
  `pg2_wt68` varchar(6) DEFAULT NULL,
  `pg2_presn68` varchar(6) DEFAULT NULL,
  `pg2_FHR68` varchar(6) DEFAULT NULL,
  `pg2_urinePr68` char(3) DEFAULT NULL,
  `pg2_urineGl68` char(3) DEFAULT NULL,
  `pg2_BP68` varchar(8) DEFAULT NULL,
  `pg2_comments68` varchar(80) DEFAULT NULL,
  `pg2_date69` date DEFAULT NULL,
  `pg2_gest69` varchar(6) DEFAULT NULL,
  `pg2_ht69` varchar(6) DEFAULT NULL,
  `pg2_wt69` varchar(6) DEFAULT NULL,
  `pg2_presn69` varchar(6) DEFAULT NULL,
  `pg2_FHR69` varchar(6) DEFAULT NULL,
  `pg2_urinePr69` char(3) DEFAULT NULL,
  `pg2_urineGl69` char(3) DEFAULT NULL,
  `pg2_BP69` varchar(8) DEFAULT NULL,
  `pg2_comments69` varchar(80) DEFAULT NULL,
  `pg2_date70` date DEFAULT NULL,
  `pg2_gest70` varchar(6) DEFAULT NULL,
  `pg2_ht70` varchar(6) DEFAULT NULL,
  `pg2_wt70` varchar(6) DEFAULT NULL,
  `pg2_presn70` varchar(6) DEFAULT NULL,
  `pg2_FHR70` varchar(6) DEFAULT NULL,
  `pg2_urinePr70` char(3) DEFAULT NULL,
  `pg2_urineGl70` char(3) DEFAULT NULL,
  `pg2_BP70` varchar(8) DEFAULT NULL,
  `pg2_comments70` varchar(80) DEFAULT NULL,
  `ar2_uDate1` date DEFAULT NULL,
  `ar2_uGA1` varchar(10) DEFAULT NULL,
  `ar2_uResults1` varchar(50) DEFAULT NULL,
  `ar2_uDate2` date DEFAULT NULL,
  `ar2_uGA2` varchar(10) DEFAULT NULL,
  `ar2_uResults2` varchar(50) DEFAULT NULL,
  `ar2_uDate3` date DEFAULT NULL,
  `ar2_uGA3` varchar(10) DEFAULT NULL,
  `ar2_uResults3` varchar(50) DEFAULT NULL,
  `ar2_uDate4` date DEFAULT NULL,
  `ar2_uGA4` varchar(10) DEFAULT NULL,
  `ar2_uResults4` varchar(50) DEFAULT NULL,
  `ar2_uDate5` date DEFAULT NULL,
  `ar2_uGA5` varchar(10) DEFAULT NULL,
  `ar2_uResults5` varchar(50) DEFAULT NULL,
  `ar2_uDate6` date DEFAULT NULL,
  `ar2_uGA6` varchar(10) DEFAULT NULL,
  `ar2_uResults6` varchar(50) DEFAULT NULL,
  `ar2_uDate7` date DEFAULT NULL,
  `ar2_uGA7` varchar(10) DEFAULT NULL,
  `ar2_uResults7` varchar(50) DEFAULT NULL,
  `ar2_uDate8` date DEFAULT NULL,
  `ar2_uGA8` varchar(10) DEFAULT NULL,
  `ar2_uResults8` varchar(50) DEFAULT NULL,
  `ar2_uDate9` date DEFAULT NULL,
  `ar2_uGA9` varchar(10) DEFAULT NULL,
  `ar2_uResults9` varchar(50) DEFAULT NULL,
  `ar2_uDate10` date DEFAULT NULL,
  `ar2_uGA10` varchar(10) DEFAULT NULL,
  `ar2_uResults10` varchar(50) DEFAULT NULL,
  `ar2_uDate11` date DEFAULT NULL,
  `ar2_uGA11` varchar(10) DEFAULT NULL,
  `ar2_uResults11` varchar(50) DEFAULT NULL,
  `ar2_uDate12` date DEFAULT NULL,
  `ar2_uGA12` varchar(10) DEFAULT NULL,
  `ar2_uResults12` varchar(50) DEFAULT NULL,
  `ar2_hb` varchar(10) DEFAULT NULL,
  `ar2_bloodGroup` varchar(6) DEFAULT NULL,
  `ar2_rh` varchar(6) DEFAULT NULL,
  `ar2_labABS` varchar(10) DEFAULT NULL,
  `ar2_lab1GCT` varchar(10) DEFAULT NULL,
  `ar2_lab2GTT` varchar(14) DEFAULT NULL,
  `ar2_strep` varchar(10) DEFAULT NULL,
  `ar2_labCustom1Label` varchar(40) DEFAULT NULL,
  `ar2_labCustom1Result` varchar(40) DEFAULT NULL,
  `ar2_labCustom2Label` varchar(40) DEFAULT NULL,
  `ar2_labCustom2Result` varchar(40) DEFAULT NULL,
  `ar2_labCustom3Label` varchar(40) DEFAULT NULL,
  `ar2_labCustom3Result` varchar(40) DEFAULT NULL,
  `ar2_labCustom4Label` varchar(40) DEFAULT NULL,
  `ar2_labCustom4Result` varchar(40) DEFAULT NULL,
  `ar2_exercise` tinyint(1) DEFAULT NULL,
  `ar2_workPlan` tinyint(1) DEFAULT NULL,
  `ar2_intercourse` tinyint(1) DEFAULT NULL,
  `ar2_travel` tinyint(1) DEFAULT NULL,
  `ar2_prenatal` tinyint(1) DEFAULT NULL,
  `ar2_birth` tinyint(1) DEFAULT NULL,
  `ar2_onCall` tinyint(1) DEFAULT NULL,
  `ar2_preterm` tinyint(1) DEFAULT NULL,
  `ar2_prom` tinyint(1) DEFAULT NULL,
  `ar2_aph` tinyint(1) DEFAULT NULL,
  `ar2_fetal` tinyint(1) DEFAULT NULL,
  `ar2_admission` tinyint(1) DEFAULT NULL,
  `ar2_pain` tinyint(1) DEFAULT NULL,
  `ar2_labour` tinyint(1) DEFAULT NULL,
  `ar2_breast` tinyint(1) DEFAULT NULL,
  `ar2_circumcision` tinyint(1) DEFAULT NULL,
  `ar2_dischargePlan` tinyint(1) DEFAULT NULL,
  `ar2_car` tinyint(1) DEFAULT NULL,
  `ar2_depression` tinyint(1) DEFAULT NULL,
  `ar2_contraception` tinyint(1) DEFAULT NULL,
  `ar2_postpartumCare` tinyint(1) DEFAULT NULL,
  `pg2_signature` varchar(50) DEFAULT NULL,
  `pg2_formDate` date DEFAULT NULL,
  `pg2_signature2` varchar(50) DEFAULT NULL,
  `pg2_formDate2` date DEFAULT NULL,
  `pg1_geneticA_riskLevel` varchar(25) DEFAULT NULL,
  `pg1_geneticB_riskLevel` varchar(25) DEFAULT NULL,
  `pg1_geneticC_riskLevel` varchar(25) DEFAULT NULL,
  `pg1_labCustom3Result_riskLevel` varchar(25) DEFAULT NULL
);

--
-- Table structure for table `formPalliativeCare`
--



--
-- Table structure for table `formPeriMenopausal`
--


CREATE TABLE `formPeriMenopausal` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `lastVisited` char(1) DEFAULT NULL,
  `pName` varchar(60) DEFAULT NULL,
  `ageMenopause` char(2) DEFAULT NULL,
  `age` char(3) DEFAULT NULL,
  `orf_emYes` tinyint(1) DEFAULT NULL,
  `orf_emNo` tinyint(1) DEFAULT NULL,
  `orf_fhoYes` tinyint(1) DEFAULT NULL,
  `orf_fhoNo` tinyint(1) DEFAULT NULL,
  `orf_fhofYes` tinyint(1) DEFAULT NULL,
  `orf_fhofNo` tinyint(1) DEFAULT NULL,
  `orf_lhYes` tinyint(1) DEFAULT NULL,
  `orf_lhNo` tinyint(1) DEFAULT NULL,
  `orf_phfYes` tinyint(1) DEFAULT NULL,
  `orf_phfNo` tinyint(1) DEFAULT NULL,
  `orf_warYes` tinyint(1) DEFAULT NULL,
  `orf_warNo` tinyint(1) DEFAULT NULL,
  `orf_tsbYes` tinyint(1) DEFAULT NULL,
  `orf_tsbNo` tinyint(1) DEFAULT NULL,
  `orf_hipYes` tinyint(1) DEFAULT NULL,
  `orf_hipNo` tinyint(1) DEFAULT NULL,
  `orf_ieYes` tinyint(1) DEFAULT NULL,
  `orf_ieNo` tinyint(1) DEFAULT NULL,
  `orf_llciYes` tinyint(1) DEFAULT NULL,
  `orf_llciNo` tinyint(1) DEFAULT NULL,
  `orf_csYes` tinyint(1) DEFAULT NULL,
  `orf_csNo` tinyint(1) DEFAULT NULL,
  `orf_cYes` tinyint(1) DEFAULT NULL,
  `orf_cNo` tinyint(1) DEFAULT NULL,
  `orf_aYes` tinyint(1) DEFAULT NULL,
  `orf_aNo` tinyint(1) DEFAULT NULL,
  `orf_cptdYes` tinyint(1) DEFAULT NULL,
  `orf_cptdNo` tinyint(1) DEFAULT NULL,
  `orf_dcYes` tinyint(1) DEFAULT NULL,
  `orf_dcNo` tinyint(1) DEFAULT NULL,
  `orf_adYes` tinyint(1) DEFAULT NULL,
  `orf_adNo` tinyint(1) DEFAULT NULL,
  `orf_tmYes` tinyint(1) DEFAULT NULL,
  `orf_tmNo` tinyint(1) DEFAULT NULL,
  `orf_comments` varchar(255) DEFAULT NULL,
  `cs_mcYes` tinyint(1) DEFAULT NULL,
  `cs_mcNo` tinyint(1) DEFAULT NULL,
  `cs_mpYes` tinyint(1) DEFAULT NULL,
  `cs_mpNo` tinyint(1) DEFAULT NULL,
  `cs_hfYes` tinyint(1) DEFAULT NULL,
  `cs_hfNo` tinyint(1) DEFAULT NULL,
  `cs_vdYes` tinyint(1) DEFAULT NULL,
  `cs_vdNo` tinyint(1) DEFAULT NULL,
  `cs_dsiYes` tinyint(1) DEFAULT NULL,
  `cs_dsiNo` tinyint(1) DEFAULT NULL,
  `cs_lisaYes` tinyint(1) DEFAULT NULL,
  `cs_lisaNo` tinyint(1) DEFAULT NULL,
  `cs_lbcYes` tinyint(1) DEFAULT NULL,
  `cs_lbcNo` tinyint(1) DEFAULT NULL,
  `cs_hbiYes` tinyint(1) DEFAULT NULL,
  `cs_hbiNo` tinyint(1) DEFAULT NULL,
  `cs_comments` varchar(255) DEFAULT NULL,
  `crf_fhhdYes` tinyint(1) DEFAULT NULL,
  `crf_fhhdNo` tinyint(1) DEFAULT NULL,
  `crf_haYes` tinyint(1) DEFAULT NULL,
  `crf_haNo` tinyint(1) DEFAULT NULL,
  `crf_hchfYes` tinyint(1) DEFAULT NULL,
  `crf_hchfNo` tinyint(1) DEFAULT NULL,
  `crf_hhaYes` tinyint(1) DEFAULT NULL,
  `crf_hhaNo` tinyint(1) DEFAULT NULL,
  `crf_hdYes` tinyint(1) DEFAULT NULL,
  `crf_hdNo` tinyint(1) DEFAULT NULL,
  `crf_csYes` tinyint(1) DEFAULT NULL,
  `crf_csNo` tinyint(1) DEFAULT NULL,
  `crf_hbpYes` tinyint(1) DEFAULT NULL,
  `crf_hbpNo` tinyint(1) DEFAULT NULL,
  `crf_lhcYes` tinyint(1) DEFAULT NULL,
  `crf_lhcNo` tinyint(1) DEFAULT NULL,
  `crf_htYes` tinyint(1) DEFAULT NULL,
  `crf_htNo` tinyint(1) DEFAULT NULL,
  `crf_hlcYes` tinyint(1) DEFAULT NULL,
  `crf_hlcNo` tinyint(1) DEFAULT NULL,
  `crf_oYes` tinyint(1) DEFAULT NULL,
  `crf_oNo` tinyint(1) DEFAULT NULL,
  `crf_slYes` tinyint(1) DEFAULT NULL,
  `crf_slNo` tinyint(1) DEFAULT NULL,
  `crf_comments` varchar(255) DEFAULT NULL,
  `rh_fhbcYes` tinyint(1) DEFAULT NULL,
  `rh_fhbcNo` tinyint(1) DEFAULT NULL,
  `rh_phbcYes` tinyint(1) DEFAULT NULL,
  `rh_phbcNo` tinyint(1) DEFAULT NULL,
  `rh_phocYes` tinyint(1) DEFAULT NULL,
  `rh_phocNo` tinyint(1) DEFAULT NULL,
  `ageHysterectomy` char(2) DEFAULT NULL,
  `rh_hYes` tinyint(1) DEFAULT NULL,
  `rh_hNo` tinyint(1) DEFAULT NULL,
  `rh_hwroYes` tinyint(1) DEFAULT NULL,
  `rh_hwroNo` tinyint(1) DEFAULT NULL,
  `rh_hpcbYes` tinyint(1) DEFAULT NULL,
  `rh_hpcbNo` tinyint(1) DEFAULT NULL,
  `rh_fhadYes` tinyint(1) DEFAULT NULL,
  `rh_fhadNo` tinyint(1) DEFAULT NULL,
  `rh_fhccYes` tinyint(1) DEFAULT NULL,
  `rh_fhccNo` tinyint(1) DEFAULT NULL,
  `rh_other` varchar(60) DEFAULT NULL,
  `rh_oYes` tinyint(1) DEFAULT NULL,
  `rh_oNo` tinyint(1) DEFAULT NULL,
  `rh_comments` varchar(255) DEFAULT NULL,
  `cm_cs` varchar(30) DEFAULT NULL,
  `cm_vds` varchar(30) DEFAULT NULL,
  `cm_other1` varchar(30) DEFAULT NULL,
  `cm_o1` varchar(30) DEFAULT NULL,
  `cm_other2` varchar(30) DEFAULT NULL,
  `cm_o2` varchar(30) DEFAULT NULL,
  `cm_comments` varchar(255) DEFAULT NULL,
  `phrtYes` tinyint(1) DEFAULT NULL,
  `phrtNo` tinyint(1) DEFAULT NULL,
  `estrogenYes` tinyint(1) DEFAULT NULL,
  `estrogenNo` tinyint(1) DEFAULT NULL,
  `progesteroneYes` tinyint(1) DEFAULT NULL,
  `progesteroneNo` tinyint(1) DEFAULT NULL,
  `hrtYes` tinyint(1) DEFAULT NULL,
  `hrtNo` tinyint(1) DEFAULT NULL,
  `whenHrt` varchar(20) DEFAULT NULL,
  `reasonDiscontinued` varchar(100) DEFAULT NULL,
  `date1` date DEFAULT NULL,
  `date2` date DEFAULT NULL,
  `date3` date DEFAULT NULL,
  `date4` date DEFAULT NULL,
  `date5` date DEFAULT NULL,
  `date6` date DEFAULT NULL,
  `date7` date DEFAULT NULL,
  `date8` date DEFAULT NULL,
  `etohUse1` varchar(100) DEFAULT NULL,
  `etohUse2` varchar(100) DEFAULT NULL,
  `etohUse3` varchar(100) DEFAULT NULL,
  `etohUse4` varchar(100) DEFAULT NULL,
  `smokingCessation1` varchar(100) DEFAULT NULL,
  `smokingCessation2` varchar(100) DEFAULT NULL,
  `smokingCessation3` varchar(100) DEFAULT NULL,
  `smokingCessation4` varchar(100) DEFAULT NULL,
  `exercise1` varchar(100) DEFAULT NULL,
  `exercise2` varchar(100) DEFAULT NULL,
  `exercise3` varchar(100) DEFAULT NULL,
  `exercise4` varchar(100) DEFAULT NULL,
  `vision1` varchar(100) DEFAULT NULL,
  `vision2` varchar(100) DEFAULT NULL,
  `vision3` varchar(100) DEFAULT NULL,
  `vision4` varchar(100) DEFAULT NULL,
  `lowFat1` varchar(100) DEFAULT NULL,
  `lowFat2` varchar(100) DEFAULT NULL,
  `lowFat3` varchar(100) DEFAULT NULL,
  `lowFat4` varchar(100) DEFAULT NULL,
  `tdLast1` varchar(100) DEFAULT NULL,
  `tdLast2` varchar(100) DEFAULT NULL,
  `tdLast3` varchar(100) DEFAULT NULL,
  `tdLast4` varchar(100) DEFAULT NULL,
  `calcium1` varchar(100) DEFAULT NULL,
  `calcium2` varchar(100) DEFAULT NULL,
  `calcium3` varchar(100) DEFAULT NULL,
  `calcium4` varchar(100) DEFAULT NULL,
  `flu1` varchar(100) DEFAULT NULL,
  `flu2` varchar(100) DEFAULT NULL,
  `flu3` varchar(100) DEFAULT NULL,
  `flu4` varchar(100) DEFAULT NULL,
  `vitaminD1` varchar(100) DEFAULT NULL,
  `vitaminD2` varchar(100) DEFAULT NULL,
  `vitaminD3` varchar(100) DEFAULT NULL,
  `vitaminD4` varchar(100) DEFAULT NULL,
  `pneumovaxDate` date DEFAULT NULL,
  `pneumovax1` varchar(100) DEFAULT NULL,
  `pneumovax2` varchar(100) DEFAULT NULL,
  `pneumovax3` varchar(100) DEFAULT NULL,
  `pneumovax4` varchar(100) DEFAULT NULL,
  `papSmear1` varchar(100) DEFAULT NULL,
  `papSmear2` varchar(100) DEFAULT NULL,
  `papSmear3` varchar(100) DEFAULT NULL,
  `papSmear4` varchar(100) DEFAULT NULL,
  `height1` varchar(100) DEFAULT NULL,
  `height2` varchar(100) DEFAULT NULL,
  `height3` varchar(100) DEFAULT NULL,
  `height4` varchar(100) DEFAULT NULL,
  `bloodPressure1` varchar(100) DEFAULT NULL,
  `bloodPressure2` varchar(100) DEFAULT NULL,
  `bloodPressure3` varchar(100) DEFAULT NULL,
  `bloodPressure4` varchar(100) DEFAULT NULL,
  `weight1` varchar(100) DEFAULT NULL,
  `weight2` varchar(100) DEFAULT NULL,
  `weight3` varchar(100) DEFAULT NULL,
  `weight4` varchar(100) DEFAULT NULL,
  `cbe1` varchar(100) DEFAULT NULL,
  `cbe2` varchar(100) DEFAULT NULL,
  `cbe3` varchar(100) DEFAULT NULL,
  `cbe4` varchar(100) DEFAULT NULL,
  `bmd1` varchar(100) DEFAULT NULL,
  `bmd2` varchar(100) DEFAULT NULL,
  `bmd3` varchar(100) DEFAULT NULL,
  `bmd4` varchar(100) DEFAULT NULL,
  `mammography1` varchar(100) DEFAULT NULL,
  `mammography2` varchar(100) DEFAULT NULL,
  `mammography3` varchar(100) DEFAULT NULL,
  `mammography4` varchar(100) DEFAULT NULL,
  `other1` varchar(30) DEFAULT NULL,
  `other11` varchar(100) DEFAULT NULL,
  `other12` varchar(100) DEFAULT NULL,
  `other13` varchar(100) DEFAULT NULL,
  `other14` varchar(100) DEFAULT NULL,
  `other2` varchar(30) DEFAULT NULL,
  `other21` varchar(100) DEFAULT NULL,
  `other22` varchar(100) DEFAULT NULL,
  `other23` varchar(100) DEFAULT NULL,
  `other24` varchar(100) DEFAULT NULL,
  `other3` varchar(30) DEFAULT NULL,
  `other31` varchar(100) DEFAULT NULL,
  `other32` varchar(100) DEFAULT NULL,
  `other33` varchar(100) DEFAULT NULL,
  `other34` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formRhImmuneGlobulin`
--


CREATE TABLE `formRhImmuneGlobulin` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `workflowId` int(10) DEFAULT NULL,
  `state` char(1) DEFAULT NULL,
  `dateOfReferral` datetime DEFAULT NULL,
  `edd` datetime DEFAULT NULL,
  `motherSurname` varchar(30) DEFAULT NULL,
  `motherFirstname` varchar(30) DEFAULT NULL,
  `dob` date DEFAULT NULL,
  `motherHIN` varchar(20) DEFAULT NULL,
  `motherVC` varchar(30) DEFAULT NULL,
  `motherAddress` varchar(60) DEFAULT NULL,
  `motherCity` varchar(60) DEFAULT NULL,
  `motherProvince` varchar(60) DEFAULT NULL,
  `motherPostalCode` varchar(10) DEFAULT NULL,
  `motherABO` char(3) DEFAULT NULL,
  `motherRHtype` varchar(4) DEFAULT NULL,
  `hospitalForDelivery` varchar(255) DEFAULT NULL,
  `refPhySurname` varchar(30) DEFAULT NULL,
  `refPhyFirstname` varchar(30) DEFAULT NULL,
  `refPhyAddress` varchar(60) DEFAULT NULL,
  `refPhyCity` varchar(60) DEFAULT NULL,
  `refPhyProvince` varchar(60) DEFAULT NULL,
  `refPhyPostalCode` varchar(10) DEFAULT NULL,
  `refPhyPhone` varchar(20) DEFAULT NULL,
  `refPhyFax` varchar(20) DEFAULT NULL,
  `comments` text,
  `obsHisG` varchar(10) DEFAULT NULL,
  `obsHisP` varchar(10) DEFAULT NULL,
  `obsHisT` varchar(10) DEFAULT NULL,
  `obsHisA` varchar(10) DEFAULT NULL,
  `obsHisL` varchar(10) DEFAULT NULL,
  `obsHisTubMolPregYes` tinyint(1) DEFAULT NULL,
  `obsHisTubMolPregNo` tinyint(1) DEFAULT NULL,
  `obsHisMisAbortionYes` tinyint(1) DEFAULT NULL,
  `obsHisMisAbortionNo` tinyint(1) DEFAULT NULL,
  `obsHisReceiveAntiDYes` tinyint(1) DEFAULT NULL,
  `obsHisReceiveAntiDNo` tinyint(1) DEFAULT NULL,
  `motherAntibodies` varchar(4) DEFAULT NULL,
  `fatherABO` char(3) DEFAULT NULL,
  `fatherRHtype` varchar(4) DEFAULT NULL,
  `pmHisBlClDisordersYes` tinyint(1) DEFAULT NULL,
  `pmHisBlClDisordersNo` tinyint(1) DEFAULT NULL,
  `pmHisBlClDisordersComment` text,
  `pmHisBlPlTransfusYes` tinyint(1) DEFAULT NULL,
  `pmHisBlPlTransfusNo` tinyint(1) DEFAULT NULL,
  `pmHisBlPlTransfusComment` text,
  `allReactionsYes` tinyint(1) DEFAULT NULL,
  `allReactionsNo` tinyint(1) DEFAULT NULL,
  `allReactionsComment` text,
  `curPregDueDateChangeYes` tinyint(1) DEFAULT NULL,
  `curPregDueDateChangeNo` tinyint(1) DEFAULT NULL,
  `curPregProceduresYes` tinyint(1) DEFAULT NULL,
  `curPregProceduresNo` tinyint(1) DEFAULT NULL,
  `curPregProceduresComment` text,
  `curPregBleedingYes` tinyint(1) DEFAULT NULL,
  `curPregBleedingNo` tinyint(1) DEFAULT NULL,
  `curPregBleedingComment` text,
  `curPregBleedingContYes` tinyint(1) DEFAULT NULL,
  `curPregBleedingContNo` tinyint(1) DEFAULT NULL,
  `curPregTraumaYes` tinyint(1) DEFAULT NULL,
  `curPregTraumaNo` tinyint(1) DEFAULT NULL,
  `curPregAntiDYes` tinyint(1) DEFAULT NULL,
  `curPregAntiDNo` tinyint(1) DEFAULT NULL,
  `curPregAntiDComment` text,
  `curPregAntiDReactionYes` tinyint(1) DEFAULT NULL,
  `curPregAntiDReactionNo` tinyint(1) DEFAULT NULL,
  `curPregBloodDrawnYes` tinyint(1) DEFAULT NULL,
  `curPregBloodDrawnNo` tinyint(1) DEFAULT NULL,
  `curPregDueDateChangeComment` text,
  `famPhySurname` varchar(30) DEFAULT NULL,
  `famPhyFirstname` varchar(30) DEFAULT NULL,
  `famPhyAddress` varchar(60) DEFAULT NULL,
  `famPhyCity` varchar(60) DEFAULT NULL,
  `famPhyProvince` varchar(60) DEFAULT NULL,
  `famPhyPostalCode` varchar(10) DEFAULT NULL,
  `famPhyPhone` varchar(20) DEFAULT NULL,
  `famPhyFax` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formRourke`
--



--
-- Table structure for table `formRourke2006`
--


CREATE TABLE `formRourke2006` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `c_lastVisited` char(3) DEFAULT NULL,
  `c_birthRemarks` text,
  `c_riskFactors` text,
  `c_famHistory` text,
  `c_pName` varchar(60) DEFAULT NULL,
  `c_birthDate` date DEFAULT NULL,
  `c_length` varchar(6) DEFAULT NULL,
  `c_headCirc` varchar(6) DEFAULT NULL,
  `c_birthWeight` varchar(7) DEFAULT NULL,
  `c_dischargeWeight` varchar(7) DEFAULT NULL,
  `p1_date1w` date DEFAULT NULL,
  `p1_date2w` date DEFAULT NULL,
  `p1_date1m` date DEFAULT NULL,
  `p1_ht1w` varchar(5) DEFAULT NULL,
  `p1_wt1w` varchar(5) DEFAULT NULL,
  `p1_hc1w` varchar(5) DEFAULT NULL,
  `p1_ht2w` varchar(5) DEFAULT NULL,
  `p1_wt2w` varchar(5) DEFAULT NULL,
  `p1_hc2w` varchar(5) DEFAULT NULL,
  `p1_ht1m` varchar(5) DEFAULT NULL,
  `p1_wt1m` varchar(5) DEFAULT NULL,
  `p1_hc1m` varchar(5) DEFAULT NULL,
  `p1_pConcern1w` text,
  `p1_pConcern2w` text,
  `p1_pConcern1m` text,
  `p1_breastFeeding1w` tinyint(1) DEFAULT NULL,
  `p1_formulaFeeding1w` tinyint(1) DEFAULT NULL,
  `p1_stoolUrine1w` tinyint(1) DEFAULT NULL,
  `p1_nutrition1w` varchar(250) DEFAULT NULL,
  `p1_breastFeeding2w` tinyint(1) DEFAULT NULL,
  `p1_formulaFeeding2w` tinyint(1) DEFAULT NULL,
  `p1_stoolUrine2w` tinyint(1) DEFAULT NULL,
  `p1_nutrition2w` varchar(250) DEFAULT NULL,
  `p1_breastFeeding1m` tinyint(1) DEFAULT NULL,
  `p1_formulaFeeding1m` tinyint(1) DEFAULT NULL,
  `p1_stoolUrine1m` tinyint(1) DEFAULT NULL,
  `p1_nutrition1m` varchar(250) DEFAULT NULL,
  `p1_carSeatOk` tinyint(1) DEFAULT NULL,
  `p1_carSeatNo` tinyint(1) DEFAULT NULL,
  `p1_sleepPosOk` tinyint(1) DEFAULT NULL,
  `p1_sleepPosNo` tinyint(1) DEFAULT NULL,
  `p1_cribSafetyOk` tinyint(1) DEFAULT NULL,
  `p1_cribSafetyNo` tinyint(1) DEFAULT NULL,
  `p1_firearmSafetyOk` tinyint(1) DEFAULT NULL,
  `p1_firearmSafetyNo` tinyint(1) DEFAULT NULL,
  `p1_smokeSafetyOk` tinyint(1) DEFAULT NULL,
  `p1_smokeSafetyNo` tinyint(1) DEFAULT NULL,
  `p1_hotWaterOk` tinyint(1) DEFAULT NULL,
  `p1_hotWaterNo` tinyint(1) DEFAULT NULL,
  `p1_safeToysOk` tinyint(1) DEFAULT NULL,
  `p1_safeToysNo` tinyint(1) DEFAULT NULL,
  `p1_sleepCryOk` tinyint(1) DEFAULT NULL,
  `p1_sleepCryNo` tinyint(1) DEFAULT NULL,
  `p1_soothabilityOk` tinyint(1) DEFAULT NULL,
  `p1_soothabilityNo` tinyint(1) DEFAULT NULL,
  `p1_homeVisitOk` tinyint(1) DEFAULT NULL,
  `p1_homeVisitNo` tinyint(1) DEFAULT NULL,
  `p1_bondingOk` tinyint(1) DEFAULT NULL,
  `p1_bondingNo` tinyint(1) DEFAULT NULL,
  `p1_pFatigueOk` tinyint(1) DEFAULT NULL,
  `p1_pFatigueNo` tinyint(1) DEFAULT NULL,
  `p1_famConflictOk` tinyint(1) DEFAULT NULL,
  `p1_famConflictNo` tinyint(1) DEFAULT NULL,
  `p1_siblingsOk` tinyint(1) DEFAULT NULL,
  `p1_siblingsNo` tinyint(1) DEFAULT NULL,
  `p1_2ndSmokeOk` tinyint(1) DEFAULT NULL,
  `p1_2ndSmokeNo` tinyint(1) DEFAULT NULL,
  `p1_altMedOk` tinyint(1) DEFAULT NULL,
  `p1_altMedNo` tinyint(1) DEFAULT NULL,
  `p1_pacifierOk` tinyint(1) DEFAULT NULL,
  `p1_pacifierNo` tinyint(1) DEFAULT NULL,
  `p1_feverOk` tinyint(1) DEFAULT NULL,
  `p1_feverNo` tinyint(1) DEFAULT NULL,
  `p1_tmpControlOk` tinyint(1) DEFAULT NULL,
  `p1_tmpControlNo` tinyint(1) DEFAULT NULL,
  `p1_sunExposureOk` tinyint(1) DEFAULT NULL,
  `p1_sunExposureNo` tinyint(1) DEFAULT NULL,
  `p1_development1w` text,
  `p1_development2w` text,
  `p1_development1m` text,
  `p1_focusGaze1mOk` tinyint(1) DEFAULT NULL,
  `p1_focusGaze1mNo` tinyint(1) DEFAULT NULL,
  `p1_startles1mOk` tinyint(1) DEFAULT NULL,
  `p1_startles1mNo` tinyint(1) DEFAULT NULL,
  `p1_sucks1mOk` tinyint(1) DEFAULT NULL,
  `p1_sucks1mNo` tinyint(1) DEFAULT NULL,
  `p1_noParentsConcerns1mOk` tinyint(1) DEFAULT NULL,
  `p1_noParentsConcerns1mNo` tinyint(1) DEFAULT NULL,
  `p1_skin1w` tinyint(1) DEFAULT NULL,
  `p1_fontanelles1w` tinyint(1) DEFAULT NULL,
  `p1_eyes1w` tinyint(1) DEFAULT NULL,
  `p1_ears1w` tinyint(1) DEFAULT NULL,
  `p1_heartLungs1w` tinyint(1) DEFAULT NULL,
  `p1_umbilicus1w` tinyint(1) DEFAULT NULL,
  `p1_femoralPulses1w` tinyint(1) DEFAULT NULL,
  `p1_hips1w` tinyint(1) DEFAULT NULL,
  `p1_muscleTone1w` tinyint(1) DEFAULT NULL,
  `p1_testicles1w` tinyint(1) DEFAULT NULL,
  `p1_maleUrinary1w` tinyint(1) DEFAULT NULL,
  `p1_skin2w` tinyint(1) DEFAULT NULL,
  `p1_fontanelles2w` tinyint(1) DEFAULT NULL,
  `p1_eyes2w` tinyint(1) DEFAULT NULL,
  `p1_ears2w` tinyint(1) DEFAULT NULL,
  `p1_heartLungs2w` tinyint(1) DEFAULT NULL,
  `p1_umbilicus2w` tinyint(1) DEFAULT NULL,
  `p1_femoralPulses2w` tinyint(1) DEFAULT NULL,
  `p1_hips2w` tinyint(1) DEFAULT NULL,
  `p1_muscleTone2w` tinyint(1) DEFAULT NULL,
  `p1_testicles2w` tinyint(1) DEFAULT NULL,
  `p1_maleUrinary2w` tinyint(1) DEFAULT NULL,
  `p1_fontanelles1m` tinyint(1) DEFAULT NULL,
  `p1_eyes1m` tinyint(1) DEFAULT NULL,
  `p1_corneal1m` tinyint(1) DEFAULT NULL,
  `p1_hearing1m` tinyint(1) DEFAULT NULL,
  `p1_heart1m` tinyint(1) DEFAULT NULL,
  `p1_hips1m` tinyint(1) DEFAULT NULL,
  `p1_muscleTone1m` tinyint(1) DEFAULT NULL,
  `p1_pkuThyroid1w` tinyint(1) DEFAULT NULL,
  `p1_hemoScreen1w` tinyint(1) DEFAULT NULL,
  `p1_problems1w` text,
  `p1_problems2w` text,
  `p1_problems1m` text,
  `p1_hepatitisVaccine1w` tinyint(1) DEFAULT NULL,
  `p1_hepatitisVaccine1m` tinyint(1) DEFAULT NULL,
  `p1_signature2w` varchar(250) DEFAULT NULL,
  `p2_date2m` date DEFAULT NULL,
  `p2_date4m` date DEFAULT NULL,
  `p2_date6m` date DEFAULT NULL,
  `p2_ht2m` varchar(5) DEFAULT NULL,
  `p2_wt2m` varchar(5) DEFAULT NULL,
  `p2_hc2m` varchar(5) DEFAULT NULL,
  `p2_ht4m` varchar(5) DEFAULT NULL,
  `p2_wt4m` varchar(5) DEFAULT NULL,
  `p2_hc4m` varchar(5) DEFAULT NULL,
  `p2_ht6m` varchar(5) DEFAULT NULL,
  `p2_wt6m` varchar(5) DEFAULT NULL,
  `p2_hc6m` varchar(5) DEFAULT NULL,
  `p2_pConcern2m` text,
  `p2_pConcern4m` text,
  `p2_pConcern6m` text,
  `p2_nutrition2m` text,
  `p2_breastFeeding2m` tinyint(1) DEFAULT NULL,
  `p2_formulaFeeding2m` tinyint(1) DEFAULT NULL,
  `p2_nutrition4m` text,
  `p2_breastFeeding4m` tinyint(1) DEFAULT NULL,
  `p2_formulaFeeding4m` tinyint(1) DEFAULT NULL,
  `p2_breastFeeding6m` tinyint(1) DEFAULT NULL,
  `p2_formulaFeeding6m` tinyint(1) DEFAULT NULL,
  `p2_bottle6m` tinyint(1) DEFAULT NULL,
  `p2_liquids6m` tinyint(1) DEFAULT NULL,
  `p2_iron6m` tinyint(1) DEFAULT NULL,
  `p2_vegFruit6m` tinyint(1) DEFAULT NULL,
  `p2_egg6m` tinyint(1) DEFAULT NULL,
  `p2_choking6m` tinyint(1) DEFAULT NULL,
  `p2_carSeatOk` tinyint(1) DEFAULT NULL,
  `p2_carSeatNo` tinyint(1) DEFAULT NULL,
  `p2_sleepPosOk` tinyint(1) DEFAULT NULL,
  `p2_sleepPosNo` tinyint(1) DEFAULT NULL,
  `p2_poisonsOk` tinyint(1) DEFAULT NULL,
  `p2_poisonsNo` tinyint(1) DEFAULT NULL,
  `p2_firearmSafetyOk` tinyint(1) DEFAULT NULL,
  `p2_firearmSafetyNo` tinyint(1) DEFAULT NULL,
  `p2_electricOk` tinyint(1) DEFAULT NULL,
  `p2_electricNo` tinyint(1) DEFAULT NULL,
  `p2_smokeSafetyOk` tinyint(1) DEFAULT NULL,
  `p2_smokeSafetyNo` tinyint(1) DEFAULT NULL,
  `p2_hotWaterOk` tinyint(1) DEFAULT NULL,
  `p2_hotWaterNo` tinyint(1) DEFAULT NULL,
  `p2_fallsOk` tinyint(1) DEFAULT NULL,
  `p2_fallsNo` tinyint(1) DEFAULT NULL,
  `p2_safeToysOk` tinyint(1) DEFAULT NULL,
  `p2_safeToysNo` tinyint(1) DEFAULT NULL,
  `p2_sleepCryOk` tinyint(1) DEFAULT NULL,
  `p2_sleepCryNo` tinyint(1) DEFAULT NULL,
  `p2_soothabilityOk` tinyint(1) DEFAULT NULL,
  `p2_soothabilityNo` tinyint(1) DEFAULT NULL,
  `p2_homeVisitOk` tinyint(1) DEFAULT NULL,
  `p2_homeVisitNo` tinyint(1) DEFAULT NULL,
  `p2_bondingOk` tinyint(1) DEFAULT NULL,
  `p2_bondingNo` tinyint(1) DEFAULT NULL,
  `p2_pFatigueOk` tinyint(1) DEFAULT NULL,
  `p2_pFatigueNo` tinyint(1) DEFAULT NULL,
  `p2_famConflictOk` tinyint(1) DEFAULT NULL,
  `p2_famConflictNo` tinyint(1) DEFAULT NULL,
  `p2_siblingsOk` tinyint(1) DEFAULT NULL,
  `p2_siblingsNo` tinyint(1) DEFAULT NULL,
  `p2_childCareOk` tinyint(1) DEFAULT NULL,
  `p2_childCareNo` tinyint(1) DEFAULT NULL,
  `p2_2ndSmokeOk` tinyint(1) DEFAULT NULL,
  `p2_2ndSmokeNo` tinyint(1) DEFAULT NULL,
  `p2_teethingOk` tinyint(1) DEFAULT NULL,
  `p2_teethingNo` tinyint(1) DEFAULT NULL,
  `p2_altMedOk` tinyint(1) DEFAULT NULL,
  `p2_altMedNo` tinyint(1) DEFAULT NULL,
  `p2_pacifierOk` tinyint(1) DEFAULT NULL,
  `p2_pacifierNo` tinyint(1) DEFAULT NULL,
  `p2_tmpControlOk` tinyint(1) DEFAULT NULL,
  `p2_tmpControlNo` tinyint(1) DEFAULT NULL,
  `p2_feverOk` tinyint(1) DEFAULT NULL,
  `p2_feverNo` tinyint(1) DEFAULT NULL,
  `p2_sunExposureOk` tinyint(1) DEFAULT NULL,
  `p2_sunExposureNo` tinyint(1) DEFAULT NULL,
  `p2_pesticidesOk` tinyint(1) DEFAULT NULL,
  `p2_pesticidesNo` tinyint(1) DEFAULT NULL,
  `p2_development2m` text,
  `p2_eyesOk` tinyint(1) DEFAULT NULL,
  `p2_eyesNo` tinyint(1) DEFAULT NULL,
  `p2_soundsOk` tinyint(1) DEFAULT NULL,
  `p2_soundsNo` tinyint(1) DEFAULT NULL,
  `p2_headUpOk` tinyint(1) DEFAULT NULL,
  `p2_headUpNo` tinyint(1) DEFAULT NULL,
  `p2_cuddledOk` tinyint(1) DEFAULT NULL,
  `p2_cuddledNo` tinyint(1) DEFAULT NULL,
  `p2_smilesOk` tinyint(1) DEFAULT NULL,
  `p2_smilesNo` tinyint(1) DEFAULT NULL,
  `p2_noParentsConcerns2mOk` tinyint(1) DEFAULT NULL,
  `p2_noParentsConcerns2mNo` tinyint(1) DEFAULT NULL,
  `p2_development4m` text,
  `p2_turnsHeadOk` tinyint(1) DEFAULT NULL,
  `p2_turnsHeadNo` tinyint(1) DEFAULT NULL,
  `p2_laughsOk` tinyint(1) DEFAULT NULL,
  `p2_laughsNo` tinyint(1) DEFAULT NULL,
  `p2_headSteadyOk` tinyint(1) DEFAULT NULL,
  `p2_headSteadyNo` tinyint(1) DEFAULT NULL,
  `p2_graspOk` tinyint(1) DEFAULT NULL,
  `p2_graspNo` tinyint(1) DEFAULT NULL,
  `p2_noParentsConcerns4mOk` tinyint(1) DEFAULT NULL,
  `p2_noParentsConcerns4mNo` tinyint(1) DEFAULT NULL,
  `p2_development6m` text,
  `p2_movingObjOk` tinyint(1) DEFAULT NULL,
  `p2_movingObjNo` tinyint(1) DEFAULT NULL,
  `p2_looksOk` tinyint(1) DEFAULT NULL,
  `p2_looksNo` tinyint(1) DEFAULT NULL,
  `p2_babblesOk` tinyint(1) DEFAULT NULL,
  `p2_babblesNo` tinyint(1) DEFAULT NULL,
  `p2_rollsOk` tinyint(1) DEFAULT NULL,
  `p2_rollsNo` tinyint(1) DEFAULT NULL,
  `p2_sitsOk` tinyint(1) DEFAULT NULL,
  `p2_sitsNo` tinyint(1) DEFAULT NULL,
  `p2_handToMouthOk` tinyint(1) DEFAULT NULL,
  `p2_handToMouthNo` tinyint(1) DEFAULT NULL,
  `p2_noParentsConcerns6mOk` tinyint(1) DEFAULT NULL,
  `p2_noParentsConcerns6mNo` tinyint(1) DEFAULT NULL,
  `p2_fontanelles2m` tinyint(1) DEFAULT NULL,
  `p2_eyes2m` tinyint(1) DEFAULT NULL,
  `p2_corneal2m` tinyint(1) DEFAULT NULL,
  `p2_hearing2m` tinyint(1) DEFAULT NULL,
  `p2_heart2m` tinyint(1) DEFAULT NULL,
  `p2_hips2m` tinyint(1) DEFAULT NULL,
  `p2_muscleTone2m` tinyint(1) DEFAULT NULL,
  `p2_eyes4m` tinyint(1) DEFAULT NULL,
  `p2_corneal4m` tinyint(1) DEFAULT NULL,
  `p2_hearing4m` tinyint(1) DEFAULT NULL,
  `p2_hips4m` tinyint(1) DEFAULT NULL,
  `p2_muscleTone4m` tinyint(1) DEFAULT NULL,
  `p2_fontanelles6m` tinyint(1) DEFAULT NULL,
  `p2_eyes6m` tinyint(1) DEFAULT NULL,
  `p2_corneal6m` tinyint(1) DEFAULT NULL,
  `p2_hearing6m` tinyint(1) DEFAULT NULL,
  `p2_hips6m` tinyint(1) DEFAULT NULL,
  `p2_muscleTone6m` tinyint(1) DEFAULT NULL,
  `p2_problems2m` text,
  `p2_problems4m` text,
  `p2_problems6m` text,
  `p2_tb6m` tinyint(1) DEFAULT NULL,
  `p2_hepatitisVaccine6m` tinyint(1) DEFAULT NULL,
  `p2_signature2m` varchar(250) DEFAULT NULL,
  `p2_signature4m` varchar(250) DEFAULT NULL,
  `p3_date9m` date DEFAULT NULL,
  `p3_date12m` date DEFAULT NULL,
  `p3_date15m` date DEFAULT NULL,
  `p3_ht9m` varchar(5) DEFAULT NULL,
  `p3_wt9m` varchar(5) DEFAULT NULL,
  `p3_hc9m` varchar(5) DEFAULT NULL,
  `p3_ht12m` varchar(5) DEFAULT NULL,
  `p3_wt12m` varchar(5) DEFAULT NULL,
  `p3_hc12m` varchar(5) DEFAULT NULL,
  `p3_ht15m` varchar(5) DEFAULT NULL,
  `p3_wt15m` varchar(5) DEFAULT NULL,
  `p3_hc15m` varchar(5) DEFAULT NULL,
  `p3_pConcern9m` text,
  `p3_pConcern12m` text,
  `p3_pConcern15m` text,
  `p3_breastFeeding9m` tinyint(1) DEFAULT NULL,
  `p3_formulaFeeding9m` tinyint(1) DEFAULT NULL,
  `p3_bottle9m` tinyint(1) DEFAULT NULL,
  `p3_liquids9m` tinyint(1) DEFAULT NULL,
  `p3_cereal9m` tinyint(1) DEFAULT NULL,
  `p3_introCowMilk9m` tinyint(1) DEFAULT NULL,
  `p3_egg9m` tinyint(1) DEFAULT NULL,
  `p3_choking9m` tinyint(1) DEFAULT NULL,
  `p3_nutrition12m` text,
  `p3_breastFeeding12m` tinyint(1) DEFAULT NULL,
  `p3_homoMilk12m` tinyint(1) DEFAULT NULL,
  `p3_cup12m` tinyint(1) DEFAULT NULL,
  `p3_appetite12m` tinyint(1) DEFAULT NULL,
  `p3_choking12m` tinyint(1) DEFAULT NULL,
  `p3_nutrition15m` text,
  `p3_breastFeeding15m` tinyint(1) DEFAULT NULL,
  `p3_homoMilk15m` tinyint(1) DEFAULT NULL,
  `p3_choking15m` tinyint(1) DEFAULT NULL,
  `p3_cup15m` tinyint(1) DEFAULT NULL,
  `p3_carSeatOk` tinyint(1) DEFAULT NULL,
  `p3_carSeatNo` tinyint(1) DEFAULT NULL,
  `p3_poisonsOk` tinyint(1) DEFAULT NULL,
  `p3_poisonsNo` tinyint(1) DEFAULT NULL,
  `p3_firearmSafetyOk` tinyint(1) DEFAULT NULL,
  `p3_firearmSafetyNo` tinyint(1) DEFAULT NULL,
  `p3_smokeSafetyOk` tinyint(1) DEFAULT NULL,
  `p3_smokeSafetyNo` tinyint(1) DEFAULT NULL,
  `p3_hotWaterOk` tinyint(1) DEFAULT NULL,
  `p3_hotWaterNo` tinyint(1) DEFAULT NULL,
  `p3_electricOk` tinyint(1) DEFAULT NULL,
  `p3_electricNo` tinyint(1) DEFAULT NULL,
  `p3_fallsOk` tinyint(1) DEFAULT NULL,
  `p3_fallsNo` tinyint(1) DEFAULT NULL,
  `p3_safeToysOk` tinyint(1) DEFAULT NULL,
  `p3_safeToysNo` tinyint(1) DEFAULT NULL,
  `p3_sleepCryOk` tinyint(1) DEFAULT NULL,
  `p3_sleepCryNo` tinyint(1) DEFAULT NULL,
  `p3_soothabilityOk` tinyint(1) DEFAULT NULL,
  `p3_soothabilityNo` tinyint(1) DEFAULT NULL,
  `p3_homeVisitOk` tinyint(1) DEFAULT NULL,
  `p3_homeVisitNo` tinyint(1) DEFAULT NULL,
  `p3_parentingOk` tinyint(1) DEFAULT NULL,
  `p3_parentingNo` tinyint(1) DEFAULT NULL,
  `p3_pFatigueOk` tinyint(1) DEFAULT NULL,
  `p3_pFatigueNo` tinyint(1) DEFAULT NULL,
  `p3_famConflictOk` tinyint(1) DEFAULT NULL,
  `p3_famConflictNo` tinyint(1) DEFAULT NULL,
  `p3_siblingsOk` tinyint(1) DEFAULT NULL,
  `p3_siblingsNo` tinyint(1) DEFAULT NULL,
  `p3_childCareOk` tinyint(1) DEFAULT NULL,
  `p3_childCareNo` tinyint(1) DEFAULT NULL,
  `p3_2ndSmokeOk` tinyint(1) DEFAULT NULL,
  `p3_2ndSmokeNo` tinyint(1) DEFAULT NULL,
  `p3_teethingOk` tinyint(1) DEFAULT NULL,
  `p3_teethingNo` tinyint(1) DEFAULT NULL,
  `p3_altMedOk` tinyint(1) DEFAULT NULL,
  `p3_altMedNo` tinyint(1) DEFAULT NULL,
  `p3_pacifierOk` tinyint(1) DEFAULT NULL,
  `p3_pacifierNo` tinyint(1) DEFAULT NULL,
  `p3_feverOk` tinyint(1) DEFAULT NULL,
  `p3_feverNo` tinyint(1) DEFAULT NULL,
  `p3_activeOk` tinyint(1) DEFAULT NULL,
  `p3_activeNo` tinyint(1) DEFAULT NULL,
  `p3_readingOk` tinyint(1) DEFAULT NULL,
  `p3_readingNo` tinyint(1) DEFAULT NULL,
  `p3_footwearOk` tinyint(1) DEFAULT NULL,
  `p3_footwearNo` tinyint(1) DEFAULT NULL,
  `p3_sunExposureOk` tinyint(1) DEFAULT NULL,
  `p3_sunExposureNo` tinyint(1) DEFAULT NULL,
  `p3_checkSerumOk` tinyint(1) DEFAULT NULL,
  `p3_checkSerumNo` tinyint(1) DEFAULT NULL,
  `p3_pesticidesOk` tinyint(1) DEFAULT NULL,
  `p3_pesticidesNo` tinyint(1) DEFAULT NULL,
  `p3_development9m` text,
  `p3_hiddenToyOk` tinyint(1) DEFAULT NULL,
  `p3_hiddenToyNo` tinyint(1) DEFAULT NULL,
  `p3_soundsOk` tinyint(1) DEFAULT NULL,
  `p3_soundsNo` tinyint(1) DEFAULT NULL,
  `p3_makeSoundsOk` tinyint(1) DEFAULT NULL,
  `p3_makeSoundsNo` tinyint(1) DEFAULT NULL,
  `p3_sitsOk` tinyint(1) DEFAULT NULL,
  `p3_sitsNo` tinyint(1) DEFAULT NULL,
  `p3_standsOk` tinyint(1) DEFAULT NULL,
  `p3_standsNo` tinyint(1) DEFAULT NULL,
  `p3_thumbOk` tinyint(1) DEFAULT NULL,
  `p3_thumbNo` tinyint(1) DEFAULT NULL,
  `p3_pickedupOk` tinyint(1) DEFAULT NULL,
  `p3_pickedupNo` tinyint(1) DEFAULT NULL,
  `p3_noParentsConcerns9mOk` tinyint(1) DEFAULT NULL,
  `p3_noParentsConcerns9mNo` tinyint(1) DEFAULT NULL,
  `p3_development12m` text,
  `p3_respondsOk` tinyint(1) DEFAULT NULL,
  `p3_respondsNo` tinyint(1) DEFAULT NULL,
  `p3_simpleRequestsOk` tinyint(1) DEFAULT NULL,
  `p3_simpleRequestsNo` tinyint(1) DEFAULT NULL,
  `p3_chattersOk` tinyint(1) DEFAULT NULL,
  `p3_chattersNo` tinyint(1) DEFAULT NULL,
  `p3_shufflesOk` tinyint(1) DEFAULT NULL,
  `p3_shufflesNo` tinyint(1) DEFAULT NULL,
  `p3_pull2standOk` tinyint(1) DEFAULT NULL,
  `p3_pull2standNo` tinyint(1) DEFAULT NULL,
  `p3_emotionsOk` tinyint(1) DEFAULT NULL,
  `p3_emotionsNo` tinyint(1) DEFAULT NULL,
  `p3_noParentsConcerns12mOk` tinyint(1) DEFAULT NULL,
  `p3_noParentsConcerns12mNo` tinyint(1) DEFAULT NULL,
  `p3_says2wordsOk` tinyint(1) DEFAULT NULL,
  `p3_says2wordsNo` tinyint(1) DEFAULT NULL,
  `p3_reachesOk` tinyint(1) DEFAULT NULL,
  `p3_reachesNo` tinyint(1) DEFAULT NULL,
  `p3_fingerFoodsOk` tinyint(1) DEFAULT NULL,
  `p3_fingerFoodsNo` tinyint(1) DEFAULT NULL,
  `p3_crawlsStairsOk` tinyint(1) DEFAULT NULL,
  `p3_crawlsStairsNo` tinyint(1) DEFAULT NULL,
  `p3_squatsOk` tinyint(1) DEFAULT NULL,
  `p3_squatsNo` tinyint(1) DEFAULT NULL,
  `p3_tieShoesOk` tinyint(1) DEFAULT NULL,
  `p3_tieShoesNo` tinyint(1) DEFAULT NULL,
  `p3_stacks2blocksOk` tinyint(1) DEFAULT NULL,
  `p3_stacks2blocksNo` tinyint(1) DEFAULT NULL,
  `p3_howToReactOk` tinyint(1) DEFAULT NULL,
  `p3_howToReactNo` tinyint(1) DEFAULT NULL,
  `p3_noParentsConcerns15mOk` tinyint(1) DEFAULT NULL,
  `p3_noParentsConcerns15mNo` tinyint(1) DEFAULT NULL,
  `p3_eyes9m` tinyint(1) DEFAULT NULL,
  `p3_corneal9m` tinyint(1) DEFAULT NULL,
  `p3_hearing9m` tinyint(1) DEFAULT NULL,
  `p3_hips9m` tinyint(1) DEFAULT NULL,
  `p3_eyes12m` tinyint(1) DEFAULT NULL,
  `p3_corneal12m` tinyint(1) DEFAULT NULL,
  `p3_hearing12m` tinyint(1) DEFAULT NULL,
  `p3_tonsil12m` tinyint(1) DEFAULT NULL,
  `p3_hips12m` tinyint(1) DEFAULT NULL,
  `p3_eyes15m` tinyint(1) DEFAULT NULL,
  `p3_corneal15m` tinyint(1) DEFAULT NULL,
  `p3_hearing15m` tinyint(1) DEFAULT NULL,
  `p3_tonsil15m` tinyint(1) DEFAULT NULL,
  `p3_hips15m` tinyint(1) DEFAULT NULL,
  `p3_problems9m` text,
  `p3_problems12m` text,
  `p3_problems15m` text,
  `p3_antiHB9m` tinyint(1) DEFAULT NULL,
  `p3_hemoglobin9m` tinyint(1) DEFAULT NULL,
  `p3_hemoglobin12m` tinyint(1) DEFAULT NULL,
  `p3_signature9m` varchar(250) DEFAULT NULL,
  `p3_signature12m` varchar(250) DEFAULT NULL,
  `p3_signature15m` varchar(250) DEFAULT NULL,
  `p4_date18m` date DEFAULT NULL,
  `p4_date24m` date DEFAULT NULL,
  `p4_date48m` date DEFAULT NULL,
  `p4_ht18m` varchar(5) DEFAULT NULL,
  `p4_wt18m` varchar(5) DEFAULT NULL,
  `p4_hc18m` varchar(5) DEFAULT NULL,
  `p4_ht24m` varchar(5) DEFAULT NULL,
  `p4_wt24m` varchar(5) DEFAULT NULL,
  `p4_hc24m` varchar(5) DEFAULT NULL,
  `p4_ht48m` varchar(5) DEFAULT NULL,
  `p4_wt48m` varchar(5) DEFAULT NULL,
  `p4_pConcern18m` text,
  `p4_pConcern24m` text,
  `p4_pConcern48m` text,
  `p4_breastFeeding18m` tinyint(1) DEFAULT NULL,
  `p4_homoMilk` tinyint(1) DEFAULT NULL,
  `p4_bottle18m` tinyint(1) DEFAULT NULL,
  `p4_homo2percent24m` tinyint(1) DEFAULT NULL,
  `p4_lowerfatdiet24m` tinyint(1) DEFAULT NULL,
  `p4_foodguide24m` tinyint(1) DEFAULT NULL,
  `p4_2pMilk48m` tinyint(1) DEFAULT NULL,
  `p4_foodguide48m` tinyint(1) DEFAULT NULL,
  `p4_carSeat18mOk` tinyint(1) DEFAULT NULL,
  `p4_carSeat18mNo` tinyint(1) DEFAULT NULL,
  `p4_bathSafetyOk` tinyint(1) DEFAULT NULL,
  `p4_bathSafetyNo` tinyint(1) DEFAULT NULL,
  `p4_safeToysOk` tinyint(1) DEFAULT NULL,
  `p4_safeToysNo` tinyint(1) DEFAULT NULL,
  `p4_parentChild18mOk` tinyint(1) DEFAULT NULL,
  `p4_parentChild18mNo` tinyint(1) DEFAULT NULL,
  `p4_discipline18mOk` tinyint(1) DEFAULT NULL,
  `p4_discipline18mNo` tinyint(1) DEFAULT NULL,
  `p4_pFatigue18mOk` tinyint(1) DEFAULT NULL,
  `p4_pFatigue18mNo` tinyint(1) DEFAULT NULL,
  `p4_highRisk18mOk` tinyint(1) DEFAULT NULL,
  `p4_highRisk18mNo` tinyint(1) DEFAULT NULL,
  `p4_socializing18mOk` tinyint(1) DEFAULT NULL,
  `p4_socializing18mNo` tinyint(1) DEFAULT NULL,
  `p4_dentalCareOk` tinyint(1) DEFAULT NULL,
  `p4_dentalCareNo` tinyint(1) DEFAULT NULL,
  `p4_toiletLearning18mOk` tinyint(1) DEFAULT NULL,
  `p4_toiletLearning18mNo` tinyint(1) DEFAULT NULL,
  `p4_carSeat24mOk` tinyint(1) DEFAULT NULL,
  `p4_carSeat24mNo` tinyint(1) DEFAULT NULL,
  `p4_bikeHelmetsOk` tinyint(1) DEFAULT NULL,
  `p4_bikeHelmetsNo` tinyint(1) DEFAULT NULL,
  `p4_firearmSafetyOk` tinyint(1) DEFAULT NULL,
  `p4_firearmSafetyNo` tinyint(1) DEFAULT NULL,
  `p4_smokeSafetyOk` tinyint(1) DEFAULT NULL,
  `p4_smokeSafetyNo` tinyint(1) DEFAULT NULL,
  `p4_matchesOk` tinyint(1) DEFAULT NULL,
  `p4_matchesNo` tinyint(1) DEFAULT NULL,
  `p4_waterSafetyOk` tinyint(1) DEFAULT NULL,
  `p4_waterSafetyNo` tinyint(1) DEFAULT NULL,
  `p4_parentChild24mOk` tinyint(1) DEFAULT NULL,
  `p4_parentChild24mNo` tinyint(1) DEFAULT NULL,
  `p4_discipline24mOk` tinyint(1) DEFAULT NULL,
  `p4_discipline24mNo` tinyint(1) DEFAULT NULL,
  `p4_highRisk24mOk` tinyint(1) DEFAULT NULL,
  `p4_highRisk24mNo` tinyint(1) DEFAULT NULL,
  `p4_pFatigue24mOk` tinyint(1) DEFAULT NULL,
  `p4_pFatigue24mNo` tinyint(1) DEFAULT NULL,
  `p4_famConflictOk` tinyint(1) DEFAULT NULL,
  `p4_famConflictNo` tinyint(1) DEFAULT NULL,
  `p4_siblingsOk` tinyint(1) DEFAULT NULL,
  `p4_siblingsNo` tinyint(1) DEFAULT NULL,
  `p4_2ndSmokeOk` tinyint(1) DEFAULT NULL,
  `p4_2ndSmokeNo` tinyint(1) DEFAULT NULL,
  `p4_dentalCleaningOk` tinyint(1) DEFAULT NULL,
  `p4_dentalCleaningNo` tinyint(1) DEFAULT NULL,
  `p4_altMedOk` tinyint(1) DEFAULT NULL,
  `p4_altMedNo` tinyint(1) DEFAULT NULL,
  `p4_toiletLearning24mOk` tinyint(1) DEFAULT NULL,
  `p4_toiletLearning24mNo` tinyint(1) DEFAULT NULL,
  `p4_activeOk` tinyint(1) DEFAULT NULL,
  `p4_activeNo` tinyint(1) DEFAULT NULL,
  `p4_socializing24mOk` tinyint(1) DEFAULT NULL,
  `p4_socializing24mNo` tinyint(1) DEFAULT NULL,
  `p4_readingOk` tinyint(1) DEFAULT NULL,
  `p4_readingNo` tinyint(1) DEFAULT NULL,
  `p4_dayCareOk` tinyint(1) DEFAULT NULL,
  `p4_dayCareNo` tinyint(1) DEFAULT NULL,
  `p4_sunExposureOk` tinyint(1) DEFAULT NULL,
  `p4_sunExposureNo` tinyint(1) DEFAULT NULL,
  `p4_pesticidesOk` tinyint(1) DEFAULT NULL,
  `p4_pesticidesNo` tinyint(1) DEFAULT NULL,
  `p4_checkSerumOk` tinyint(1) DEFAULT NULL,
  `p4_checkSerumNo` tinyint(1) DEFAULT NULL,
  `p4_manageableOk` tinyint(1) DEFAULT NULL,
  `p4_manageableNo` tinyint(1) DEFAULT NULL,
  `p4_soothabilityOk` tinyint(1) DEFAULT NULL,
  `p4_soothabilityNo` tinyint(1) DEFAULT NULL,
  `p4_comfortOk` tinyint(1) DEFAULT NULL,
  `p4_comfortNo` tinyint(1) DEFAULT NULL,
  `p4_pointsOk` tinyint(1) DEFAULT NULL,
  `p4_pointsNo` tinyint(1) DEFAULT NULL,
  `p4_getAttnOk` tinyint(1) DEFAULT NULL,
  `p4_getAttnNo` tinyint(1) DEFAULT NULL,
  `p4_pretendPlayOk` tinyint(1) DEFAULT NULL,
  `p4_pretendPlayNo` tinyint(1) DEFAULT NULL,
  `p4_recsNameOk` tinyint(1) DEFAULT NULL,
  `p4_recsNameNo` tinyint(1) DEFAULT NULL,
  `p4_initSpeechOk` tinyint(1) DEFAULT NULL,
  `p4_initSpeechNo` tinyint(1) DEFAULT NULL,
  `p4_3consonantsOk` tinyint(1) DEFAULT NULL,
  `p4_3consonantsNo` tinyint(1) DEFAULT NULL,
  `p4_walksbackOk` tinyint(1) DEFAULT NULL,
  `p4_walksbackNo` tinyint(1) DEFAULT NULL,
  `p4_feedsSelfOk` tinyint(1) DEFAULT NULL,
  `p4_feedsSelfNo` tinyint(1) DEFAULT NULL,
  `p4_removesHatOk` tinyint(1) DEFAULT NULL,
  `p4_removesHatNo` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns18mOk` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns18mNo` tinyint(1) DEFAULT NULL,
  `p4_newWordsOk` tinyint(1) DEFAULT NULL,
  `p4_newWordsNo` tinyint(1) DEFAULT NULL,
  `p4_2wSentenceOk` tinyint(1) DEFAULT NULL,
  `p4_2wSentenceNo` tinyint(1) DEFAULT NULL,
  `p4_runsOk` tinyint(1) DEFAULT NULL,
  `p4_runsNo` tinyint(1) DEFAULT NULL,
  `p4_smallContainerOk` tinyint(1) DEFAULT NULL,
  `p4_smallContainerNo` tinyint(1) DEFAULT NULL,
  `p4_copiesActionsOk` tinyint(1) DEFAULT NULL,
  `p4_copiesActionsNo` tinyint(1) DEFAULT NULL,
  `p4_newSkillsOk` tinyint(1) DEFAULT NULL,
  `p4_newSkillsNo` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns24mOk` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns24mNo` tinyint(1) DEFAULT NULL,
  `p4_3directionsOk` tinyint(1) DEFAULT NULL,
  `p4_3directionsNo` tinyint(1) DEFAULT NULL,
  `p4_asksQuestionsOk` tinyint(1) DEFAULT NULL,
  `p4_asksQuestionsNo` tinyint(1) DEFAULT NULL,
  `p4_stands1footOk` tinyint(1) DEFAULT NULL,
  `p4_stands1footNo` tinyint(1) DEFAULT NULL,
  `p4_drawsOk` tinyint(1) DEFAULT NULL,
  `p4_drawsNo` tinyint(1) DEFAULT NULL,
  `p4_toiletTrainedOk` tinyint(1) DEFAULT NULL,
  `p4_toiletTrainedNo` tinyint(1) DEFAULT NULL,
  `p4_tries2comfortOk` tinyint(1) DEFAULT NULL,
  `p4_tries2comfortNo` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns48mOk` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns48mNo` tinyint(1) DEFAULT NULL,
  `p4_2directionsOk` tinyint(1) DEFAULT NULL,
  `p4_2directionsNo` tinyint(1) DEFAULT NULL,
  `p4_twistslidsOk` tinyint(1) DEFAULT NULL,
  `p4_twistslidsNo` tinyint(1) DEFAULT NULL,
  `p4_turnsPagesOk` tinyint(1) DEFAULT NULL,
  `p4_turnsPagesNo` tinyint(1) DEFAULT NULL,
  `p4_sharesSometimeOk` tinyint(1) DEFAULT NULL,
  `p4_sharesSometimeNo` tinyint(1) DEFAULT NULL,
  `p4_listenMusikOk` tinyint(1) DEFAULT NULL,
  `p4_listenMusikNo` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns36mOk` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns36mNo` tinyint(1) DEFAULT NULL,
  `p4_counts2tenOk` tinyint(1) DEFAULT NULL,
  `p4_counts2tenNo` tinyint(1) DEFAULT NULL,
  `p4_speaksClearlyOk` tinyint(1) DEFAULT NULL,
  `p4_speaksClearlyNo` tinyint(1) DEFAULT NULL,
  `p4_throwsCatchesOk` tinyint(1) DEFAULT NULL,
  `p4_throwsCatchesNo` tinyint(1) DEFAULT NULL,
  `p4_hops1footOk` tinyint(1) DEFAULT NULL,
  `p4_hops1footNo` tinyint(1) DEFAULT NULL,
  `p4_sharesWillinglyOk` tinyint(1) DEFAULT NULL,
  `p4_sharesWillinglyNo` tinyint(1) DEFAULT NULL,
  `p4_worksAloneOk` tinyint(1) DEFAULT NULL,
  `p4_worksAloneNo` tinyint(1) DEFAULT NULL,
  `p4_separatesOk` tinyint(1) DEFAULT NULL,
  `p4_separatesNo` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns60mOk` tinyint(1) DEFAULT NULL,
  `p4_noParentsConcerns60mNo` tinyint(1) DEFAULT NULL,
  `p4_eyes18m` tinyint(1) DEFAULT NULL,
  `p4_corneal18m` tinyint(1) DEFAULT NULL,
  `p4_hearing18m` tinyint(1) DEFAULT NULL,
  `p4_tonsil18m` tinyint(1) DEFAULT NULL,
  `p4_bloodpressure24m` tinyint(1) DEFAULT NULL,
  `p4_eyes24m` tinyint(1) DEFAULT NULL,
  `p4_corneal24m` tinyint(1) DEFAULT NULL,
  `p4_hearing24m` tinyint(1) DEFAULT NULL,
  `p4_tonsil24m` tinyint(1) DEFAULT NULL,
  `p4_bloodpressure48m` tinyint(1) DEFAULT NULL,
  `p4_eyes48m` tinyint(1) DEFAULT NULL,
  `p4_corneal48m` tinyint(1) DEFAULT NULL,
  `p4_hearing48m` tinyint(1) DEFAULT NULL,
  `p4_tonsil48m` tinyint(1) DEFAULT NULL,
  `p4_problems18m` text,
  `p4_problems24m` text,
  `p4_problems48m` text,
  `p4_signature18m` varchar(250) DEFAULT NULL,
  `p4_signature24m` varchar(250) DEFAULT NULL,
  `p4_signature48m` varchar(250) DEFAULT NULL,
  `p1_signature1w` varchar(250) DEFAULT NULL,
  `p1_signature1m` varchar(250) DEFAULT NULL,
  `p2_signature6m` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formRourke2017`
--

CREATE TABLE IF NOT EXISTS `formRourke2017` (
   `ID` int(10) NOT NULL AUTO_INCREMENT,
   `demographic_no` int(10),
   `c_male` varchar(2),
   `c_female` varchar(2),
   `provider_no` varchar(6),
   `formCreated` date,
   `formEdited` timestamp NOT NULL ON UPDATE CURRENT_TIMESTAMP,
   `c_lastVisited` char(3),
   `c_birthRemarks` text,
   `c_riskFactors` text,
   `c_famHistory` text,
   `c_pName` varchar(60),
   `c_birthDate` date,
   `c_length` varchar(6),
   `c_headCirc` varchar(6),
   `c_birthWeight` varchar(7),
   `c_dischargeWeight` varchar(7),
   `c_fsa` char(3),
   `start_of_gestation` DATE,
   `c_APGAR1min` int(11),
   `c_APGAR5min` int(11),
   `p1_date1w` date,
   `p1_date2w` date,
   `p1_date1m` date,
   `p1_ht1w` varchar(5),
   `p1_wt1w` varchar(5),
   `p1_hc1w` varchar(5),
   `p1_ht2w` varchar(5),
   `p1_wt2w` varchar(5),
   `p1_hc2w` varchar(5),
   `p1_ht1m` varchar(5),
   `p1_wt1m` varchar(5),
   `p1_hc1m` varchar(5),
   `p1_pConcern1w` text,
   `p1_pConcern2w` text,
   `p1_pConcern1m` text,
   `p1_development1w` text,
   `p1_development2w` text,
   `p1_development1m` text,
   `p1_problems1w` text,
   `p1_problems2w` text,
   `p1_problems1m` text,
   `p1_signature2w` varchar(250),
   `p2_date2m` date,
   `p2_date4m` date,
   `p2_date6m` date,
   `p2_ht2m` varchar(5),
   `p2_wt2m` varchar(5),
   `p2_hc2m` varchar(5),
   `p2_ht4m` varchar(5),
   `p2_wt4m` varchar(5),
   `p2_hc4m` varchar(5),
   `p2_ht6m` varchar(5),
   `p2_wt6m` varchar(5),
   `p2_hc6m` varchar(5),
   `p2_pConcern2m` text,
   `p2_pConcern4m` text,
   `p2_pConcern6m` text,
   `p2_nutrition2m` text,
   `p2_nutrition4m` text,
   `p2_development2m` text,
   `p2_development4m` text,
   `p2_development6m` text,
   `p2_problems2m` text,
   `p2_problems4m` text,
   `p2_problems6m` text,
   `p2_signature2m` varchar(250),
   `p2_signature4m` varchar(250),
   `p3_date9m` date,
   `p3_date12m` date,
   `p3_date15m` date,
   `p3_ht9m` varchar(5),
   `p3_wt9m` varchar(5),
   `p3_hc9m` varchar(5),
   `p3_ht12m` varchar(5),
   `p3_wt12m` varchar(5),
   `p3_hc12m` varchar(5),
   `p3_ht15m` varchar(5),
   `p3_wt15m` varchar(5),
   `p3_hc15m` varchar(5),
   `p3_pConcern9m` text,
   `p3_pConcern12m` text,
   `p3_pConcern15m` text,
   `p3_nutrition12m` text,
   `p3_nutrition15m` text,
   `p3_development9m` text,
   `p3_development12m` text,
   `p3_development15m` text,
   `p3_problems9m` text,
   `p3_problems12m` text,
   `p3_problems15m` text,
   `p3_signature9m` varchar(250),
   `p3_signature12m` varchar(250),
   `p3_signature15m` varchar(250),
   `p4_date18m` date,
   `p4_date24m` date,
   `p4_date48m` date,
   `p4_ht18m` varchar(5),
   `p4_wt18m` varchar(5),
   `p4_hc18m` varchar(5),
   `p4_ht24m` varchar(5),
   `p4_wt24m` varchar(5),
   `p4_hc24m` varchar(5),
   `p4_ht48m` varchar(5),
   `p4_bmi24m` varchar(5),
   `p4_bmi48m` varchar(10),
   `p4_wt48m` varchar(5),
   `p4_pConcern18m` text,
   `p4_pConcern24m` text,
   `p4_pConcern48m` text,
   `p4_problems18m` text,
   `p4_problems24m` text,
   `p4_problems48m` text,
   `p4_signature18m` varchar(250),
   `p4_signature24m` varchar(250),
   `p4_signature48m` varchar(250),
   `p1_signature1w` varchar(250),
   `p1_signature1m` varchar(250),
   `p2_signature6m` varchar(250),
   `p1_pNutrition1w` text,
   `p1_pNutrition2w` text,
   `p1_pNutrition1m` text,
   `p1_education1w` text,
   `p1_education2w` text,
   `p1_education1m` text,
   `p1_pPhysical1w` text,
   `p1_pPhysical2w` text,
   `p1_pPhysical1m` text,
   `p1_immunization1w` text,
   `p1_immunization2w` text,
   `p1_immunization1m` text,
   `p2_nutrition6m` text,
   `p2_education2m` text,
   `p2_education4m` text,
   `p2_education6m` text,
   `p2_physical2m` text,
   `p2_physical4m` text,
   `p2_physical6m` text,
   `p2_immunization6m` text,
   `p3_nutrition9m` text,
   `p3_education9m` text,
   `p3_education12m` text,
   `p3_education15m` text,
   `p3_physical9m` text,
   `p3_physical12m` text,
   `p3_physical15m` text,
   `p4_nutrition18m` text,
   `p4_nutrition24m` text,
   `p4_nutrition48m` text,
   `p4_education18m` text,
   `p4_education24m` text,
   `p4_education48m` text,
   `p4_development18m` text,
   `p4_development24m` text,
   `p4_development48m` text,
   `p4_development36m` text,
   `p4_development60m` text,
   `p4_physical18m` text,
   `p4_physical24m` text,
   `p4_physical48m` text,
   `p4_nippisingattained` text,
   PRIMARY KEY (`ID`),
   KEY `formRourke2017_demographic_no` (`demographic_no`)
 ); 

--
-- Table structure for table `formSF36`
--


CREATE TABLE `formSF36` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `Q1Ex` tinyint(1) DEFAULT NULL,
  `Q1VG` tinyint(1) DEFAULT NULL,
  `Q1G` tinyint(1) DEFAULT NULL,
  `Q1F` tinyint(1) DEFAULT NULL,
  `Q1P` tinyint(1) DEFAULT NULL,
  `Q1Cmt` varchar(255) DEFAULT NULL,
  `Q2MuchBetter` tinyint(1) DEFAULT NULL,
  `Q2Better` tinyint(1) DEFAULT NULL,
  `Q2Same` tinyint(1) DEFAULT NULL,
  `Q2Worse` tinyint(1) DEFAULT NULL,
  `Q2MuchWorse` tinyint(1) DEFAULT NULL,
  `Q2Cmt` varchar(255) DEFAULT NULL,
  `Q3aYesLot` tinyint(1) DEFAULT NULL,
  `Q3aYesLittle` tinyint(1) DEFAULT NULL,
  `Q3aNo` tinyint(1) DEFAULT NULL,
  `Q3aCmt` varchar(255) DEFAULT NULL,
  `Q3bYesLot` tinyint(1) DEFAULT NULL,
  `Q3bYesLittle` tinyint(1) DEFAULT NULL,
  `Q3bNo` tinyint(1) DEFAULT NULL,
  `Q3bCmt` varchar(255) DEFAULT NULL,
  `Q3cYesLot` tinyint(1) DEFAULT NULL,
  `Q3cYesLittle` tinyint(1) DEFAULT NULL,
  `Q3cNo` tinyint(1) DEFAULT NULL,
  `Q3cCmt` varchar(255) DEFAULT NULL,
  `Q3dYesLot` tinyint(1) DEFAULT NULL,
  `Q3dYesLittle` tinyint(1) DEFAULT NULL,
  `Q3dNo` tinyint(1) DEFAULT NULL,
  `Q3dCmt` varchar(255) DEFAULT NULL,
  `Q3eYesLot` tinyint(1) DEFAULT NULL,
  `Q3eYesLittle` tinyint(1) DEFAULT NULL,
  `Q3eNo` tinyint(1) DEFAULT NULL,
  `Q3eCmt` varchar(255) DEFAULT NULL,
  `Q3fYesLot` tinyint(1) DEFAULT NULL,
  `Q3fYesLittle` tinyint(1) DEFAULT NULL,
  `Q3fNo` tinyint(1) DEFAULT NULL,
  `Q3fCmt` varchar(255) DEFAULT NULL,
  `Q3gYesLot` tinyint(1) DEFAULT NULL,
  `Q3gYesLittle` tinyint(1) DEFAULT NULL,
  `Q3gNo` tinyint(1) DEFAULT NULL,
  `Q3gCmt` varchar(255) DEFAULT NULL,
  `Q3hYesLot` tinyint(1) DEFAULT NULL,
  `Q3hYesLittle` tinyint(1) DEFAULT NULL,
  `Q3hNo` tinyint(1) DEFAULT NULL,
  `Q3hCmt` varchar(255) DEFAULT NULL,
  `Q3iYesLot` tinyint(1) DEFAULT NULL,
  `Q3iYesLittle` tinyint(1) DEFAULT NULL,
  `Q3iNo` tinyint(1) DEFAULT NULL,
  `Q3iCmt` varchar(255) DEFAULT NULL,
  `Q3jYesLot` tinyint(1) DEFAULT NULL,
  `Q3jYesLittle` tinyint(1) DEFAULT NULL,
  `Q3jNo` tinyint(1) DEFAULT NULL,
  `Q3jCmt` varchar(255) DEFAULT NULL,
  `Q4aAll` tinyint(1) DEFAULT NULL,
  `Q4aMost` tinyint(1) DEFAULT NULL,
  `Q4aSome` tinyint(1) DEFAULT NULL,
  `Q4aLittle` tinyint(1) DEFAULT NULL,
  `Q4aNone` tinyint(1) DEFAULT NULL,
  `Q4aCmt` varchar(255) DEFAULT NULL,
  `Q4bAll` tinyint(1) DEFAULT NULL,
  `Q4bMost` tinyint(1) DEFAULT NULL,
  `Q4bSome` tinyint(1) DEFAULT NULL,
  `Q4bLittle` tinyint(1) DEFAULT NULL,
  `Q4bNone` tinyint(1) DEFAULT NULL,
  `Q4bCmt` varchar(255) DEFAULT NULL,
  `Q4cAll` tinyint(1) DEFAULT NULL,
  `Q4cMost` tinyint(1) DEFAULT NULL,
  `Q4cSome` tinyint(1) DEFAULT NULL,
  `Q4cLittle` tinyint(1) DEFAULT NULL,
  `Q4cNone` tinyint(1) DEFAULT NULL,
  `Q4cCmt` varchar(255) DEFAULT NULL,
  `Q4dAll` tinyint(1) DEFAULT NULL,
  `Q4dMost` tinyint(1) DEFAULT NULL,
  `Q4dSome` tinyint(1) DEFAULT NULL,
  `Q4dLittle` tinyint(1) DEFAULT NULL,
  `Q4dNone` tinyint(1) DEFAULT NULL,
  `Q4dCmt` varchar(255) DEFAULT NULL,
  `Q5aAll` tinyint(1) DEFAULT NULL,
  `Q5aMost` tinyint(1) DEFAULT NULL,
  `Q5aSome` tinyint(1) DEFAULT NULL,
  `Q5aLittle` tinyint(1) DEFAULT NULL,
  `Q5aNone` tinyint(1) DEFAULT NULL,
  `Q5aCmt` varchar(255) DEFAULT NULL,
  `Q5bAll` tinyint(1) DEFAULT NULL,
  `Q5bMost` tinyint(1) DEFAULT NULL,
  `Q5bSome` tinyint(1) DEFAULT NULL,
  `Q5bLittle` tinyint(1) DEFAULT NULL,
  `Q5bNone` tinyint(1) DEFAULT NULL,
  `Q5bCmt` varchar(255) DEFAULT NULL,
  `Q5cAll` tinyint(1) DEFAULT NULL,
  `Q5cMost` tinyint(1) DEFAULT NULL,
  `Q5cSome` tinyint(1) DEFAULT NULL,
  `Q5cLittle` tinyint(1) DEFAULT NULL,
  `Q5cNone` tinyint(1) DEFAULT NULL,
  `Q5cCmt` varchar(255) DEFAULT NULL,
  `Q6NotAtAll` tinyint(1) DEFAULT NULL,
  `Q6Slightly` tinyint(1) DEFAULT NULL,
  `Q6Moderately` tinyint(1) DEFAULT NULL,
  `Q6QuiteABit` tinyint(1) DEFAULT NULL,
  `Q6Extremely` tinyint(1) DEFAULT NULL,
  `Q6Cmt` varchar(255) DEFAULT NULL,
  `Q7None` tinyint(1) DEFAULT NULL,
  `Q7VeryMild` tinyint(1) DEFAULT NULL,
  `Q7Mild` tinyint(1) DEFAULT NULL,
  `Q7Moderate` tinyint(1) DEFAULT NULL,
  `Q7Severe` tinyint(1) DEFAULT NULL,
  `Q7VerySevere` tinyint(1) DEFAULT NULL,
  `Q7Cmt` varchar(255) DEFAULT NULL,
  `Q8NotAtAll` tinyint(1) DEFAULT NULL,
  `Q8Slightly` tinyint(1) DEFAULT NULL,
  `Q8Moderately` tinyint(1) DEFAULT NULL,
  `Q8QuiteABit` tinyint(1) DEFAULT NULL,
  `Q8Extremely` tinyint(1) DEFAULT NULL,
  `Q8Cmt` varchar(255) DEFAULT NULL,
  `Q9aAll` tinyint(1) DEFAULT NULL,
  `Q9aMost` tinyint(1) DEFAULT NULL,
  `Q9aSome` tinyint(1) DEFAULT NULL,
  `Q9aLittle` tinyint(1) DEFAULT NULL,
  `Q9aNone` tinyint(1) DEFAULT NULL,
  `Q9aCmt` varchar(255) DEFAULT NULL,
  `Q9bAll` tinyint(1) DEFAULT NULL,
  `Q9bMost` tinyint(1) DEFAULT NULL,
  `Q9bSome` tinyint(1) DEFAULT NULL,
  `Q9bLittle` tinyint(1) DEFAULT NULL,
  `Q9bNone` tinyint(1) DEFAULT NULL,
  `Q9bCmt` varchar(255) DEFAULT NULL,
  `Q9cAll` tinyint(1) DEFAULT NULL,
  `Q9cMost` tinyint(1) DEFAULT NULL,
  `Q9cSome` tinyint(1) DEFAULT NULL,
  `Q9cLittle` tinyint(1) DEFAULT NULL,
  `Q9cNone` tinyint(1) DEFAULT NULL,
  `Q9cCmt` varchar(255) DEFAULT NULL,
  `Q9dAll` tinyint(1) DEFAULT NULL,
  `Q9dMost` tinyint(1) DEFAULT NULL,
  `Q9dSome` tinyint(1) DEFAULT NULL,
  `Q9dLittle` tinyint(1) DEFAULT NULL,
  `Q9dNone` tinyint(1) DEFAULT NULL,
  `Q9dCmt` varchar(255) DEFAULT NULL,
  `Q9eAll` tinyint(1) DEFAULT NULL,
  `Q9eMost` tinyint(1) DEFAULT NULL,
  `Q9eSome` tinyint(1) DEFAULT NULL,
  `Q9eLittle` tinyint(1) DEFAULT NULL,
  `Q9eNone` tinyint(1) DEFAULT NULL,
  `Q9eCmt` varchar(255) DEFAULT NULL,
  `Q9fAll` tinyint(1) DEFAULT NULL,
  `Q9fMost` tinyint(1) DEFAULT NULL,
  `Q9fSome` tinyint(1) DEFAULT NULL,
  `Q9fLittle` tinyint(1) DEFAULT NULL,
  `Q9fNone` tinyint(1) DEFAULT NULL,
  `Q9fCmt` varchar(255) DEFAULT NULL,
  `Q9gAll` tinyint(1) DEFAULT NULL,
  `Q9gMost` tinyint(1) DEFAULT NULL,
  `Q9gSome` tinyint(1) DEFAULT NULL,
  `Q9gLittle` tinyint(1) DEFAULT NULL,
  `Q9gNone` tinyint(1) DEFAULT NULL,
  `Q9gCmt` varchar(255) DEFAULT NULL,
  `Q9hAll` tinyint(1) DEFAULT NULL,
  `Q9hMost` tinyint(1) DEFAULT NULL,
  `Q9hSome` tinyint(1) DEFAULT NULL,
  `Q9hLittle` tinyint(1) DEFAULT NULL,
  `Q9hNone` tinyint(1) DEFAULT NULL,
  `Q9hCmt` varchar(255) DEFAULT NULL,
  `Q9iAll` tinyint(1) DEFAULT NULL,
  `Q9iMost` tinyint(1) DEFAULT NULL,
  `Q9iSome` tinyint(1) DEFAULT NULL,
  `Q9iLittle` tinyint(1) DEFAULT NULL,
  `Q9iNone` tinyint(1) DEFAULT NULL,
  `Q9iCmt` varchar(255) DEFAULT NULL,
  `Q10All` tinyint(1) DEFAULT NULL,
  `Q10Most` tinyint(1) DEFAULT NULL,
  `Q10Some` tinyint(1) DEFAULT NULL,
  `Q10Little` tinyint(1) DEFAULT NULL,
  `Q10None` tinyint(1) DEFAULT NULL,
  `Q10Cmt` varchar(255) DEFAULT NULL,
  `Q11aDefTrue` tinyint(1) DEFAULT NULL,
  `Q11aMostTrue` tinyint(1) DEFAULT NULL,
  `Q11aNotSure` tinyint(1) DEFAULT NULL,
  `Q11aMostFalse` tinyint(1) DEFAULT NULL,
  `Q11aDefFalse` tinyint(1) DEFAULT NULL,
  `Q11aCmt` varchar(255) DEFAULT NULL,
  `Q11bDefTrue` tinyint(1) DEFAULT NULL,
  `Q11bMostTrue` tinyint(1) DEFAULT NULL,
  `Q11bNotSure` tinyint(1) DEFAULT NULL,
  `Q11bMostFalse` tinyint(1) DEFAULT NULL,
  `Q11bDefFalse` tinyint(1) DEFAULT NULL,
  `Q11bCmt` varchar(255) DEFAULT NULL,
  `Q11cDefTrue` tinyint(1) DEFAULT NULL,
  `Q11cMostTrue` tinyint(1) DEFAULT NULL,
  `Q11cNotSure` tinyint(1) DEFAULT NULL,
  `Q11cMostFalse` tinyint(1) DEFAULT NULL,
  `Q11cDefFalse` tinyint(1) DEFAULT NULL,
  `Q11cCmt` varchar(255) DEFAULT NULL,
  `Q11dDefTrue` tinyint(1) DEFAULT NULL,
  `Q11dMostTrue` tinyint(1) DEFAULT NULL,
  `Q11dNotSure` tinyint(1) DEFAULT NULL,
  `Q11dMostFalse` tinyint(1) DEFAULT NULL,
  `Q11dDefFalse` tinyint(1) DEFAULT NULL,
  `Q11dCmt` varchar(255) DEFAULT NULL,
  `Q12aNotAns` tinyint(1) DEFAULT NULL,
  `Q12aNot` tinyint(1) DEFAULT NULL,
  `Q12aLittle` tinyint(1) DEFAULT NULL,
  `Q12aSome` tinyint(1) DEFAULT NULL,
  `Q12aLot` tinyint(1) DEFAULT NULL,
  `Q12aMuch` tinyint(1) DEFAULT NULL,
  `Q12aCmt` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formSF36Caregiver`
--


CREATE TABLE `formSF36Caregiver` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `Q1Ex` tinyint(1) DEFAULT NULL,
  `Q1VG` tinyint(1) DEFAULT NULL,
  `Q1G` tinyint(1) DEFAULT NULL,
  `Q1F` tinyint(1) DEFAULT NULL,
  `Q1P` tinyint(1) DEFAULT NULL,
  `Q1Cmt` varchar(255) DEFAULT NULL,
  `Q2MuchBetter` tinyint(1) DEFAULT NULL,
  `Q2Better` tinyint(1) DEFAULT NULL,
  `Q2Same` tinyint(1) DEFAULT NULL,
  `Q2Worse` tinyint(1) DEFAULT NULL,
  `Q2MuchWorse` tinyint(1) DEFAULT NULL,
  `Q2Cmt` varchar(255) DEFAULT NULL,
  `Q3aYesLot` tinyint(1) DEFAULT NULL,
  `Q3aYesLittle` tinyint(1) DEFAULT NULL,
  `Q3aNo` tinyint(1) DEFAULT NULL,
  `Q3aCmt` varchar(255) DEFAULT NULL,
  `Q3bYesLot` tinyint(1) DEFAULT NULL,
  `Q3bYesLittle` tinyint(1) DEFAULT NULL,
  `Q3bNo` tinyint(1) DEFAULT NULL,
  `Q3bCmt` varchar(255) DEFAULT NULL,
  `Q3cYesLot` tinyint(1) DEFAULT NULL,
  `Q3cYesLittle` tinyint(1) DEFAULT NULL,
  `Q3cNo` tinyint(1) DEFAULT NULL,
  `Q3cCmt` varchar(255) DEFAULT NULL,
  `Q3dYesLot` tinyint(1) DEFAULT NULL,
  `Q3dYesLittle` tinyint(1) DEFAULT NULL,
  `Q3dNo` tinyint(1) DEFAULT NULL,
  `Q3dCmt` varchar(255) DEFAULT NULL,
  `Q3eYesLot` tinyint(1) DEFAULT NULL,
  `Q3eYesLittle` tinyint(1) DEFAULT NULL,
  `Q3eNo` tinyint(1) DEFAULT NULL,
  `Q3eCmt` varchar(255) DEFAULT NULL,
  `Q3fYesLot` tinyint(1) DEFAULT NULL,
  `Q3fYesLittle` tinyint(1) DEFAULT NULL,
  `Q3fNo` tinyint(1) DEFAULT NULL,
  `Q3fCmt` varchar(255) DEFAULT NULL,
  `Q3gYesLot` tinyint(1) DEFAULT NULL,
  `Q3gYesLittle` tinyint(1) DEFAULT NULL,
  `Q3gNo` tinyint(1) DEFAULT NULL,
  `Q3gCmt` varchar(255) DEFAULT NULL,
  `Q3hYesLot` tinyint(1) DEFAULT NULL,
  `Q3hYesLittle` tinyint(1) DEFAULT NULL,
  `Q3hNo` tinyint(1) DEFAULT NULL,
  `Q3hCmt` varchar(255) DEFAULT NULL,
  `Q3iYesLot` tinyint(1) DEFAULT NULL,
  `Q3iYesLittle` tinyint(1) DEFAULT NULL,
  `Q3iNo` tinyint(1) DEFAULT NULL,
  `Q3iCmt` varchar(255) DEFAULT NULL,
  `Q3jYesLot` tinyint(1) DEFAULT NULL,
  `Q3jYesLittle` tinyint(1) DEFAULT NULL,
  `Q3jNo` tinyint(1) DEFAULT NULL,
  `Q3jCmt` varchar(255) DEFAULT NULL,
  `Q4aAll` tinyint(1) DEFAULT NULL,
  `Q4aMost` tinyint(1) DEFAULT NULL,
  `Q4aSome` tinyint(1) DEFAULT NULL,
  `Q4aLittle` tinyint(1) DEFAULT NULL,
  `Q4aNone` tinyint(1) DEFAULT NULL,
  `Q4aCmt` varchar(255) DEFAULT NULL,
  `Q4bAll` tinyint(1) DEFAULT NULL,
  `Q4bMost` tinyint(1) DEFAULT NULL,
  `Q4bSome` tinyint(1) DEFAULT NULL,
  `Q4bLittle` tinyint(1) DEFAULT NULL,
  `Q4bNone` tinyint(1) DEFAULT NULL,
  `Q4bCmt` varchar(255) DEFAULT NULL,
  `Q4cAll` tinyint(1) DEFAULT NULL,
  `Q4cMost` tinyint(1) DEFAULT NULL,
  `Q4cSome` tinyint(1) DEFAULT NULL,
  `Q4cLittle` tinyint(1) DEFAULT NULL,
  `Q4cNone` tinyint(1) DEFAULT NULL,
  `Q4cCmt` varchar(255) DEFAULT NULL,
  `Q4dAll` tinyint(1) DEFAULT NULL,
  `Q4dMost` tinyint(1) DEFAULT NULL,
  `Q4dSome` tinyint(1) DEFAULT NULL,
  `Q4dLittle` tinyint(1) DEFAULT NULL,
  `Q4dNone` tinyint(1) DEFAULT NULL,
  `Q4dCmt` varchar(255) DEFAULT NULL,
  `Q5aAll` tinyint(1) DEFAULT NULL,
  `Q5aMost` tinyint(1) DEFAULT NULL,
  `Q5aSome` tinyint(1) DEFAULT NULL,
  `Q5aLittle` tinyint(1) DEFAULT NULL,
  `Q5aNone` tinyint(1) DEFAULT NULL,
  `Q5aCmt` varchar(255) DEFAULT NULL,
  `Q5bAll` tinyint(1) DEFAULT NULL,
  `Q5bMost` tinyint(1) DEFAULT NULL,
  `Q5bSome` tinyint(1) DEFAULT NULL,
  `Q5bLittle` tinyint(1) DEFAULT NULL,
  `Q5bNone` tinyint(1) DEFAULT NULL,
  `Q5bCmt` varchar(255) DEFAULT NULL,
  `Q5cAll` tinyint(1) DEFAULT NULL,
  `Q5cMost` tinyint(1) DEFAULT NULL,
  `Q5cSome` tinyint(1) DEFAULT NULL,
  `Q5cLittle` tinyint(1) DEFAULT NULL,
  `Q5cNone` tinyint(1) DEFAULT NULL,
  `Q5cCmt` varchar(255) DEFAULT NULL,
  `Q6NotAtAll` tinyint(1) DEFAULT NULL,
  `Q6Slightly` tinyint(1) DEFAULT NULL,
  `Q6Moderately` tinyint(1) DEFAULT NULL,
  `Q6QuiteABit` tinyint(1) DEFAULT NULL,
  `Q6Extremely` tinyint(1) DEFAULT NULL,
  `Q6Cmt` varchar(255) DEFAULT NULL,
  `Q7None` tinyint(1) DEFAULT NULL,
  `Q7VeryMild` tinyint(1) DEFAULT NULL,
  `Q7Mild` tinyint(1) DEFAULT NULL,
  `Q7Moderate` tinyint(1) DEFAULT NULL,
  `Q7Severe` tinyint(1) DEFAULT NULL,
  `Q7VerySevere` tinyint(1) DEFAULT NULL,
  `Q7Cmt` varchar(255) DEFAULT NULL,
  `Q8NotAtAll` tinyint(1) DEFAULT NULL,
  `Q8Slightly` tinyint(1) DEFAULT NULL,
  `Q8Moderately` tinyint(1) DEFAULT NULL,
  `Q8QuiteABit` tinyint(1) DEFAULT NULL,
  `Q8Extremely` tinyint(1) DEFAULT NULL,
  `Q8Cmt` varchar(255) DEFAULT NULL,
  `Q9aAll` tinyint(1) DEFAULT NULL,
  `Q9aMost` tinyint(1) DEFAULT NULL,
  `Q9aSome` tinyint(1) DEFAULT NULL,
  `Q9aLittle` tinyint(1) DEFAULT NULL,
  `Q9aNone` tinyint(1) DEFAULT NULL,
  `Q9aCmt` varchar(255) DEFAULT NULL,
  `Q9bAll` tinyint(1) DEFAULT NULL,
  `Q9bMost` tinyint(1) DEFAULT NULL,
  `Q9bSome` tinyint(1) DEFAULT NULL,
  `Q9bLittle` tinyint(1) DEFAULT NULL,
  `Q9bNone` tinyint(1) DEFAULT NULL,
  `Q9bCmt` varchar(255) DEFAULT NULL,
  `Q9cAll` tinyint(1) DEFAULT NULL,
  `Q9cMost` tinyint(1) DEFAULT NULL,
  `Q9cSome` tinyint(1) DEFAULT NULL,
  `Q9cLittle` tinyint(1) DEFAULT NULL,
  `Q9cNone` tinyint(1) DEFAULT NULL,
  `Q9cCmt` varchar(255) DEFAULT NULL,
  `Q9dAll` tinyint(1) DEFAULT NULL,
  `Q9dMost` tinyint(1) DEFAULT NULL,
  `Q9dSome` tinyint(1) DEFAULT NULL,
  `Q9dLittle` tinyint(1) DEFAULT NULL,
  `Q9dNone` tinyint(1) DEFAULT NULL,
  `Q9dCmt` varchar(255) DEFAULT NULL,
  `Q9eAll` tinyint(1) DEFAULT NULL,
  `Q9eMost` tinyint(1) DEFAULT NULL,
  `Q9eSome` tinyint(1) DEFAULT NULL,
  `Q9eLittle` tinyint(1) DEFAULT NULL,
  `Q9eNone` tinyint(1) DEFAULT NULL,
  `Q9eCmt` varchar(255) DEFAULT NULL,
  `Q9fAll` tinyint(1) DEFAULT NULL,
  `Q9fMost` tinyint(1) DEFAULT NULL,
  `Q9fSome` tinyint(1) DEFAULT NULL,
  `Q9fLittle` tinyint(1) DEFAULT NULL,
  `Q9fNone` tinyint(1) DEFAULT NULL,
  `Q9fCmt` varchar(255) DEFAULT NULL,
  `Q9gAll` tinyint(1) DEFAULT NULL,
  `Q9gMost` tinyint(1) DEFAULT NULL,
  `Q9gSome` tinyint(1) DEFAULT NULL,
  `Q9gLittle` tinyint(1) DEFAULT NULL,
  `Q9gNone` tinyint(1) DEFAULT NULL,
  `Q9gCmt` varchar(255) DEFAULT NULL,
  `Q9hAll` tinyint(1) DEFAULT NULL,
  `Q9hMost` tinyint(1) DEFAULT NULL,
  `Q9hSome` tinyint(1) DEFAULT NULL,
  `Q9hLittle` tinyint(1) DEFAULT NULL,
  `Q9hNone` tinyint(1) DEFAULT NULL,
  `Q9hCmt` varchar(255) DEFAULT NULL,
  `Q9iAll` tinyint(1) DEFAULT NULL,
  `Q9iMost` tinyint(1) DEFAULT NULL,
  `Q9iSome` tinyint(1) DEFAULT NULL,
  `Q9iLittle` tinyint(1) DEFAULT NULL,
  `Q9iNone` tinyint(1) DEFAULT NULL,
  `Q9iCmt` varchar(255) DEFAULT NULL,
  `Q10All` tinyint(1) DEFAULT NULL,
  `Q10Most` tinyint(1) DEFAULT NULL,
  `Q10Some` tinyint(1) DEFAULT NULL,
  `Q10Little` tinyint(1) DEFAULT NULL,
  `Q10None` tinyint(1) DEFAULT NULL,
  `Q10Cmt` varchar(255) DEFAULT NULL,
  `Q11aDefTrue` tinyint(1) DEFAULT NULL,
  `Q11aMostTrue` tinyint(1) DEFAULT NULL,
  `Q11aNotSure` tinyint(1) DEFAULT NULL,
  `Q11aMostFalse` tinyint(1) DEFAULT NULL,
  `Q11aDefFalse` tinyint(1) DEFAULT NULL,
  `Q11aCmt` varchar(255) DEFAULT NULL,
  `Q11bDefTrue` tinyint(1) DEFAULT NULL,
  `Q11bMostTrue` tinyint(1) DEFAULT NULL,
  `Q11bNotSure` tinyint(1) DEFAULT NULL,
  `Q11bMostFalse` tinyint(1) DEFAULT NULL,
  `Q11bDefFalse` tinyint(1) DEFAULT NULL,
  `Q11bCmt` varchar(255) DEFAULT NULL,
  `Q11cDefTrue` tinyint(1) DEFAULT NULL,
  `Q11cMostTrue` tinyint(1) DEFAULT NULL,
  `Q11cNotSure` tinyint(1) DEFAULT NULL,
  `Q11cMostFalse` tinyint(1) DEFAULT NULL,
  `Q11cDefFalse` tinyint(1) DEFAULT NULL,
  `Q11cCmt` varchar(255) DEFAULT NULL,
  `Q11dDefTrue` tinyint(1) DEFAULT NULL,
  `Q11dMostTrue` tinyint(1) DEFAULT NULL,
  `Q11dNotSure` tinyint(1) DEFAULT NULL,
  `Q11dMostFalse` tinyint(1) DEFAULT NULL,
  `Q11dDefFalse` tinyint(1) DEFAULT NULL,
  `Q11dCmt` varchar(255) DEFAULT NULL,
  `Q12aNotAns` tinyint(1) DEFAULT NULL,
  `Q12aNot` tinyint(1) DEFAULT NULL,
  `Q12aLittle` tinyint(1) DEFAULT NULL,
  `Q12aSome` tinyint(1) DEFAULT NULL,
  `Q12aLot` tinyint(1) DEFAULT NULL,
  `Q12aMuch` tinyint(1) DEFAULT NULL,
  `Q12aCmt` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formSatisfactionScale`
--


CREATE TABLE `formSatisfactionScale` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `believe1Y` tinyint(1) DEFAULT NULL,
  `believe1N` tinyint(1) DEFAULT NULL,
  `receive2Y` tinyint(1) DEFAULT NULL,
  `receive2N` tinyint(1) DEFAULT NULL,
  `receiveOT3Y` tinyint(1) DEFAULT NULL,
  `receiveP3Y` tinyint(1) DEFAULT NULL,
  `receiveB3Y` tinyint(1) DEFAULT NULL,
  `otTreats4` char(4) DEFAULT NULL,
  `ptTreats4` char(4) DEFAULT NULL,
  `explaining1` char(2) DEFAULT NULL,
  `everythingNeeded2` char(2) DEFAULT NULL,
  `perfect3` char(2) DEFAULT NULL,
  `wonder4` char(2) DEFAULT NULL,
  `confident5` char(2) DEFAULT NULL,
  `careful6` char(2) DEFAULT NULL,
  `afford7` char(2) DEFAULT NULL,
  `easyaccess8` char(2) DEFAULT NULL,
  `toolong9` char(2) DEFAULT NULL,
  `businesslike10` char(2) DEFAULT NULL,
  `veryfriendly11` char(2) DEFAULT NULL,
  `hurrytoomuch12` char(2) DEFAULT NULL,
  `ignore13` char(2) DEFAULT NULL,
  `doubtability14` char(2) DEFAULT NULL,
  `plentyoftime15` char(2) DEFAULT NULL,
  `hardtogetanappointment16` char(2) DEFAULT NULL,
  `dissatisfied17` char(2) DEFAULT NULL,
  `abletogetrehabilitation18` char(2) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formSelfAdministered`
--


CREATE TABLE `formSelfAdministered` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `sex` varchar(1) DEFAULT NULL,
  `dob` date DEFAULT NULL,
  `healthEx` tinyint(1) DEFAULT NULL,
  `healthVG` tinyint(1) DEFAULT NULL,
  `healthG` tinyint(1) DEFAULT NULL,
  `healthF` tinyint(1) DEFAULT NULL,
  `healthP` tinyint(1) DEFAULT NULL,
  `stayInHospNo` tinyint(1) DEFAULT NULL,
  `stayInHosp1` tinyint(1) DEFAULT NULL,
  `stayInHosp2Or3` tinyint(1) DEFAULT NULL,
  `stayInHospMore3` tinyint(1) DEFAULT NULL,
  `visitPhyNo` tinyint(1) DEFAULT NULL,
  `visitPhy1` tinyint(1) DEFAULT NULL,
  `visitPhy2Or3` tinyint(1) DEFAULT NULL,
  `visitPhyMore3` tinyint(1) DEFAULT NULL,
  `diabetesY` tinyint(1) DEFAULT NULL,
  `diabetesN` tinyint(1) DEFAULT NULL,
  `heartDiseaseY` tinyint(1) DEFAULT NULL,
  `heartDiseaseN` tinyint(1) DEFAULT NULL,
  `anginaPectorisY` tinyint(1) DEFAULT NULL,
  `anginaPectorisN` tinyint(1) DEFAULT NULL,
  `myocardialInfarctionY` tinyint(1) DEFAULT NULL,
  `myocardialInfarctionN` tinyint(1) DEFAULT NULL,
  `anyHeartAttackY` tinyint(1) DEFAULT NULL,
  `anyHeartAttackN` tinyint(1) DEFAULT NULL,
  `relativeTakeCareY` tinyint(1) DEFAULT NULL,
  `relativeTakeCareN` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formSelfAssessment`
--


CREATE TABLE `formSelfAssessment` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `name` varchar(255) DEFAULT NULL,
  `p_birthdate` varchar(255) DEFAULT NULL,
  `sex` varchar(255) DEFAULT NULL,
  `faculty` varchar(255) DEFAULT NULL,
  `AcademicYear` varchar(255) DEFAULT NULL,
  `PTFT` varchar(255) DEFAULT NULL,
  `Job` varchar(255) DEFAULT NULL,
  `Hours` varchar(255) DEFAULT NULL,
  `Residence` mediumtext,
  `Campus` mediumtext,
  `Home` mediumtext,
  `Roommates` mediumtext,
  `LivingSituationOther` mediumtext,
  `Depression` mediumtext,
  `helplessness` mediumtext,
  `ADHD` mediumtext,
  `Obsessions` mediumtext,
  `Bipolar` mediumtext,
  `Anxiety` mediumtext,
  `Esteem` mediumtext,
  `Relationship` mediumtext,
  `Eating` mediumtext,
  `Sexual` mediumtext,
  `Suicidal` mediumtext,
  `Psychosis` mediumtext,
  `Mania` mediumtext,
  `Grief` mediumtext,
  `Substance` mediumtext,
  `TraumaEmotional` mediumtext,
  `TraumaPhysical` mediumtext,
  `TraumaSexual` mediumtext,
  `Academic` mediumtext,
  `ReasonsOther` mediumtext,
  `Hospitalizations` mediumtext,
  `Surgery` mediumtext,
  `Medicalillnesses` mediumtext,
  `CurrentMedications` mediumtext,
  `CurrentMedicationsList` mediumtext,
  `psychiatricMedications` mediumtext,
  `psychiatricMedicationsList` mediumtext,
  `HospitalizationsOther` mediumtext,
  `PastSubstance` mediumtext,
  `PastAlcohol` mediumtext,
  `PastPrescribedDrugs` mediumtext,
  `PastCounterMedications` mediumtext,
  `PastStreetDrugs` mediumtext,
  `PastTobacco` mediumtext,
  `PastPSYCHIATRICTraumaEmotional` mediumtext,
  `PastPSYCHIATRICTraumaPhysical` mediumtext,
  `PastPSYCHIATRICTraumaSexual` mediumtext,
  `PastLegal` mediumtext,
  `PastGambling` mediumtext,
  `PastReactionsMedication` mediumtext,
  `PastReactionsMedicationList` mediumtext,
  `PastSuicideAttempts` mediumtext,
  `PastSuicideMany` mediumtext,
  `PastSuicideWhen` mediumtext,
  `PastCutting` mediumtext,
  `ptsd` mediumtext,
  `PastPASTPSYCHIATRICOther` mediumtext,
  `AgesMother` mediumtext,
  `AgesFather` mediumtext,
  `AgesSiblings` mediumtext,
  `AgesOthers` mediumtext,
  `Adopted` mediumtext,
  `FamilyDepression` mediumtext,
  `FamilyAnxiety` mediumtext,
  `FamilySubstance` mediumtext,
  `FamilyAlcohol` mediumtext,
  `FamilyDrugs` mediumtext,
  `FamilyEmotional` mediumtext,
  `FamilyPhysical` mediumtext,
  `FamilySexual` mediumtext,
  `FamilySuicide` mediumtext,
  `FamilyEating` mediumtext,
  `FamilyBipolar` mediumtext,
  `FamilyPsychosis` mediumtext,
  `FamilySchizophrenia` mediumtext,
  `FamilyADHD` mediumtext,
  `FamilyPsychiatricOther` mediumtext,
  `Smoker` mediumtext,
  `SmokeQty` mediumtext,
  `StreetDrugs` mediumtext,
  `DrinkAlcohol` mediumtext,
  `DrinkAlcoholMany` mediumtext,
  `DrinkAlcoholWeekly` mediumtext,
  `Exercise` mediumtext,
  `Meals` mediumtext,
  `InRelationship` mediumtext,
  `AcademicPerformance` mediumtext,
  `SexualOrientation` mediumtext,
  `ReligiousAffiliation` mediumtext,
  `GeneralOther` mediumtext,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formSelfEfficacy`
--


CREATE TABLE `formSelfEfficacy` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `ex1` varchar(2) DEFAULT NULL,
  `ex2` varchar(2) DEFAULT NULL,
  `ex3` varchar(2) DEFAULT NULL,
  `exerScore` varchar(5) DEFAULT NULL,
  `disease1` varchar(2) DEFAULT NULL,
  `diseaseScore` varchar(5) DEFAULT NULL,
  `help1` varchar(2) DEFAULT NULL,
  `help2` varchar(2) DEFAULT NULL,
  `help3` varchar(2) DEFAULT NULL,
  `help4` varchar(2) DEFAULT NULL,
  `helpScore` varchar(5) DEFAULT NULL,
  `communicateWithPhy1` varchar(2) DEFAULT NULL,
  `communicateWithPhy2` varchar(2) DEFAULT NULL,
  `communicateWithPhy3` varchar(2) DEFAULT NULL,
  `commScore` varchar(5) DEFAULT NULL,
  `manageDisease1` varchar(2) DEFAULT NULL,
  `manageDisease2` varchar(2) DEFAULT NULL,
  `manageDisease3` varchar(2) DEFAULT NULL,
  `manageDisease4` varchar(2) DEFAULT NULL,
  `manageDisease5` varchar(2) DEFAULT NULL,
  `manDiseaseScore` varchar(5) DEFAULT NULL,
  `doChore1` varchar(2) DEFAULT NULL,
  `doChore2` varchar(2) DEFAULT NULL,
  `doChore3` varchar(2) DEFAULT NULL,
  `choresScore` varchar(5) DEFAULT NULL,
  `social1` varchar(2) DEFAULT NULL,
  `social2` varchar(2) DEFAULT NULL,
  `socialScore` varchar(5) DEFAULT NULL,
  `shortBreath1` varchar(2) DEFAULT NULL,
  `breathScore` varchar(5) DEFAULT NULL,
  `manageSymptoms1` varchar(2) DEFAULT NULL,
  `manageSymptoms2` varchar(2) DEFAULT NULL,
  `manageSymptoms3` varchar(2) DEFAULT NULL,
  `manageSymptoms4` varchar(2) DEFAULT NULL,
  `manageSymptoms5` varchar(2) DEFAULT NULL,
  `manSymScore` varchar(5) DEFAULT NULL,
  `controlDepress1` varchar(2) DEFAULT NULL,
  `controlDepress2` varchar(2) DEFAULT NULL,
  `controlDepress3` varchar(2) DEFAULT NULL,
  `controlDepress4` varchar(2) DEFAULT NULL,
  `controlDepress5` varchar(2) DEFAULT NULL,
  `controlDepress6` varchar(2) DEFAULT NULL,
  `manDprScore` varchar(5) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formSelfManagement`
--


CREATE TABLE `formSelfManagement` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `ex1` int(1) DEFAULT NULL,
  `ex2` int(1) DEFAULT NULL,
  `ex3` int(1) DEFAULT NULL,
  `ex4` int(1) DEFAULT NULL,
  `ex5` int(1) DEFAULT NULL,
  `ex6Spec` varchar(255) DEFAULT NULL,
  `ex6` int(1) DEFAULT NULL,
  `exTime1` int(3) DEFAULT NULL,
  `exTime2To6` int(3) DEFAULT NULL,
  `cog1` varchar(1) DEFAULT NULL,
  `cog2` varchar(1) DEFAULT NULL,
  `cog3` varchar(1) DEFAULT NULL,
  `cog4` varchar(1) DEFAULT NULL,
  `cog5` varchar(1) DEFAULT NULL,
  `cog6` varchar(1) DEFAULT NULL,
  `cogScore` varchar(4) DEFAULT NULL,
  `mentalStressTimes` int(3) DEFAULT NULL,
  `mentalStressToRelax` varchar(255) DEFAULT NULL,
  `mentalStressScore` varchar(10) DEFAULT NULL,
  `tangibleHelpHouseN` tinyint(1) DEFAULT NULL,
  `tangibleHelpHouseY` tinyint(1) DEFAULT NULL,
  `tangibleHelpYardN` tinyint(1) DEFAULT NULL,
  `tangibleHelpYardY` tinyint(1) DEFAULT NULL,
  `tangibleHelpHomeN` tinyint(1) DEFAULT NULL,
  `tangibleHelpHomeY` tinyint(1) DEFAULT NULL,
  `tangibleHelpMealN` tinyint(1) DEFAULT NULL,
  `tangibleHelpMealY` tinyint(1) DEFAULT NULL,
  `tangibleHelpHygieneN` tinyint(1) DEFAULT NULL,
  `tangibleHelpHygieneY` tinyint(1) DEFAULT NULL,
  `tangibleHelpErrandsN` tinyint(1) DEFAULT NULL,
  `tangibleHelpErrandsY` tinyint(1) DEFAULT NULL,
  `tangibleHelpTransportN` tinyint(1) DEFAULT NULL,
  `tangibleHelpTransportY` tinyint(1) DEFAULT NULL,
  `tangibleHelpScore` int(1) DEFAULT NULL,
  `emotionalSupportN` tinyint(1) DEFAULT NULL,
  `emotionalSupportY` tinyint(1) DEFAULT NULL,
  `emotionalSupportScore` int(1) DEFAULT NULL,
  `healthEducationN` tinyint(1) DEFAULT NULL,
  `healthEducationY` tinyint(1) DEFAULT NULL,
  `healthEducationHours` int(4) DEFAULT NULL,
  `healthEducationScore` varchar(10) DEFAULT NULL,
  `exercisePrgmN` tinyint(1) DEFAULT NULL,
  `exercisePrgmY` tinyint(1) DEFAULT NULL,
  `exercisePrgmHours` int(4) DEFAULT NULL,
  `exercisePrgmScore` int(1) DEFAULT NULL,
  `communicate1` varchar(1) DEFAULT NULL,
  `communicate2` varchar(1) DEFAULT NULL,
  `communicate3` varchar(1) DEFAULT NULL,
  `communicateScore` varchar(4) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formTreatmentPref`
--


CREATE TABLE `formTreatmentPref` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `studyID` varchar(20) NOT NULL DEFAULT 'N/A',
  `treatmentGr` tinyint(1) DEFAULT NULL,
  `controlGr` tinyint(1) DEFAULT NULL,
  `eitherGr` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formType2Diabetes`
--


CREATE TABLE `formType2Diabetes` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `pName` varchar(60) DEFAULT NULL,
  `birthDate` date DEFAULT NULL,
  `dateDx` date DEFAULT NULL,
  `height` varchar(10) DEFAULT NULL,
  `date1` date DEFAULT NULL,
  `date2` date DEFAULT NULL,
  `date3` date DEFAULT NULL,
  `date4` date DEFAULT NULL,
  `date5` date DEFAULT NULL,
  `weight1` varchar(20) DEFAULT NULL,
  `weight2` varchar(20) DEFAULT NULL,
  `weight3` varchar(20) DEFAULT NULL,
  `weight4` varchar(20) DEFAULT NULL,
  `weight5` varchar(20) DEFAULT NULL,
  `bp1` varchar(20) DEFAULT NULL,
  `bp2` varchar(20) DEFAULT NULL,
  `bp3` varchar(20) DEFAULT NULL,
  `bp4` varchar(20) DEFAULT NULL,
  `bp5` varchar(20) DEFAULT NULL,
  `glucoseA1` varchar(50) DEFAULT NULL,
  `glucoseA2` varchar(50) DEFAULT NULL,
  `glucoseA3` varchar(50) DEFAULT NULL,
  `glucoseA4` varchar(50) DEFAULT NULL,
  `glucoseA5` varchar(50) DEFAULT NULL,
  `glucoseB1` varchar(50) DEFAULT NULL,
  `glucoseB2` varchar(50) DEFAULT NULL,
  `glucoseB3` varchar(50) DEFAULT NULL,
  `glucoseB4` varchar(50) DEFAULT NULL,
  `glucoseB5` varchar(50) DEFAULT NULL,
  `glucoseC1` varchar(50) DEFAULT NULL,
  `glucoseC2` varchar(50) DEFAULT NULL,
  `glucoseC3` varchar(50) DEFAULT NULL,
  `glucoseC4` varchar(50) DEFAULT NULL,
  `glucoseC5` varchar(50) DEFAULT NULL,
  `renal1` varchar(50) DEFAULT NULL,
  `renal2` varchar(50) DEFAULT NULL,
  `renal3` varchar(50) DEFAULT NULL,
  `renal4` varchar(50) DEFAULT NULL,
  `renal5` varchar(50) DEFAULT NULL,
  `urineRatio1` varchar(50) DEFAULT NULL,
  `urineRatio2` varchar(50) DEFAULT NULL,
  `urineRatio3` varchar(50) DEFAULT NULL,
  `urineRatio4` varchar(50) DEFAULT NULL,
  `urineRatio5` varchar(50) DEFAULT NULL,
  `urineClearance1` varchar(100) DEFAULT NULL,
  `urineClearance2` varchar(100) DEFAULT NULL,
  `urineClearance3` varchar(100) DEFAULT NULL,
  `urineClearance4` varchar(100) DEFAULT NULL,
  `urineClearance5` varchar(100) DEFAULT NULL,
  `lipidsA1` varchar(30) DEFAULT NULL,
  `lipidsA2` varchar(30) DEFAULT NULL,
  `lipidsA3` varchar(30) DEFAULT NULL,
  `lipidsA4` varchar(30) DEFAULT NULL,
  `lipidsA5` varchar(30) DEFAULT NULL,
  `lipidsB1` varchar(30) DEFAULT NULL,
  `lipidsB2` varchar(30) DEFAULT NULL,
  `lipidsB3` varchar(30) DEFAULT NULL,
  `lipidsB4` varchar(30) DEFAULT NULL,
  `lipidsB5` varchar(30) DEFAULT NULL,
  `lipidsC1` varchar(30) DEFAULT NULL,
  `lipidsC2` varchar(30) DEFAULT NULL,
  `lipidsC3` varchar(30) DEFAULT NULL,
  `lipidsC4` varchar(30) DEFAULT NULL,
  `lipidsC5` varchar(30) DEFAULT NULL,
  `ophthalmologist` varchar(50) DEFAULT NULL,
  `eyes1` varchar(50) DEFAULT NULL,
  `eyes2` varchar(50) DEFAULT NULL,
  `eyes3` varchar(50) DEFAULT NULL,
  `eyes4` varchar(50) DEFAULT NULL,
  `eyes5` varchar(50) DEFAULT NULL,
  `feet1` varchar(100) DEFAULT NULL,
  `feet2` varchar(100) DEFAULT NULL,
  `feet3` varchar(100) DEFAULT NULL,
  `feet4` varchar(100) DEFAULT NULL,
  `feet5` varchar(100) DEFAULT NULL,
  `metformin` tinyint(1) DEFAULT NULL,
  `aceInhibitor` tinyint(1) DEFAULT NULL,
  `glyburide` tinyint(1) DEFAULT NULL,
  `asa` tinyint(1) DEFAULT NULL,
  `otherOha` tinyint(1) DEFAULT NULL,
  `otherBox7` varchar(20) DEFAULT NULL,
  `insulin` tinyint(1) DEFAULT NULL,
  `otherBox8` varchar(20) DEFAULT NULL,
  `meds1` varchar(100) DEFAULT NULL,
  `meds2` varchar(100) DEFAULT NULL,
  `meds3` varchar(100) DEFAULT NULL,
  `meds4` varchar(100) DEFAULT NULL,
  `meds5` varchar(100) DEFAULT NULL,
  `lifestyle1` varchar(50) DEFAULT NULL,
  `lifestyle2` varchar(50) DEFAULT NULL,
  `lifestyle3` varchar(50) DEFAULT NULL,
  `lifestyle4` varchar(50) DEFAULT NULL,
  `lifestyle5` varchar(50) DEFAULT NULL,
  `exercise1` varchar(50) DEFAULT NULL,
  `exercise2` varchar(50) DEFAULT NULL,
  `exercise3` varchar(50) DEFAULT NULL,
  `exercise4` varchar(50) DEFAULT NULL,
  `exercise5` varchar(50) DEFAULT NULL,
  `alcohol1` varchar(50) DEFAULT NULL,
  `alcohol2` varchar(50) DEFAULT NULL,
  `alcohol3` varchar(50) DEFAULT NULL,
  `alcohol4` varchar(50) DEFAULT NULL,
  `alcohol5` varchar(50) DEFAULT NULL,
  `sexualFunction1` varchar(50) DEFAULT NULL,
  `sexualFunction2` varchar(50) DEFAULT NULL,
  `sexualFunction3` varchar(50) DEFAULT NULL,
  `sexualFunction4` varchar(50) DEFAULT NULL,
  `sexualFunction5` varchar(50) DEFAULT NULL,
  `diet1` varchar(50) DEFAULT NULL,
  `diet2` varchar(50) DEFAULT NULL,
  `diet3` varchar(50) DEFAULT NULL,
  `diet4` varchar(50) DEFAULT NULL,
  `diet5` varchar(50) DEFAULT NULL,
  `otherPlan1` varchar(100) DEFAULT NULL,
  `otherPlan2` varchar(100) DEFAULT NULL,
  `otherPlan3` varchar(100) DEFAULT NULL,
  `otherPlan4` varchar(100) DEFAULT NULL,
  `otherPlan5` varchar(100) DEFAULT NULL,
  `consultant` varchar(30) DEFAULT NULL,
  `educator` varchar(30) DEFAULT NULL,
  `nutritionist` varchar(30) DEFAULT NULL,
  `cdn1` varchar(100) DEFAULT NULL,
  `cdn2` varchar(100) DEFAULT NULL,
  `cdn3` varchar(100) DEFAULT NULL,
  `cdn4` varchar(100) DEFAULT NULL,
  `cdn5` varchar(100) DEFAULT NULL,
  `initials1` varchar(30) DEFAULT NULL,
  `initials2` varchar(30) DEFAULT NULL,
  `initials3` varchar(30) DEFAULT NULL,
  `initials4` varchar(30) DEFAULT NULL,
  `initials5` varchar(30) DEFAULT NULL,
  `resource1` tinyint(1) DEFAULT NULL,
  `resource2` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formVTForm`
--


CREATE TABLE `formVTForm` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `visitCod` varchar(10) DEFAULT NULL,
  `HTValue` varchar(10) DEFAULT NULL,
  `HTDate` varchar(10) DEFAULT NULL,
  `HTComments` varchar(255) DEFAULT NULL,
  `WTValue` varchar(10) DEFAULT NULL,
  `WTDate` varchar(10) DEFAULT NULL,
  `WTComments` varchar(255) DEFAULT NULL,
  `WHRValue` varchar(10) DEFAULT NULL,
  `WHRDate` varchar(10) DEFAULT NULL,
  `WHRComments` varchar(255) DEFAULT NULL,
  `WCValue` varchar(10) DEFAULT NULL,
  `WCDate` varchar(10) DEFAULT NULL,
  `WCComments` varchar(255) DEFAULT NULL,
  `HCValue` varchar(10) DEFAULT NULL,
  `HCDate` varchar(10) DEFAULT NULL,
  `HCComments` varchar(255) DEFAULT NULL,
  `BPValue` varchar(10) DEFAULT NULL,
  `BPDate` varchar(10) DEFAULT NULL,
  `BPComments` varchar(255) DEFAULT NULL,
  `HRValue` varchar(10) DEFAULT NULL,
  `HRDate` varchar(10) DEFAULT NULL,
  `HRComments` varchar(255) DEFAULT NULL,
  `HbA1Value` varchar(10) DEFAULT NULL,
  `HbA1Date` varchar(10) DEFAULT NULL,
  `HbA1Comments` varchar(255) DEFAULT NULL,
  `BGValue` varchar(10) DEFAULT NULL,
  `BGDate` varchar(10) DEFAULT NULL,
  `BGComments` varchar(255) DEFAULT NULL,
  `LDLValue` varchar(10) DEFAULT NULL,
  `LDLDate` varchar(10) DEFAULT NULL,
  `LDLComments` varchar(255) DEFAULT NULL,
  `HDLValue` varchar(10) DEFAULT NULL,
  `HDLDate` varchar(10) DEFAULT NULL,
  `HDLComments` varchar(255) DEFAULT NULL,
  `TCHLValue` varchar(10) DEFAULT NULL,
  `TCHLDate` varchar(10) DEFAULT NULL,
  `TCHLComments` varchar(255) DEFAULT NULL,
  `TRIGValue` varchar(10) DEFAULT NULL,
  `TRIGDate` varchar(10) DEFAULT NULL,
  `TRIGComments` varchar(255) DEFAULT NULL,
  `UALBValue` varchar(10) DEFAULT NULL,
  `UALBDate` varchar(10) DEFAULT NULL,
  `UALBComments` varchar(255) DEFAULT NULL,
  `24UAValue` varchar(10) DEFAULT NULL,
  `24UADate` varchar(10) DEFAULT NULL,
  `24UAComments` varchar(255) DEFAULT NULL,
  `FTExValue` varchar(10) DEFAULT NULL,
  `FTExDate` varchar(10) DEFAULT NULL,
  `FTExComments` varchar(255) DEFAULT NULL,
  `FTNeValue` varchar(10) DEFAULT NULL,
  `FTNeDate` varchar(10) DEFAULT NULL,
  `FTNeComments` varchar(255) DEFAULT NULL,
  `FTIsValue` varchar(10) DEFAULT NULL,
  `FTIsDate` varchar(10) DEFAULT NULL,
  `FTIsComments` varchar(255) DEFAULT NULL,
  `FTUlValue` varchar(10) DEFAULT NULL,
  `FTUlDate` varchar(10) DEFAULT NULL,
  `FTUlComments` varchar(255) DEFAULT NULL,
  `FTInValue` varchar(10) DEFAULT NULL,
  `FTInDate` varchar(10) DEFAULT NULL,
  `FTInComments` varchar(255) DEFAULT NULL,
  `FTOtValue` varchar(10) DEFAULT NULL,
  `FTOtDate` varchar(10) DEFAULT NULL,
  `FTOtComments` varchar(255) DEFAULT NULL,
  `FTReValue` varchar(10) DEFAULT NULL,
  `FTReDate` varchar(10) DEFAULT NULL,
  `FTReComments` varchar(255) DEFAULT NULL,
  `iExValue` varchar(10) DEFAULT NULL,
  `iExDate` varchar(10) DEFAULT NULL,
  `iExComments` varchar(255) DEFAULT NULL,
  `iDiaValue` varchar(10) DEFAULT NULL,
  `iDiaDate` varchar(10) DEFAULT NULL,
  `iDiaComments` varchar(255) DEFAULT NULL,
  `iHypValue` varchar(10) DEFAULT NULL,
  `iHypDate` varchar(10) DEFAULT NULL,
  `iHypComments` varchar(255) DEFAULT NULL,
  `iOthValue` varchar(10) DEFAULT NULL,
  `iOthDate` varchar(10) DEFAULT NULL,
  `iOthComments` varchar(255) DEFAULT NULL,
  `iRefValue` varchar(10) DEFAULT NULL,
  `iRefDate` varchar(10) DEFAULT NULL,
  `iRefComments` varchar(255) DEFAULT NULL,
  `SmkSValue` varchar(10) DEFAULT NULL,
  `SmkSDate` varchar(10) DEFAULT NULL,
  `SmkSComments` varchar(255) DEFAULT NULL,
  `SmkHValue` varchar(10) DEFAULT NULL,
  `SmkHDate` varchar(10) DEFAULT NULL,
  `SmkHComments` varchar(255) DEFAULT NULL,
  `SmkCValue` varchar(10) DEFAULT NULL,
  `SmkCDate` varchar(10) DEFAULT NULL,
  `SmkCComments` varchar(255) DEFAULT NULL,
  `ExerValue` varchar(10) DEFAULT NULL,
  `ExerDate` varchar(10) DEFAULT NULL,
  `ExerComments` varchar(255) DEFAULT NULL,
  `DietValue` varchar(10) DEFAULT NULL,
  `DietDate` varchar(10) DEFAULT NULL,
  `DietComments` varchar(255) DEFAULT NULL,
  `DpScValue` varchar(10) DEFAULT NULL,
  `DpScDate` varchar(10) DEFAULT NULL,
  `DpScComments` varchar(255) DEFAULT NULL,
  `StScValue` varchar(10) DEFAULT NULL,
  `StScDate` varchar(10) DEFAULT NULL,
  `StScComments` varchar(255) DEFAULT NULL,
  `LcCtValue` varchar(10) DEFAULT NULL,
  `LcCtDate` varchar(10) DEFAULT NULL,
  `LcCtComments` varchar(255) DEFAULT NULL,
  `MedGValue` varchar(10) DEFAULT NULL,
  `MedGDate` varchar(10) DEFAULT NULL,
  `MedGComments` varchar(255) DEFAULT NULL,
  `MedNValue` varchar(10) DEFAULT NULL,
  `MedNDate` varchar(10) DEFAULT NULL,
  `MedNComments` varchar(255) DEFAULT NULL,
  `MedRValue` varchar(10) DEFAULT NULL,
  `MedRDate` varchar(10) DEFAULT NULL,
  `MedRComments` varchar(255) DEFAULT NULL,
  `MedAValue` varchar(10) DEFAULT NULL,
  `MedADate` varchar(10) DEFAULT NULL,
  `MedAComments` varchar(255) DEFAULT NULL,
  `NtrCValue` varchar(10) DEFAULT NULL,
  `NtrCDate` varchar(10) DEFAULT NULL,
  `NtrCComments` varchar(255) DEFAULT NULL,
  `ExeCValue` varchar(10) DEFAULT NULL,
  `ExeCDate` varchar(10) DEFAULT NULL,
  `ExeCComments` varchar(255) DEFAULT NULL,
  `SmCCValue` varchar(10) DEFAULT NULL,
  `SmCCDate` varchar(10) DEFAULT NULL,
  `SmCCComments` varchar(255) DEFAULT NULL,
  `DiaCValue` varchar(10) DEFAULT NULL,
  `DiaCDate` varchar(10) DEFAULT NULL,
  `DiaCComments` varchar(255) DEFAULT NULL,
  `PsyCValue` varchar(10) DEFAULT NULL,
  `PsyCDate` varchar(10) DEFAULT NULL,
  `PsyCComments` varchar(255) DEFAULT NULL,
  `OthCValue` varchar(10) DEFAULT NULL,
  `OthCDate` varchar(10) DEFAULT NULL,
  `OthCComments` varchar(255) DEFAULT NULL,
  `DMValue` varchar(10) DEFAULT NULL,
  `HTNValue` varchar(10) DEFAULT NULL,
  `HchlValue` varchar(10) DEFAULT NULL,
  `MIValue` varchar(10) DEFAULT NULL,
  `AngValue` varchar(10) DEFAULT NULL,
  `ACSValue` varchar(10) DEFAULT NULL,
  `RVTNValue` varchar(10) DEFAULT NULL,
  `CVDValue` varchar(10) DEFAULT NULL,
  `PVDValue` varchar(10) DEFAULT NULL,
  `Diagnosis` text,
  `Subjective` text,
  `Objective` text,
  `Assessment` text,
  `Plan` text,
  `WHRBValue` varchar(10) DEFAULT NULL,
  `WHRBDate` varchar(10) DEFAULT NULL,
  `WHRBComments` varchar(255) DEFAULT NULL,
  `WHRBLastData` varchar(10) DEFAULT NULL,
  `WHRBLastDataEnteredDate` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `ID` (`ID`),
  KEY `demographic_no` (`demographic_no`)
);

--
-- Table structure for table `form_hsfo2_visit`
--


CREATE TABLE `form_hsfo2_visit` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL,
  `provider_no` varchar(10) NOT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `Patient_Id` varchar(255) NOT NULL,
  `VisitDate_Id` date NOT NULL,
  `Drugcoverage` enum('yes','no','null') DEFAULT NULL,
  `SBP` int(3) DEFAULT NULL,
  `SBP_goal` int(3) DEFAULT NULL,
  `DBP` int(3) DEFAULT NULL,
  `DBP_goal` int(3) DEFAULT NULL,
  `Height` double(4,1) NOT NULL,
  `Height_unit` enum('cm','inch') NOT NULL,
  `Bptru_used` enum('yes','no','null') DEFAULT NULL,
  `Weight` double(4,1) DEFAULT NULL,
  `Weight_unit` enum('kg','lb','null') DEFAULT NULL,
  `Waist` double(4,1) DEFAULT NULL,
  `Waist_unit` enum('cm','inch','null') DEFAULT NULL,
  `TC_HDL` double(3,1) DEFAULT NULL,
  `LDL` double(3,1) DEFAULT NULL,
  `HDL` double(2,1) DEFAULT NULL,
  `Triglycerides` double(3,1) DEFAULT NULL,
  `Nextvisit` enum('Under1Mo','1to2Mo','3to6Mo','Over6Mo','null') DEFAULT NULL,
  `Bpactionplan` tinyint(1) NOT NULL,
  `PressureOff` tinyint(1) NOT NULL,
  `PatientProvider` tinyint(1) NOT NULL,
  `ABPM` tinyint(1) NOT NULL,
  `Home` tinyint(1) NOT NULL,
  `CommunityRes` tinyint(1) NOT NULL,
  `ProRefer` tinyint(1) NOT NULL,
  `HtnDxType` enum('PrimaryHtn','ElevatedBpReadings','null') DEFAULT NULL,
  `Dyslipid` tinyint(1) NOT NULL,
  `Diabetes` tinyint(1) NOT NULL,
  `KidneyDis` tinyint(1) NOT NULL,
  `Obesity` tinyint(1) NOT NULL,
  `CHD` tinyint(1) NOT NULL,
  `Stroke_TIA` tinyint(1) NOT NULL,
  `Risk_weight` tinyint(1) DEFAULT NULL,
  `Risk_activity` tinyint(1) DEFAULT NULL,
  `Risk_diet` tinyint(1) DEFAULT NULL,
  `Risk_smoking` tinyint(1) DEFAULT NULL,
  `Risk_alcohol` tinyint(1) DEFAULT NULL,
  `Risk_stress` tinyint(1) DEFAULT NULL,
  `PtView` enum('Uninterested','Thinking','Deciding','TakingAction','Maintaining','Relapsing','null') DEFAULT NULL,
  `Change_importance` int(2) DEFAULT NULL,
  `Change_confidence` int(2) DEFAULT NULL,
  `exercise_minPerWk` int(3) DEFAULT NULL,
  `smoking_cigsPerDay` int(2) DEFAULT NULL,
  `alcohol_drinksPerWk` int(2) DEFAULT NULL,
  `sel_DashDiet` enum('Always','Often','Sometimes','Never','null') DEFAULT NULL,
  `sel_HighSaltFood` enum('Always','Often','Sometimes','Never','null') DEFAULT NULL,
  `sel_Stressed` enum('Always','Often','Sometimes','Never','null') DEFAULT NULL,
  `LifeGoal` enum('Goal_weight','Goal_activity','Goal_dietDash','Goal_dietSalt','Goal_smoking','Goal_alcohol','Goal_stress','null') DEFAULT NULL,
  `FamHx_Htn` tinyint(1) NOT NULL,
  `FamHx_Dyslipid` tinyint(1) NOT NULL,
  `FamHx_Diabetes` tinyint(1) NOT NULL,
  `FamHx_KidneyDis` tinyint(1) NOT NULL,
  `FamHx_Obesity` tinyint(1) NOT NULL,
  `FamHx_CHD` tinyint(1) NOT NULL,
  `FamHx_Stroke_TIA` tinyint(1) NOT NULL,
  `Diuret_rx` tinyint(1) NOT NULL,
  `Diuret_SideEffects` tinyint(1) NOT NULL,
  `Diuret_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Ace_rx` tinyint(1) NOT NULL,
  `Ace_SideEffects` tinyint(1) NOT NULL,
  `Ace_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Arecept_rx` tinyint(1) NOT NULL,
  `Arecept_SideEffects` tinyint(1) NOT NULL,
  `Arecept_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Beta_rx` tinyint(1) NOT NULL,
  `Beta_SideEffects` tinyint(1) NOT NULL,
  `Beta_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Calc_rx` tinyint(1) NOT NULL,
  `Calc_SideEffects` tinyint(1) NOT NULL,
  `Calc_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Anti_rx` tinyint(1) NOT NULL,
  `Anti_SideEffects` tinyint(1) NOT NULL,
  `Anti_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Statin_rx` tinyint(1) NOT NULL,
  `Statin_SideEffects` tinyint(1) NOT NULL,
  `Statin_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Lipid_rx` tinyint(1) NOT NULL,
  `Lipid_SideEffects` tinyint(1) NOT NULL,
  `Lipid_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Hypo_rx` tinyint(1) NOT NULL,
  `Hypo_SideEffects` tinyint(1) NOT NULL,
  `Hypo_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Insul_rx` tinyint(1) NOT NULL,
  `Insul_SideEffects` tinyint(1) NOT NULL,
  `Insul_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  `Often_miss` int(2) DEFAULT NULL,
  `Herbal` enum('yes','no','null') DEFAULT NULL,
  `TC_HDL_LabresultsDate` date DEFAULT NULL,
  `LDL_LabresultsDate` date DEFAULT NULL,
  `HDL_LabresultsDate` date DEFAULT NULL,
  `A1C_LabresultsDate` date DEFAULT NULL,
  `Locked` tinyint(1) DEFAULT NULL,
  `depression` tinyint(1) DEFAULT NULL,
  `famHx_depression` tinyint(1) DEFAULT NULL,
  `assessActivity` int(3) DEFAULT NULL,
  `assessSmoking` int(3) DEFAULT NULL,
  `assessAlcohol` int(3) DEFAULT NULL,
  `nextVisitInMonths` int(3) DEFAULT NULL,
  `nextVisitInWeeks` int(3) DEFAULT NULL,
  `monitor` tinyint(1) DEFAULT NULL,
  `egfrDate` date DEFAULT NULL,
  `egfr` int(3) DEFAULT NULL,
  `acr` double(5,1) DEFAULT NULL,
  `lastBaseLineRecord` tinyint(1) NOT NULL,
  `A1C` double(3,3) DEFAULT NULL,
  `fbs` double(3,1) DEFAULT NULL,
  `ASA_rx` tinyint(1) NOT NULL,
  `ASA_SideEffects` tinyint(1) NOT NULL,
  `ASA_RxDecToday` enum('Same','Increase','Decrease','Stop','Start','InClassSwitch','null') DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `formchf`
--


CREATE TABLE `formchf` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` int(10) DEFAULT NULL,
  `formCreated` date DEFAULT NULL,
  `formEdited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `pName` varchar(60) DEFAULT NULL,
  `sex` varchar(1) DEFAULT NULL,
  `birthDate` varchar(15) DEFAULT NULL,
  `SHFDx` tinyint(1) DEFAULT NULL,
  `PSFDx` tinyint(1) DEFAULT NULL,
  `dateFlu` date DEFAULT NULL,
  `datePneumo` date DEFAULT NULL,
  `dateEcho` date DEFAULT NULL,
  `dateCXR` date DEFAULT NULL,
  `CXRedema` tinyint(1) DEFAULT NULL,
  `CXRcardiomegaly` tinyint(1) DEFAULT NULL,
  `CXReffusion` tinyint(1) DEFAULT NULL,
  `dateEKG` date DEFAULT NULL,
  `CBC` tinyint(1) DEFAULT NULL,
  `lytes` tinyint(1) DEFAULT NULL,
  `creat` tinyint(1) DEFAULT NULL,
  `ua` tinyint(1) DEFAULT NULL,
  `RBS` tinyint(1) DEFAULT NULL,
  `lipids` tinyint(1) DEFAULT NULL,
  `LFT` tinyint(1) DEFAULT NULL,
  `TSH` tinyint(1) DEFAULT NULL,
  `date1` date DEFAULT NULL,
  `date2` date DEFAULT NULL,
  `date3` date DEFAULT NULL,
  `weight1` varchar(5) DEFAULT NULL,
  `weight2` varchar(5) DEFAULT NULL,
  `weight3` varchar(5) DEFAULT NULL,
  `fatigue1` tinyint(1) DEFAULT NULL,
  `dizzy1` tinyint(1) DEFAULT NULL,
  `SOBOE1` tinyint(1) DEFAULT NULL,
  `SOBresting1` tinyint(1) DEFAULT NULL,
  `orthopnea1` tinyint(1) DEFAULT NULL,
  `PND1` tinyint(1) DEFAULT NULL,
  `fatigue2` tinyint(1) DEFAULT NULL,
  `dizzy2` tinyint(1) DEFAULT NULL,
  `SOBOE2` tinyint(1) DEFAULT NULL,
  `SOBresting2` tinyint(1) DEFAULT NULL,
  `orthopnea2` tinyint(1) DEFAULT NULL,
  `PND2` tinyint(1) DEFAULT NULL,
  `fatigue3` tinyint(1) DEFAULT NULL,
  `dizzy3` tinyint(1) DEFAULT NULL,
  `SOBOE3` tinyint(1) DEFAULT NULL,
  `SOBresting3` tinyint(1) DEFAULT NULL,
  `orthopnea3` tinyint(1) DEFAULT NULL,
  `PND3` tinyint(1) DEFAULT NULL,
  `NYHAI1` tinyint(1) DEFAULT NULL,
  `NYHAII1` tinyint(1) DEFAULT NULL,
  `NYHAIII1` tinyint(1) DEFAULT NULL,
  `NYHAIV1` tinyint(1) DEFAULT NULL,
  `NYHAI2` tinyint(1) DEFAULT NULL,
  `NYHAII2` tinyint(1) DEFAULT NULL,
  `NYHAIII2` tinyint(1) DEFAULT NULL,
  `NYHAIV2` tinyint(1) DEFAULT NULL,
  `NYHAI3` tinyint(1) DEFAULT NULL,
  `NYHAII3` tinyint(1) DEFAULT NULL,
  `NYHAIII3` tinyint(1) DEFAULT NULL,
  `NYHAIV3` tinyint(1) DEFAULT NULL,
  `BP1` varchar(8) DEFAULT NULL,
  `BP2` varchar(8) DEFAULT NULL,
  `BP3` varchar(8) DEFAULT NULL,
  `JVPyes1` tinyint(1) DEFAULT NULL,
  `JVPno1` tinyint(1) DEFAULT NULL,
  `JVPyes2` tinyint(1) DEFAULT NULL,
  `JVPno2` tinyint(1) DEFAULT NULL,
  `JVPyes3` tinyint(1) DEFAULT NULL,
  `JVPno3` tinyint(1) DEFAULT NULL,
  `edemayes1` tinyint(1) DEFAULT NULL,
  `edemano1` tinyint(1) DEFAULT NULL,
  `edema1` varchar(30) DEFAULT NULL,
  `edemayes2` tinyint(1) DEFAULT NULL,
  `edemano2` tinyint(1) DEFAULT NULL,
  `edema2` varchar(30) DEFAULT NULL,
  `edemayes3` tinyint(1) DEFAULT NULL,
  `edemano3` tinyint(1) DEFAULT NULL,
  `edema3` varchar(30) DEFAULT NULL,
  `cracklesyes1` tinyint(1) DEFAULT NULL,
  `cracklesno1` tinyint(1) DEFAULT NULL,
  `crackles1` varchar(30) DEFAULT NULL,
  `cracklesyes2` tinyint(1) DEFAULT NULL,
  `cracklesno2` tinyint(1) DEFAULT NULL,
  `crackles2` varchar(30) DEFAULT NULL,
  `cracklesyes3` tinyint(1) DEFAULT NULL,
  `cracklesno3` tinyint(1) DEFAULT NULL,
  `crackles3` varchar(30) DEFAULT NULL,
  `PI1` varchar(60) DEFAULT NULL,
  `PI2` varchar(60) DEFAULT NULL,
  `PI3` varchar(60) DEFAULT NULL,
  `Na1` varchar(10) DEFAULT NULL,
  `Na2` varchar(10) DEFAULT NULL,
  `Na3` varchar(10) DEFAULT NULL,
  `K1` varchar(4) DEFAULT NULL,
  `K2` varchar(4) DEFAULT NULL,
  `K3` varchar(4) DEFAULT NULL,
  `creat1` varchar(4) DEFAULT NULL,
  `creat2` varchar(4) DEFAULT NULL,
  `creat3` varchar(4) DEFAULT NULL,
  `eGFR1` varchar(4) DEFAULT NULL,
  `eGFR2` varchar(4) DEFAULT NULL,
  `eGFR3` varchar(4) DEFAULT NULL,
  `ervisits1` varchar(20) DEFAULT NULL,
  `ervisits2` varchar(20) DEFAULT NULL,
  `ervisits3` varchar(20) DEFAULT NULL,
  `compliance1` tinyint(1) DEFAULT NULL,
  `fluids1` tinyint(1) DEFAULT NULL,
  `weights1` tinyint(1) DEFAULT NULL,
  `exercise1` tinyint(1) DEFAULT NULL,
  `compliance2` tinyint(1) DEFAULT NULL,
  `fluids2` tinyint(1) DEFAULT NULL,
  `weights2` tinyint(1) DEFAULT NULL,
  `exercise2` tinyint(1) DEFAULT NULL,
  `compliance3` tinyint(1) DEFAULT NULL,
  `fluids3` tinyint(1) DEFAULT NULL,
  `weights3` tinyint(1) DEFAULT NULL,
  `exercise3` tinyint(1) DEFAULT NULL,
  `discussbp1` tinyint(1) DEFAULT NULL,
  `discussdm1` tinyint(1) DEFAULT NULL,
  `discusslipids1` tinyint(1) DEFAULT NULL,
  `discusssmoking1` tinyint(1) DEFAULT NULL,
  `discussweight1` tinyint(1) DEFAULT NULL,
  `discussbp2` tinyint(1) DEFAULT NULL,
  `discussdm2` tinyint(1) DEFAULT NULL,
  `discusslipids2` tinyint(1) DEFAULT NULL,
  `discusssmoking2` tinyint(1) DEFAULT NULL,
  `discussweight2` tinyint(1) DEFAULT NULL,
  `discussbp3` tinyint(1) DEFAULT NULL,
  `discussdm3` tinyint(1) DEFAULT NULL,
  `discusslipids3` tinyint(1) DEFAULT NULL,
  `discusssmoking3` tinyint(1) DEFAULT NULL,
  `discussweight3` tinyint(1) DEFAULT NULL,
  `goal1` varchar(60) DEFAULT NULL,
  `goal2` varchar(60) DEFAULT NULL,
  `goal3` varchar(60) DEFAULT NULL,
  `challange1` varchar(60) DEFAULT NULL,
  `challange2` varchar(60) DEFAULT NULL,
  `challange3` varchar(60) DEFAULT NULL,
  `ACEintolerant` tinyint(1) DEFAULT NULL,
  `ACEcontraindicated` tinyint(1) DEFAULT NULL,
  `ACE1` varchar(40) DEFAULT NULL,
  `ACEtargetY1` tinyint(1) DEFAULT NULL,
  `ACEtargetN1` tinyint(1) DEFAULT NULL,
  `ACE2` varchar(40) DEFAULT NULL,
  `ACEtargetY2` tinyint(1) DEFAULT NULL,
  `ACEtargetN2` tinyint(1) DEFAULT NULL,
  `ACE3` varchar(40) DEFAULT NULL,
  `ACEtargetY3` tinyint(1) DEFAULT NULL,
  `ACEtargetN3` tinyint(1) DEFAULT NULL,
  `bbintolerant` tinyint(1) DEFAULT NULL,
  `bbcontraindicated` tinyint(1) DEFAULT NULL,
  `bb1` varchar(40) DEFAULT NULL,
  `bbtargetY1` tinyint(1) DEFAULT NULL,
  `bbtargetN1` tinyint(1) DEFAULT NULL,
  `bb2` varchar(40) DEFAULT NULL,
  `bbtargetY2` tinyint(1) DEFAULT NULL,
  `bbtargetN2` tinyint(1) DEFAULT NULL,
  `bb3` varchar(40) DEFAULT NULL,
  `bbtargetY3` tinyint(1) DEFAULT NULL,
  `bbtargetN3` tinyint(1) DEFAULT NULL,
  `ARB1` varchar(40) DEFAULT NULL,
  `ARBtargetY1` tinyint(1) DEFAULT NULL,
  `ARBtargetN1` tinyint(1) DEFAULT NULL,
  `ARB2` varchar(40) DEFAULT NULL,
  `ARBtargetY2` tinyint(1) DEFAULT NULL,
  `ARBtargetN2` tinyint(1) DEFAULT NULL,
  `ARB3` varchar(40) DEFAULT NULL,
  `ARBtargetY3` tinyint(1) DEFAULT NULL,
  `ARBtargetN3` tinyint(1) DEFAULT NULL,
  `loop1` varchar(40) DEFAULT NULL,
  `loop2` varchar(40) DEFAULT NULL,
  `loop3` varchar(40) DEFAULT NULL,
  `spironolactone1` varchar(10) DEFAULT NULL,
  `spironolactone2` varchar(10) DEFAULT NULL,
  `spironolactone3` varchar(10) DEFAULT NULL,
  `digoxin1` varchar(10) DEFAULT NULL,
  `digoxin2` varchar(10) DEFAULT NULL,
  `digoxin3` varchar(10) DEFAULT NULL,
  `ASA1` varchar(20) DEFAULT NULL,
  `ASA2` varchar(20) DEFAULT NULL,
  `ASA3` varchar(20) DEFAULT NULL,
  `anticoagulant1` varchar(40) DEFAULT NULL,
  `anticoagulant2` varchar(40) DEFAULT NULL,
  `anticoagulant3` varchar(40) DEFAULT NULL,
  `sig1` varchar(20) DEFAULT NULL,
  `sig2` varchar(20) DEFAULT NULL,
  `sig3` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `groupMembers_tbl`
--


CREATE TABLE `groupMembers_tbl` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `groupID` int(10) DEFAULT NULL,
  `provider_No` varchar(6) DEFAULT NULL,
  `facilityId` int(6) DEFAULT NULL,
  `clinicLocationNo` int(6) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `groups_tbl`
--


CREATE TABLE `groups_tbl` (
  `groupID` int(10) NOT NULL AUTO_INCREMENT,
  `parentID` int(10) DEFAULT NULL,
  `groupDesc` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`groupID`)
);

--
-- Table structure for table `gstControl`
--


CREATE TABLE `gstControl` (
  `gstFlag` int(1) NOT NULL DEFAULT '0',
  `gstPercent` int(3) NOT NULL DEFAULT '0',
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `hash_audit`
--


CREATE TABLE `hash_audit` (
  `pkid` int(10) NOT NULL AUTO_INCREMENT,
  `signature` varchar(255) NOT NULL,
  `id` int(10) DEFAULT '0',
  `type` char(3) NOT NULL,
  `algorithm` varchar(127) DEFAULT NULL,
  PRIMARY KEY (`pkid`)
);

--
-- Table structure for table `hl7TextInfo`
--


CREATE TABLE `hl7TextInfo` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `lab_no` int(10) NOT NULL,
  `sex` varchar(1) DEFAULT NULL,
  `health_no` varchar(12) DEFAULT NULL,
  `result_status` varchar(1) DEFAULT NULL,
  `final_result_count` int(10) DEFAULT NULL,
  `obr_date` varchar(20) DEFAULT NULL,
  `priority` varchar(1) DEFAULT NULL,
  `requesting_client` varchar(100) DEFAULT NULL,
  `discipline` varchar(100) DEFAULT NULL,
  `last_name` varchar(30) DEFAULT NULL,
  `first_name` varchar(30) DEFAULT NULL,
  `report_status` varchar(20) NOT NULL,
  `accessionNum` varchar(255) DEFAULT NULL,
  `filler_order_num` varchar(50) DEFAULT NULL,
  `sending_facility` varchar(50) DEFAULT NULL,
  `label` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `labno_index` (`lab_no`),
  KEY `accession_index` (`accessionNum`)
);

--
-- Table structure for table `hl7TextMessage`
--


CREATE TABLE `hl7TextMessage` (
  `lab_id` int(10) NOT NULL AUTO_INCREMENT,
  `fileUploadCheck_id` int(10) NOT NULL,
  `message` longtext NOT NULL,
  `type` varchar(100) NOT NULL,
  `serviceName` varchar(100) NOT NULL,
  `created` datetime NOT NULL,
  PRIMARY KEY (`lab_id`)
);

--
-- Table structure for table `hsfo2_patient`
--


CREATE TABLE `hsfo2_patient` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `SiteCode` varchar(10) NOT NULL,
  `Patient_Id` varchar(255) NOT NULL,
  `FName` text NOT NULL,
  `LName` text NOT NULL,
  `BirthDate` date NOT NULL,
  `Sex` enum('m','f') NOT NULL,
  `PostalCode` varchar(7) NOT NULL,
  `Ethnic_White` tinyint(1) NOT NULL,
  `Ethnic_Black` tinyint(1) NOT NULL,
  `Ethnic_EIndian` tinyint(1) NOT NULL,
  `Ethnic_Pakistani` tinyint(1) NOT NULL,
  `Ethnic_SriLankan` tinyint(1) NOT NULL,
  `Ethnic_Bangladeshi` tinyint(1) NOT NULL,
  `Ethnic_Chinese` tinyint(1) NOT NULL,
  `Ethnic_Japanese` tinyint(1) NOT NULL,
  `Ethnic_Korean` tinyint(1) NOT NULL,
  `Ethnic_Hispanic` tinyint(1) NOT NULL,
  `Ethnic_FirstNation` tinyint(1) NOT NULL,
  `Ethnic_Other` tinyint(1) NOT NULL,
  `Ethnic_Refused` tinyint(1) NOT NULL,
  `Ethnic_Unknown` tinyint(1) NOT NULL,
  `PharmacyName` text,
  `PharmacyLocation` text,
  `sel_TimeAgoDx` enum('AtLeast1YrAgo','Under1YrAgo','NA','null') DEFAULT NULL,
  `EmrHCPId` text,
  `ConsentDate` date NOT NULL,
  `statusInHmp` enum('enrolled','notEnrolled') DEFAULT NULL,
  `dateOfHmpStatus` date DEFAULT NULL,
  `registrationId` varchar(64) DEFAULT NULL,
  `submitted` tinyint(1) NOT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `hsfo2_system`
--


CREATE TABLE `hsfo2_system` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `LastUploadDate` date NOT NULL,
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `hsfo_recommit_schedule`
--


CREATE TABLE `hsfo_recommit_schedule` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `status` varchar(2) DEFAULT NULL,
  `memo` text,
  `schedule_time` datetime DEFAULT NULL,
  `user_no` varchar(6) DEFAULT NULL,
  `check_flag` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `ichppccode`
--


CREATE TABLE `ichppccode` (
  `ichppccode` varchar(10) NOT NULL DEFAULT '',
  `diagnostic_code` varchar(10) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ichppccode`)
);

--
-- Table structure for table `immunizations`
--


CREATE TABLE `immunizations` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `immunizations` text,
  `save_date` date NOT NULL DEFAULT '0001-01-01',
  `archived` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`ID`),
  KEY `demographic_no` (`demographic_no`)
);

--
-- Table structure for table `incomingLabRules`
--


CREATE TABLE `incomingLabRules` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL,
  `status` varchar(1) DEFAULT NULL,
  `frwdProvider_no` varchar(6) DEFAULT NULL,
  `archive` varchar(1) DEFAULT '0',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `indicatorTemplate`
--


CREATE TABLE `indicatorTemplate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `dashboardId` int(11) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `category` varchar(255) DEFAULT NULL,
  `subCategory` varchar(255) DEFAULT NULL,
  `framework` varchar(255) DEFAULT NULL,
  `frameworkVersion` date DEFAULT NULL,
  `definition` tinytext,
  `notes` tinytext,
  `template` mediumtext,
  `active` bit(1) DEFAULT NULL,
  `locked` bit(1) DEFAULT NULL,
  `shared` tinyint(1) DEFAULT NULL,
  `metricSetName` varchar(255) DEFAULT NULL,
  `metricLabel` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `indivoDocs`
--


CREATE TABLE `indivoDocs` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `oscarDocNo` int(10) NOT NULL,
  `indivoDocIdx` varchar(255) NOT NULL,
  `docType` varchar(20) NOT NULL,
  `dateSent` date NOT NULL,
  `update` char(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `issue`
--


CREATE TABLE `issue` (
  `issue_id` int(10) NOT NULL AUTO_INCREMENT,
  `code` varchar(20) NOT NULL,
  `description` varchar(255) NOT NULL,
  `role` varchar(100) NOT NULL,
  `update_date` datetime NOT NULL,
  `priority` char(10) DEFAULT NULL,
  `type` varchar(32) DEFAULT NULL,
  `sortOrderId` int(11) NOT NULL,
  PRIMARY KEY (`issue_id`),
  KEY `description_index` (`description`(20)),
  KEY `code` (`code`)
);

--
-- Table structure for table `labPatientPhysicianInfo`
--


CREATE TABLE `labPatientPhysicianInfo` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `labReportInfo_id` int(10) DEFAULT NULL,
  `accession_num` varchar(64) DEFAULT NULL,
  `physician_account_num` varchar(30) DEFAULT NULL,
  `service_date` varchar(10) DEFAULT NULL,
  `patient_first_name` varchar(100) DEFAULT NULL,
  `patient_last_name` varchar(100) DEFAULT NULL,
  `patient_sex` char(1) DEFAULT NULL,
  `patient_health_num` varchar(20) DEFAULT NULL,
  `patient_dob` varchar(15) DEFAULT NULL,
  `lab_status` char(1) DEFAULT NULL,
  `doc_num` varchar(50) DEFAULT NULL,
  `doc_name` varchar(100) DEFAULT NULL,
  `doc_addr1` varchar(100) DEFAULT NULL,
  `doc_addr2` varchar(100) DEFAULT NULL,
  `doc_addr3` varchar(100) DEFAULT NULL,
  `doc_postal` varchar(15) DEFAULT NULL,
  `doc_route` varchar(50) DEFAULT NULL,
  `comment1` text,
  `comment2` text,
  `patient_phone` varchar(20) DEFAULT NULL,
  `doc_phone` varchar(20) DEFAULT NULL,
  `collection_date` varchar(20) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `labRequestReportLink`
--


CREATE TABLE `labRequestReportLink` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `request_table` varchar(60) DEFAULT NULL,
  `request_id` int(10) DEFAULT NULL,
  `request_date` datetime DEFAULT NULL,
  `report_table` varchar(60) NOT NULL,
  `report_id` int(10) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `labTestResults`
--


CREATE TABLE `labTestResults` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `labPatientPhysicianInfo_id` int(10) DEFAULT NULL,
  `line_type` char(1) DEFAULT NULL,
  `title` varchar(255) DEFAULT NULL,
  `notUsed1` varchar(255) DEFAULT NULL,
  `notUsed2` varchar(255) DEFAULT NULL,
  `test_name` varchar(255) DEFAULT NULL,
  `abn` char(1) DEFAULT NULL,
  `minimum` varchar(65) DEFAULT NULL,
  `maximum` varchar(65) DEFAULT NULL,
  `units` varchar(65) DEFAULT NULL,
  `result` varchar(65) DEFAULT NULL,
  `description` text,
  `location_id` varchar(255) DEFAULT NULL,
  `last` char(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `log`
--


CREATE TABLE `log` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `dateTime` datetime NOT NULL,
  `provider_no` varchar(10) DEFAULT NULL,
  `action` varchar(100) DEFAULT NULL,
  `content` varchar(80) DEFAULT NULL,
  `contentId` varchar(80) DEFAULT NULL,
  `ip` varchar(64) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `data` text,
  `securityId` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `datetime` (`dateTime`,`provider_no`),
  KEY `action` (`action`),
  KEY `content` (`content`),
  KEY `contentId` (`contentId`),
  KEY `demographic_no` (`demographic_no`)
);

--
-- Table structure for table `log_letters`
--


CREATE TABLE `log_letters` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `date_time` datetime DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `log` text,
  `report_id` int(10) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `report_id` (`report_id`),
  KEY `provider_no` (`provider_no`),
  KEY `date_time` (`date_time`)
);

--
-- Table structure for table `lst_orgcd`
--


CREATE TABLE `lst_orgcd` (
  `code` varchar(8) NOT NULL,
  `description` varchar(240) DEFAULT NULL,
  `activeyn` varchar(1) DEFAULT NULL,
  `orderbyindex` int(11) DEFAULT NULL,
  `codetree` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`code`),
  KEY `IDX_ORGCD_CODE` (`codetree`)
);

--
-- Table structure for table `mdsMSH`
--


CREATE TABLE `mdsMSH` (
  `segmentID` int(10) NOT NULL AUTO_INCREMENT,
  `sendingApp` char(180) DEFAULT NULL,
  `dateTime` datetime NOT NULL,
  `type` char(7) DEFAULT NULL,
  `messageConID` char(20) DEFAULT NULL,
  `processingID` char(3) DEFAULT NULL,
  `versionID` char(8) DEFAULT NULL,
  `acceptAckType` char(2) DEFAULT NULL,
  `appAckType` char(2) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT '0',
  PRIMARY KEY (`segmentID`)
);

--
-- Table structure for table `mdsNTE`
--


CREATE TABLE `mdsNTE` (
  `segmentID` int(10) DEFAULT NULL,
  `sourceOfComment` varchar(8) DEFAULT NULL,
  `comment` varchar(255) DEFAULT NULL,
  `associatedOBX` int(10) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsOBR`
--


CREATE TABLE `mdsOBR` (
  `segmentID` int(10) DEFAULT NULL,
  `obrID` int(10) DEFAULT NULL,
  `placerOrderNo` char(75) DEFAULT NULL,
  `universalServiceID` char(200) DEFAULT NULL,
  `observationDateTime` char(26) DEFAULT NULL,
  `specimenRecDateTime` char(26) DEFAULT NULL,
  `fillerFieldOne` char(60) DEFAULT NULL,
  `quantityTiming` char(200) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsOBX`
--


CREATE TABLE `mdsOBX` (
  `segmentID` int(10) DEFAULT NULL,
  `obxID` int(10) DEFAULT '0',
  `valueType` char(2) DEFAULT NULL,
  `observationIden` varchar(80) DEFAULT NULL,
  `observationSubID` varchar(255) DEFAULT NULL,
  `observationValue` varchar(255) DEFAULT NULL,
  `abnormalFlags` varchar(5) DEFAULT NULL,
  `observationResultStatus` char(2) DEFAULT NULL,
  `producersID` varchar(60) DEFAULT NULL,
  `associatedOBR` int(10) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsPID`
--


CREATE TABLE `mdsPID` (
  `segmentID` int(10) DEFAULT NULL,
  `intPatientID` char(16) DEFAULT NULL,
  `altPatientID` char(15) DEFAULT NULL,
  `patientName` char(48) DEFAULT NULL,
  `dOB` char(26) DEFAULT NULL,
  `sex` char(1) DEFAULT NULL,
  `homePhone` char(40) DEFAULT NULL,
  `healthNumber` char(16) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsPV1`
--


CREATE TABLE `mdsPV1` (
  `segmentID` int(10) DEFAULT NULL,
  `patientClass` char(1) DEFAULT NULL,
  `patientLocation` char(80) DEFAULT NULL,
  `refDoctor` char(60) DEFAULT NULL,
  `conDoctor` char(60) DEFAULT NULL,
  `admDoctor` char(60) DEFAULT NULL,
  `vNumber` char(20) DEFAULT NULL,
  `accStatus` char(2) DEFAULT NULL,
  `admDateTime` char(26) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsZCL`
--


CREATE TABLE `mdsZCL` (
  `segmentID` int(10) DEFAULT NULL,
  `setID` char(4) DEFAULT NULL,
  `consultDoc` char(60) DEFAULT NULL,
  `clientAddress` char(106) DEFAULT NULL,
  `route` char(6) DEFAULT NULL,
  `stop` char(6) DEFAULT NULL,
  `area` char(2) DEFAULT NULL,
  `reportSet` char(1) DEFAULT NULL,
  `clientType` char(5) DEFAULT NULL,
  `clientModemPool` char(2) DEFAULT NULL,
  `clientFaxNumber` char(40) DEFAULT NULL,
  `clientBakFax` char(40) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsZCT`
--


CREATE TABLE `mdsZCT` (
  `segmentID` int(10) DEFAULT NULL,
  `barCodeIdentifier` char(14) DEFAULT NULL,
  `placerGroupNo` char(14) DEFAULT NULL,
  `observationDateTime` char(26) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsZFR`
--


CREATE TABLE `mdsZFR` (
  `segmentID` int(10) DEFAULT NULL,
  `reportForm` char(1) DEFAULT NULL,
  `reportFormStatus` char(1) DEFAULT NULL,
  `testingLab` varchar(5) DEFAULT NULL,
  `medicalDirector` varchar(255) DEFAULT NULL,
  `editFlag` varchar(255) DEFAULT NULL,
  `abnormalFlag` varchar(255) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsZLB`
--


CREATE TABLE `mdsZLB` (
  `segmentID` int(10) DEFAULT NULL,
  `labID` varchar(5) DEFAULT NULL,
  `labIDVersion` varchar(255) DEFAULT NULL,
  `labAddress` varchar(100) DEFAULT NULL,
  `primaryLab` varchar(5) DEFAULT NULL,
  `primaryLabVersion` varchar(5) DEFAULT NULL,
  `MDSLU` varchar(5) DEFAULT NULL,
  `MDSLV` varchar(5) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsZMC`
--


CREATE TABLE `mdsZMC` (
  `segmentID` int(10) DEFAULT NULL,
  `setID` varchar(10) DEFAULT NULL,
  `messageCodeIdentifier` varchar(10) DEFAULT NULL,
  `messageCodeVersion` varchar(255) DEFAULT NULL,
  `noMessageCodeDescLines` varchar(30) DEFAULT NULL,
  `sigFlag` varchar(5) DEFAULT NULL,
  `messageCodeDesc` varchar(255) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsZMN`
--


CREATE TABLE `mdsZMN` (
  `segmentID` int(10) DEFAULT NULL,
  `resultMnemonic` varchar(20) DEFAULT NULL,
  `resultMnemonicVersion` varchar(255) DEFAULT NULL,
  `reportName` varchar(255) DEFAULT NULL,
  `units` varchar(60) DEFAULT NULL,
  `cumulativeSequence` varchar(255) DEFAULT NULL,
  `referenceRange` varchar(255) DEFAULT NULL,
  `resultCode` varchar(20) DEFAULT NULL,
  `reportForm` varchar(255) DEFAULT NULL,
  `reportGroup` varchar(10) DEFAULT NULL,
  `reportGroupVersion` varchar(255) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `mdsZRG`
--


CREATE TABLE `mdsZRG` (
  `segmentID` int(10) DEFAULT NULL,
  `reportSequence` varchar(255) DEFAULT NULL,
  `reportGroupID` varchar(10) DEFAULT NULL,
  `reportGroupVersion` varchar(10) DEFAULT NULL,
  `reportFlags` varchar(255) DEFAULT NULL,
  `reportGroupDesc` varchar(30) DEFAULT NULL,
  `MDSIndex` varchar(255) DEFAULT NULL,
  `reportGroupHeading` varchar(255) DEFAULT NULL,
  KEY `segmentID` (`segmentID`)
);

--
-- Table structure for table `measurementCSSLocation`
--


CREATE TABLE `measurementCSSLocation` (
  `cssID` int(9) NOT NULL AUTO_INCREMENT,
  `location` varchar(255) NOT NULL,
  PRIMARY KEY (`cssID`)
);

--
-- Table structure for table `measurementGroup`
--


CREATE TABLE `measurementGroup` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `typeDisplayName` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
);

--
-- Table structure for table `measurementGroupStyle`
--


CREATE TABLE `measurementGroupStyle` (
  `groupID` int(9) NOT NULL AUTO_INCREMENT,
  `groupName` varchar(100) NOT NULL,
  `cssID` int(9) NOT NULL,
  PRIMARY KEY (`groupID`)
);

--
-- Table structure for table `measurementMap`
--


CREATE TABLE `measurementMap` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `loinc_code` varchar(20) NOT NULL,
  `ident_code` varchar(20) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `lab_type` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ident_code` (`ident_code`)
);

--
-- Table structure for table `measurementType`
--


CREATE TABLE `measurementType` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` varchar(50) NOT NULL,
  `typeDisplayName` varchar(255) NOT NULL,
  `typeDescription` varchar(255) NOT NULL,
  `measuringInstruction` varchar(255) NOT NULL,
  `validation` varchar(100) NOT NULL,
  `createDate` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `id` (`id`),
  KEY `type` (`type`),
  KEY `measuringInstruction` (`measuringInstruction`)
);

--
-- Table structure for table `measurementTypeDeleted`
--


CREATE TABLE `measurementTypeDeleted` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` varchar(50) NOT NULL,
  `typeDisplayName` varchar(255) NOT NULL,
  `typeDescription` varchar(255) NOT NULL,
  `measuringInstruction` varchar(255) NOT NULL,
  `validation` varchar(100) NOT NULL,
  `dateDeleted` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `measurements`
--


CREATE TABLE `measurements` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` varchar(50) NOT NULL,
  `demographicNo` int(10) NOT NULL DEFAULT '0',
  `providerNo` varchar(6) NOT NULL DEFAULT '',
  `dataField` varchar(255) NOT NULL,
  `measuringInstruction` varchar(255) NOT NULL,
  `comments` varchar(255) DEFAULT NULL,
  `dateObserved` datetime DEFAULT NULL,
  `dateEntered` datetime NOT NULL,
  `appointmentNo` int(10) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `type` (`type`),
  KEY `measuringInstruction` (`measuringInstruction`),
  KEY `demographicNo` (`demographicNo`)
);

--
-- Table structure for table `measurementsDeleted`
--


CREATE TABLE `measurementsDeleted` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` varchar(4) NOT NULL,
  `demographicNo` int(10) NOT NULL DEFAULT '0',
  `providerNo` varchar(6) NOT NULL DEFAULT '',
  `dataField` varchar(255) NOT NULL,
  `measuringInstruction` varchar(255) NOT NULL,
  `comments` varchar(255) NOT NULL,
  `dateObserved` datetime NOT NULL,
  `dateEntered` datetime NOT NULL,
  `dateDeleted` datetime NOT NULL,
  `originalId` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `measurementsExt`
--


CREATE TABLE `measurementsExt` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `measurement_id` int(10) NOT NULL,
  `keyval` varchar(20) NOT NULL,
  `val` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `measurement_id` (`measurement_id`)
);

--
-- Table structure for table `messageFolder`
--


CREATE TABLE `messageFolder` (
  `folderID` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(25) NOT NULL DEFAULT '',
  `providerNo` varchar(6) DEFAULT NULL,
  `displayOrder` int(10) DEFAULT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`folderID`)
);

--
-- Table structure for table `messagelisttbl`
--


CREATE TABLE `messagelisttbl` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `message` mediumint(9) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `status` varchar(10) DEFAULT NULL,
  `remoteLocation` int(10) DEFAULT NULL,
  `destinationFacilityId` int(6) DEFAULT NULL,
  `sourceFacilityId` int(6) DEFAULT NULL,
  `folderid` int(10) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `message` (`message`),
  KEY `provider_no` (`provider_no`),
  KEY `status` (`status`),
  KEY `remoteLocation` (`remoteLocation`)
);

--
-- Table structure for table `messagetbl`
--


CREATE TABLE `messagetbl` (
  `messageid` mediumint(9) NOT NULL AUTO_INCREMENT,
  `thedate` date DEFAULT NULL,
  `theime` time DEFAULT NULL,
  `themessage` text,
  `thesubject` varchar(128) DEFAULT NULL,
  `sentby` varchar(62) DEFAULT NULL,
  `sentto` text,
  `sentbyNo` varchar(6) DEFAULT NULL,
  `sentByLocation` int(10) DEFAULT NULL,
  `attachment` text,
  `pdfattachment` blob,
  `actionstatus` char(2) DEFAULT NULL,
  `type` int(10) DEFAULT NULL,
  `type_link` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`messageid`)
);

--
-- Table structure for table `msgDemoMap`
--


CREATE TABLE `msgDemoMap` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `messageID` mediumint(9) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `messageID` (`messageID`,`demographic_no`)
);

--
-- Table structure for table `msgIntegratorDemoMap`
--


CREATE TABLE `msgIntegratorDemoMap` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `messageId` int(11) DEFAULT NULL,
  `sourceDemographicNo` int(11) DEFAULT NULL,
  `sourceFacilityId` int(6) DEFAULT NULL,
  `msgDemoMapId` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `mygroup`
--


CREATE TABLE `mygroup` (
  `mygroup_no` varchar(10) NOT NULL DEFAULT '',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `last_name` varchar(30) NOT NULL DEFAULT '',
  `first_name` varchar(30) NOT NULL DEFAULT '',
  `vieworder` char(2) DEFAULT NULL,
  `default_billing_form` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`mygroup_no`,`provider_no`)
);

--
-- Table structure for table `OMDGatewayTransactionLog` PHC note that this is reverse engineered from the DAO
--

CREATE TABLE `OMDGatewayTransactionLog` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `started` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `ended` timestamp DEFAULT CURRENT_TIMESTAMP,
  `initiatingProviderNo` varchar(10) DEFAULT NULL,
  `transactionType` varchar(50) DEFAULT NULL,
  `externalSystem` varchar(50) DEFAULT NULL,
  `demographicNo` int(10) DEFAULT NULL,
  `resultCode` int(10) DEFAULT NULL,
  `success` tinyint(1) DEFAULT NULL,
  `error` varchar(255) DEFAULT NULL,
  `dataSent` varchar(255) DEFAULT NULL,
  `dataRecieved` varchar(255) DEFAULT NULL,
  `headers` varchar(255) DEFAULT NULL,
  `uao` varchar(255) DEFAULT NULL,
  `oscarSessionId` varchar(50) DEFAULT '1',
  `contextSessionId` varchar(50) DEFAULT '2',
  `uniqueSessionId` varchar(50) DEFAULT NULL,
  `xRequestId` varchar(50) DEFAULT NULL,
  `xLobTxId` varchar(50) DEFAULT NULL,
  `xCorrelationId` varchar(50) DEFAULT NULL,
  `xGtwyClientId` varchar(50) DEFAULT NULL,
  `secondsLeft` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ;

--
-- Table structure for table `onCallClinicDates`
--

CREATE TABLE `onCallClinicDates` (
  `id` int(10) NOT NULL,
  `startDate` date DEFAULT NULL,
  `endDate` date DEFAULT NULL,
  `name` varchar(256) DEFAULT NULL,
  `location` varchar(256) DEFAULT NULL,
  `color` varchar(7) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `oscarKeys`
--


CREATE TABLE `oscarKeys` (
  `name` varchar(100) NOT NULL,
  `pubKey` text,
  `privKey` text,
  PRIMARY KEY (`name`)
);

--
-- Table structure for table `oscar_annotations`
--


CREATE TABLE `oscar_annotations` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `table_id` int(10) DEFAULT NULL,
  `table_name` int(10) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `create_date` datetime DEFAULT NULL,
  `observation_date` datetime DEFAULT NULL,
  `deleted` char(1) DEFAULT '0',
  `note` text,
  `uuid` char(36) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `oscar_msg_type`
--


CREATE TABLE `oscar_msg_type` (
  `type` int(10) NOT NULL DEFAULT '0',
  `description` varchar(255) DEFAULT NULL,
  `code` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`type`)
);

--
-- Table structure for table `oscarcommlocations`
--


CREATE TABLE `oscarcommlocations` (
  `locationId` int(10) NOT NULL DEFAULT '0',
  `locationDesc` varchar(50) NOT NULL DEFAULT '',
  `locationAuth` varchar(30) DEFAULT NULL,
  `current1` tinyint(1) NOT NULL DEFAULT '0',
  `addressBook` text,
  `remoteServerURL` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`locationId`)
);

--
-- Table structure for table `other_id`
--


CREATE TABLE `other_id` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `table_name` int(11) NOT NULL,
  `table_id` varchar(30) NOT NULL,
  `other_key` varchar(30) NOT NULL,
  `other_id` varchar(30) NOT NULL,
  `deleted` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `partial_date`
--


CREATE TABLE `partial_date` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `table_name` int(11) DEFAULT NULL,
  `table_id` int(11) DEFAULT NULL,
  `field_name` int(11) DEFAULT NULL,
  `format` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `patientLabRouting`
--


CREATE TABLE `patientLabRouting` (
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `lab_no` int(10) NOT NULL DEFAULT '0',
  `lab_type` char(3) NOT NULL DEFAULT 'MDS',
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `created` datetime NOT NULL,
  `dateModified` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `demographic` (`demographic_no`),
  KEY `lab_type_index` (`lab_type`),
  KEY `lab_no_index` (`lab_no`),
  KEY `all_index` (`lab_type`,`lab_no`,`demographic_no`)
);

--
-- Table structure for table `pharmacyInfo`
--


CREATE TABLE `pharmacyInfo` (
  `recordID` int(10) NOT NULL AUTO_INCREMENT,
  `ID` int(5) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `address` text,
  `city` varchar(255) DEFAULT NULL,
  `province` varchar(255) DEFAULT NULL,
  `postalCode` varchar(20) DEFAULT NULL,
  `phone1` varchar(20) DEFAULT NULL,
  `phone2` varchar(20) DEFAULT NULL,
  `fax` varchar(20) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `serviceLocationIdentifier` varchar(255) DEFAULT NULL,
  `notes` text,
  `addDate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `status` char(1) DEFAULT '1',
  PRIMARY KEY (`recordID`)
);

--
-- Table structure for table `prescribe`
--


CREATE TABLE `prescribe` (
  `prescribe_no` int(12) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `prescribe_date` date NOT NULL DEFAULT '0001-01-01',
  `prescribe_time` time NOT NULL DEFAULT '00:00:00',
  `content` text,
  PRIMARY KEY (`prescribe_no`)
);

--
-- Table structure for table `prescription`
--


CREATE TABLE `prescription` (
  `script_no` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `date_prescribed` date DEFAULT NULL,
  `date_printed` date DEFAULT NULL,
  `dates_reprinted` text,
  `textView` text,
  `rx_comments` text,
  `lastUpdateDate` datetime NOT NULL,
  PRIMARY KEY (`script_no`)
);

--
-- Table structure for table `preventions`
--


CREATE TABLE `preventions` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `creation_date` datetime DEFAULT NULL,
  `prevention_date` datetime DEFAULT NULL,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `provider_name` varchar(255) DEFAULT NULL,
  `prevention_type` varchar(255) DEFAULT NULL,
  `deleted` char(1) DEFAULT '0',
  `refused` char(1) DEFAULT '0',
  `next_date` date DEFAULT NULL,
  `never` char(1) DEFAULT '0',
  `creator` int(10) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `snomedId` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `preventions_demographic_no` (`demographic_no`),
  KEY `preventions_provider_no` (`provider_no`),
  KEY `preventions_prevention_type` (`prevention_type`(10)),
  KEY `preventions_refused` (`refused`),
  KEY `preventions_deleted` (`deleted`),
  KEY `preventions_never` (`never`),
  KEY `preventions_creation_date` (`creation_date`),
  KEY `preventions_next_date` (`next_date`)
);

--
-- Table structure for table `preventionsExt`
--


CREATE TABLE `preventionsExt` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `prevention_id` int(10) DEFAULT NULL,
  `keyval` varchar(20) DEFAULT NULL,
  `val` text,
  PRIMARY KEY (`id`),
  KEY `preventionsExt_prevention_id` (`prevention_id`),
  KEY `preventionsExt_keyval` (`keyval`(10))
);

--
-- Table structure for table `professionalSpecialists`
--


CREATE TABLE `professionalSpecialists` (
  `specId` int(10) NOT NULL AUTO_INCREMENT,
  `fName` varchar(32) DEFAULT NULL,
  `lName` varchar(32) DEFAULT NULL,
  `proLetters` varchar(20) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `phone` varchar(30) DEFAULT NULL,
  `fax` varchar(30) DEFAULT NULL,
  `website` varchar(128) DEFAULT NULL,
  `email` varchar(128) DEFAULT NULL,
  `specType` varchar(128) DEFAULT NULL,
  `eDataUrl` varchar(255) DEFAULT NULL,
  `eDataOscarKey` varchar(1024) DEFAULT NULL,
  `eDataServiceKey` varchar(1024) DEFAULT NULL,
  `eDataServiceName` varchar(255) DEFAULT NULL,
  `lastUpdated` datetime NOT NULL,
  `annotation` text,
  `referralNo` varchar(6) DEFAULT NULL,
  `institutionId` int(10) NOT NULL,
  `departmentId` int(10) NOT NULL,
  `privatePhoneNumber` varchar(30) DEFAULT NULL,
  `cellPhoneNumber` varchar(30) DEFAULT NULL,
  `pagerNumber` varchar(30) DEFAULT NULL,
  `salutation` varchar(10) DEFAULT NULL,
  `hideFromView` tinyint(1) DEFAULT NULL,
  `eformId` int(10) DEFAULT NULL,
  PRIMARY KEY (`specId`)
);

--
-- Table structure for table `program`
--


CREATE TABLE `program` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `facilityId` int(11) NOT NULL,
  `intakeProgram` int(11) DEFAULT NULL,
  `name` varchar(70) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `functionalCentreId` varchar(64) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `fax` varchar(255) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `emergencyNumber` varchar(255) DEFAULT NULL,
  `type` varchar(50) DEFAULT NULL,
  `location` varchar(70) DEFAULT NULL,
  `maxAllowed` int(11) NOT NULL,
  `holdingTank` tinyint(1) DEFAULT NULL,
  `allowBatchAdmission` tinyint(1) DEFAULT NULL,
  `allowBatchDischarge` tinyint(1) DEFAULT NULL,
  `hic` tinyint(1) DEFAULT NULL,
  `programStatus` varchar(8) NOT NULL,
  `bedProgramLinkId` int(11) DEFAULT NULL,
  `manOrWoman` varchar(6) DEFAULT NULL,
  `transgender` tinyint(1) NOT NULL,
  `firstNation` tinyint(1) NOT NULL,
  `bedProgramAffiliated` tinyint(1) NOT NULL,
  `alcohol` tinyint(1) NOT NULL,
  `abstinenceSupport` varchar(20) DEFAULT NULL,
  `physicalHealth` tinyint(1) NOT NULL,
  `mentalHealth` tinyint(1) NOT NULL,
  `housing` tinyint(1) NOT NULL,
  `exclusiveView` varchar(20) NOT NULL,
  `maximumServiceRestrictionDays` int(11) DEFAULT NULL,
  `defaultServiceRestrictionDays` int(11) DEFAULT NULL,
  `ageMin` int(11) NOT NULL,
  `ageMax` int(11) NOT NULL,
  `userDefined` int(1) DEFAULT NULL,
  `shelter_id` int(11) DEFAULT NULL,
  `facility_id` int(10) DEFAULT NULL,
  `capacity_funding` int(10) DEFAULT NULL,
  `capacity_space` int(10) DEFAULT NULL,
  `lastUpdateUser` varchar(6) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `enableEncounterTime` tinyint(1) DEFAULT NULL,
  `enableEncounterTransportationTime` tinyint(1) DEFAULT NULL,
  `siteSpecificField` varchar(255) DEFAULT NULL,
  `emailNotificationAddressesCsv` varchar(255) DEFAULT NULL,
  `lastReferralNotification` datetime DEFAULT NULL,
  `enableOCAN` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `facilityId` (`facilityId`),
  CONSTRAINT `program_ibfk_1` FOREIGN KEY (`facilityId`) REFERENCES `Facility` (`id`)
);

--
-- Table structure for table `property`
--


CREATE TABLE `property` (
  `name` varchar(255) NOT NULL DEFAULT '',
  `value` varchar(4000) DEFAULT NULL,
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `provider`
--


CREATE TABLE `provider` (
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `last_name` varchar(30) NOT NULL DEFAULT '',
  `first_name` varchar(30) NOT NULL DEFAULT '',
  `provider_type` varchar(15) NOT NULL DEFAULT '',
  `supervisor` varchar(6) DEFAULT NULL,
  `specialty` varchar(40) NOT NULL DEFAULT '',
  `team` varchar(20) DEFAULT '',
  `sex` char(1) NOT NULL DEFAULT '',
  `dob` date DEFAULT NULL,
  `address` varchar(40) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `work_phone` varchar(50) DEFAULT NULL,
  `ohip_no` varchar(20) DEFAULT NULL,
  `rma_no` varchar(20) DEFAULT NULL,
  `billing_no` varchar(20) DEFAULT NULL,
  `hso_no` varchar(10) DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  `comments` text,
  `provider_activity` char(3) DEFAULT NULL,
  `practitionerNo` varchar(20) DEFAULT NULL,
  `init` varchar(10) DEFAULT NULL,
  `job_title` varchar(100) DEFAULT NULL,
  `email` varchar(60) DEFAULT NULL,
  `title` varchar(20) DEFAULT NULL,
  `lastUpdateUser` varchar(6) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  `signed_confidentiality` datetime DEFAULT NULL,
  `practitionerNoType` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`provider_no`)
);

--
-- Table structure for table `providerArchive`
--


CREATE TABLE `providerArchive` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `last_name` varchar(30) DEFAULT NULL,
  `first_name` varchar(30) DEFAULT NULL,
  `provider_type` varchar(15) DEFAULT NULL,
  `specialty` varchar(40) DEFAULT NULL,
  `team` varchar(20) DEFAULT NULL,
  `sex` char(1) DEFAULT NULL,
  `dob` date DEFAULT NULL,
  `address` varchar(40) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `work_phone` varchar(50) DEFAULT NULL,
  `ohip_no` varchar(20) DEFAULT NULL,
  `rma_no` varchar(20) DEFAULT NULL,
  `billing_no` varchar(20) DEFAULT NULL,
  `hso_no` varchar(10) DEFAULT NULL,
  `status` char(1) DEFAULT NULL,
  `comments` text,
  `provider_activity` char(3) DEFAULT NULL,
  `practitionerNo` varchar(20) DEFAULT NULL,
  `init` varchar(10) DEFAULT NULL,
  `job_title` varchar(100) DEFAULT NULL,
  `email` varchar(60) DEFAULT NULL,
  `title` varchar(20) DEFAULT NULL,
  `lastUpdateUser` varchar(6) DEFAULT NULL,
  `lastUpdateDate` date DEFAULT NULL,
  `signed_confidentiality` date DEFAULT NULL,
  `practitionerNoType` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `providerExt`
--


CREATE TABLE `providerExt` (
  `provider_no` varchar(6) DEFAULT NULL,
  `signature` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`provider_no`)
);

--
-- Table structure for table `providerLabRouting`
--


CREATE TABLE `providerLabRouting` (
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `lab_no` int(10) NOT NULL DEFAULT '0',
  `status` char(1) DEFAULT '',
  `comment` varchar(255) DEFAULT '',
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `lab_type` char(3) DEFAULT 'MDS',
  `id` int(10) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`),
  KEY `labno_index` (`lab_no`),
  KEY `provider_lab_status_index` (`provider_no`(3),`status`)
);

--
-- Table structure for table `providerLabRoutingFavorites`
--


CREATE TABLE `providerLabRoutingFavorites` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `route_to_provider_no` varchar(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `provider_no` (`provider_no`)
);

--
-- Table structure for table `provider_facility`
--


CREATE TABLE `provider_facility` (
  `provider_no` varchar(6) NOT NULL,
  `facility_id` int(11) NOT NULL,
  UNIQUE KEY `provider_no` (`provider_no`,`facility_id`),
  KEY `facility_id` (`facility_id`)
);

--
-- Table structure for table `providerbillcenter`
--


CREATE TABLE `providerbillcenter` (
  `provider_no` varchar(6) NOT NULL DEFAULT '""',
  `billcenter_code` char(2) NOT NULL DEFAULT '""',
  PRIMARY KEY (`provider_no`)
);

--
-- Table structure for table `providersite`
--


CREATE TABLE `providersite` (
  `provider_no` varchar(6) NOT NULL,
  `site_id` int(11) NOT NULL,
  PRIMARY KEY (`provider_no`,`site_id`)
);

--
-- Table structure for table `providerstudy`
--


CREATE TABLE `providerstudy` (
  `study_no` int(10) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `creator` varchar(6) DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

--
-- Table structure for table `publicKeys`
--


CREATE TABLE `publicKeys` (
  `service` varchar(100) NOT NULL,
  `type` varchar(100) NOT NULL,
  `pubKey` text NOT NULL,
  `privateKey` text NOT NULL,
  `matchingProfessionalSpecialistId` int(11) DEFAULT NULL,
  PRIMARY KEY (`service`)
);

--
-- Table structure for table `queue`
--


CREATE TABLE `queue` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
);

--
-- Table structure for table `queue_document_link`
--


CREATE TABLE `queue_document_link` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `queue_id` int(10) NOT NULL,
  `document_id` int(10) NOT NULL,
  `status` char(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `quickList`
--


CREATE TABLE `quickList` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `quickListName` varchar(255) NOT NULL,
  `createdByProvider` varchar(20) DEFAULT NULL,
  `dxResearchCode` varchar(10) DEFAULT NULL,
  `codingSystem` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `quickListUser`
--


CREATE TABLE `quickListUser` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(20) NOT NULL,
  `quickListName` varchar(10) NOT NULL,
  `lastUsed` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `radetail`
--


CREATE TABLE `radetail` (
  `radetail_no` int(6) NOT NULL AUTO_INCREMENT,
  `raheader_no` int(6) NOT NULL DEFAULT '0',
  `providerohip_no` varchar(12) NOT NULL DEFAULT '',
  `billing_no` int(6) NOT NULL DEFAULT '0',
  `service_code` varchar(5) NOT NULL DEFAULT '',
  `service_count` char(2) NOT NULL DEFAULT '',
  `hin` varchar(12) NOT NULL DEFAULT '',
  `amountclaim` varchar(8) NOT NULL DEFAULT '',
  `amountpay` varchar(8) NOT NULL DEFAULT '',
  `service_date` varchar(12) NOT NULL DEFAULT '',
  `error_code` char(2) NOT NULL DEFAULT '',
  `billtype` char(3) NOT NULL DEFAULT '',
  `claim_no` varchar(12) NOT NULL DEFAULT '',
  PRIMARY KEY (`radetail_no`)
);

--
-- Table structure for table `raheader`
--


CREATE TABLE `raheader` (
  `raheader_no` int(6) NOT NULL AUTO_INCREMENT,
  `filename` varchar(30) NOT NULL,
  `paymentdate` varchar(8) NOT NULL DEFAULT '',
  `payable` varchar(30) NOT NULL DEFAULT '',
  `totalamount` varchar(10) NOT NULL DEFAULT '',
  `records` varchar(5) NOT NULL DEFAULT '',
  `claims` varchar(5) NOT NULL DEFAULT '',
  `status` char(1) NOT NULL DEFAULT '',
  `readdate` varchar(12) NOT NULL DEFAULT '',
  `content` text,
  PRIMARY KEY (`raheader_no`)
);

--
-- Table structure for table `recycle_bin`
--


CREATE TABLE `recycle_bin` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `table_name` varchar(30) NOT NULL DEFAULT '',
  `table_content` text,
  `updatedatetime` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `recyclebin`
--


CREATE TABLE `recyclebin` (
  `recyclebin_no` int(12) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `updatedatetime` datetime DEFAULT NULL,
  `table_name` varchar(30) DEFAULT NULL,
  `keyword` varchar(50) DEFAULT NULL,
  `table_content` text,
  PRIMARY KEY (`recyclebin_no`),
  KEY `keyword` (`keyword`)
);

--
-- Table structure for table `rehabStudy2004`
--


CREATE TABLE `rehabStudy2004` (
  `studyID` int(10) NOT NULL,
  `demographic_no` int(10) NOT NULL,
  PRIMARY KEY (`studyID`)
);

--
-- Table structure for table `relationships`
--


CREATE TABLE `relationships` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `facility_id` int(11) DEFAULT NULL,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `relation_demographic_no` int(10) NOT NULL DEFAULT '0',
  `relation` varchar(20) DEFAULT NULL,
  `creation_date` datetime DEFAULT NULL,
  `creator` varchar(6) NOT NULL DEFAULT '',
  `sub_decision_maker` char(1) DEFAULT '0',
  `emergency_contact` char(1) DEFAULT '0',
  `notes` text,
  `deleted` char(1) DEFAULT '0',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `remoteAttachments`
--


CREATE TABLE `remoteAttachments` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `messageid` mediumint(9) DEFAULT NULL,
  `savedBy` varchar(255) DEFAULT NULL,
  `date` date DEFAULT NULL,
  `time` time DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `reportByExamples`
--


CREATE TABLE `reportByExamples` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(6) NOT NULL,
  `query` blob NOT NULL,
  `date` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `reportByExamplesFavorite`
--


CREATE TABLE `reportByExamplesFavorite` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `providerNo` varchar(6) NOT NULL,
  `query` blob NOT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `reportConfig`
--


CREATE TABLE `reportConfig` (
  `id` int(7) NOT NULL AUTO_INCREMENT,
  `report_id` int(5) DEFAULT NULL,
  `name` varchar(80) NOT NULL DEFAULT '',
  `caption` varchar(80) NOT NULL DEFAULT '',
  `order_no` int(3) DEFAULT NULL,
  `table_name` varchar(80) NOT NULL DEFAULT '',
  `save` varchar(80) NOT NULL DEFAULT 'default',
  PRIMARY KEY (`id`),
  KEY `report_id` (`report_id`),
  KEY `name` (`name`)
);

--
-- Table structure for table `reportFilter`
--


CREATE TABLE `reportFilter` (
  `id` int(7) NOT NULL AUTO_INCREMENT,
  `report_id` int(5) DEFAULT NULL,
  `description` text,
  `value` varchar(255) NOT NULL DEFAULT '',
  `position` varchar(80) NOT NULL DEFAULT '',
  `status` int(1) DEFAULT '1',
  `order_no` int(3) DEFAULT NULL,
  `javascript` text,
  `date_format` varchar(20) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `order_no` (`report_id`,`order_no`),
  KEY `report_id` (`report_id`)
);

--
-- Table structure for table `reportItem`
--


CREATE TABLE `reportItem` (
  `id` int(5) NOT NULL AUTO_INCREMENT,
  `report_name` varchar(80) NOT NULL DEFAULT '',
  `status` int(1) DEFAULT '1',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `reportTableFieldCaption`
--


CREATE TABLE `reportTableFieldCaption` (
  `id` int(7) NOT NULL AUTO_INCREMENT,
  `table_name` varchar(80) NOT NULL DEFAULT '',
  `name` varchar(80) NOT NULL DEFAULT '',
  `caption` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `table_name` (`table_name`,`name`)
);

--
-- Table structure for table `reportTemplates`
--


CREATE TABLE `reportTemplates` (
  `templateid` int(11) NOT NULL AUTO_INCREMENT,
  `templatetitle` varchar(80) NOT NULL DEFAULT '',
  `templatedescription` text NOT NULL,
  `templatesql` text NOT NULL,
  `templatexml` text NOT NULL,
  `active` tinyint(4) NOT NULL DEFAULT '1',
  `type` varchar(32) DEFAULT NULL,
  `uuid` varchar(60) DEFAULT NULL,
  `sequence` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`templateid`)
);

--
-- Table structure for table `report_letters`
--


CREATE TABLE `report_letters` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `report_name` varchar(255) DEFAULT NULL,
  `file_name` varchar(255) DEFAULT NULL,
  `report_file` mediumblob,
  `date_time` datetime DEFAULT NULL,
  `archive` char(1) DEFAULT '0',
  PRIMARY KEY (`ID`),
  KEY `archive` (`archive`),
  KEY `provider_no` (`provider_no`),
  KEY `date_time` (`date_time`)
);

--
-- Table structure for table `reportagesex`
--


CREATE TABLE `reportagesex` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT NULL,
  `age` int(4) DEFAULT '0',
  `roster` varchar(4) DEFAULT '',
  `sex` char(2) DEFAULT '',
  `provider_no` varchar(6) DEFAULT NULL,
  `reportdate` date DEFAULT NULL,
  `status` char(2) DEFAULT '',
  `date_joined` date DEFAULT '0001-01-01',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `reportprovider`
--


CREATE TABLE `reportprovider` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(10) DEFAULT '',
  `team` varchar(10) DEFAULT '',
  `action` varchar(20) DEFAULT '',
  `status` char(1) DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `reporttemp`
--


CREATE TABLE `reporttemp` (
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `edb` date NOT NULL DEFAULT '0001-01-01',
  `demo_name` varchar(60) NOT NULL DEFAULT '',
  `provider_no` varchar(6) DEFAULT NULL,
  `address` text,
  `creator` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`demographic_no`,`edb`)
);

--
-- Table structure for table `resident_oscarMsg`
--


CREATE TABLE `resident_oscarMsg` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `supervisor_no` varchar(6) DEFAULT NULL,
  `resident_no` varchar(6) DEFAULT NULL,
  `demographic_no` int(11) DEFAULT NULL,
  `appointment_no` int(11) DEFAULT NULL,
  `note_id` int(10) DEFAULT NULL,
  `complete` int(1) DEFAULT NULL,
  `create_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `complete_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  KEY `note_id_idx` (`note_id`)
);

--
-- Table structure for table `rschedule`
--


CREATE TABLE `rschedule` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `sdate` date NOT NULL DEFAULT '0001-01-01',
  `edate` date DEFAULT NULL,
  `available` char(1) NOT NULL DEFAULT '',
  `day_of_week` varchar(30) DEFAULT NULL,
  `avail_hourB` varchar(255) DEFAULT NULL,
  `avail_hour` text,
  `creator` varchar(50) DEFAULT NULL,
  `status` char(1) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `scheduledate`
--


CREATE TABLE `scheduledate` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `sdate` date NOT NULL DEFAULT '0001-01-01',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `available` char(1) NOT NULL DEFAULT '',
  `priority` char(1) DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `hour` varchar(255) DEFAULT NULL,
  `creator` varchar(50) DEFAULT NULL,
  `status` char(1) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `scheduleholiday`
--


CREATE TABLE `scheduleholiday` (
  `sdate` date NOT NULL DEFAULT '0001-01-01',
  `holiday_name` varchar(100) NOT NULL DEFAULT '',
  PRIMARY KEY (`sdate`)
);

--
-- Table structure for table `scheduletemplate`
--


CREATE TABLE `scheduletemplate` (
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `name` varchar(20) NOT NULL DEFAULT '',
  `summary` varchar(80) DEFAULT NULL,
  `timecode` text,
  PRIMARY KEY (`provider_no`,`name`)
);

--
-- Table structure for table `scheduletemplatecode`
--


CREATE TABLE `scheduletemplatecode` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `code` char(1) NOT NULL DEFAULT '',
  `description` varchar(80) DEFAULT NULL,
  `duration` char(3) DEFAULT '',
  `color` varchar(10) DEFAULT NULL,
  `confirm` char(3) NOT NULL DEFAULT 'No',
  `bookinglimit` int(11) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `code` (`code`)
);

--
-- Table structure for table `scratch_pad`
--


CREATE TABLE `scratch_pad` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `date_time` datetime DEFAULT NULL,
  `scratch_text` text,
  `status` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `secObjPrivilege`
--


CREATE TABLE `secObjPrivilege` (
  `roleUserGroup` varchar(30) NOT NULL DEFAULT '',
  `objectName` varchar(100) NOT NULL DEFAULT '',
  `privilege` varchar(100) NOT NULL DEFAULT '|0|',
  `priority` int(2) DEFAULT '0',
  `provider_no` varchar(6) DEFAULT NULL,
  PRIMARY KEY (`roleUserGroup`,`objectName`)
);

--
-- Table structure for table `secObjectName`
--


CREATE TABLE `secObjectName` (
  `objectName` varchar(100) NOT NULL DEFAULT '',
  `description` varchar(60) DEFAULT NULL,
  `orgapplicable` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`objectName`)
);

--
-- Table structure for table `secPrivilege`
--


CREATE TABLE `secPrivilege` (
  `id` int(2) NOT NULL AUTO_INCREMENT,
  `privilege` varchar(5) NOT NULL DEFAULT '0',
  `description` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `privilege` (`privilege`)
);

--
-- Table structure for table `secRole`
--


CREATE TABLE `secRole` (
  `role_no` int(3) NOT NULL AUTO_INCREMENT,
  `role_name` varchar(60) NOT NULL DEFAULT '',
  `description` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`role_no`),
  UNIQUE KEY `role_name` (`role_name`)
);

--
-- Table structure for table `secUserRole`
--


CREATE TABLE `secUserRole` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) NOT NULL,
  `role_name` varchar(60) NOT NULL,
  `orgcd` varchar(80) DEFAULT 'R0000001',
  `activeyn` int(1) DEFAULT NULL,
  `lastUpdateDate` datetime NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `security`
--


CREATE TABLE `security` (
  `security_no` int(6) NOT NULL AUTO_INCREMENT,
  `user_name` varchar(30) NOT NULL DEFAULT '',
  `password` varchar(255) NOT NULL DEFAULT '',
  `provider_no` varchar(6) DEFAULT NULL,
  `pin` varchar(255) DEFAULT NULL,
  `b_ExpireSet` int(1) DEFAULT '1',
  `date_ExpireDate` date DEFAULT '2100-01-01',
  `b_LocalLockSet` int(1) DEFAULT '1',
  `b_RemoteLockSet` int(1) DEFAULT '1',
  `forcePasswordReset` tinyint(1) DEFAULT NULL,
  `passwordUpdateDate` datetime DEFAULT NULL,
  `pinUpdateDate` datetime DEFAULT NULL,
  `lastUpdateUser` varchar(20) DEFAULT NULL,
  `lastUpdateDate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `oneIdKey` varchar(255) DEFAULT NULL,
  `oneIdEmail` varchar(255) DEFAULT NULL,
  `delegateOneIdEmail` varchar(255) DEFAULT NULL,
  `totp_enabled` smallint(1) NOT NULL DEFAULT '0',
  `totp_secret` varchar(254) NOT NULL,
  `totp_algorithm` varchar(50) NOT NULL DEFAULT 'sha1',
  `totp_digits` smallint(6) NOT NULL DEFAULT '6',
  `totp_period` smallint(6) NOT NULL DEFAULT '30',
  PRIMARY KEY (`security_no`),
  UNIQUE KEY `user_name` (`user_name`)
);

--
-- Table structure for table `serviceSpecialists`
--


CREATE TABLE `serviceSpecialists` (
  `serviceId` int(10) DEFAULT NULL,
  `specId` int(10) DEFAULT NULL
);


--
-- Table structure for table `sharing_affinity_domain`  MUST BE DECLARED BEFORE THE FOREIGN KEY
--


CREATE TABLE `sharing_affinity_domain` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `oid` varchar(255) DEFAULT NULL,
  `permission` varchar(10) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);


--
-- Table structure for table `sharing_policy_definition`
--


CREATE TABLE `sharing_policy_definition` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) DEFAULT NULL,
  `code` varchar(255) DEFAULT NULL,
  `code_system` varchar(255) DEFAULT NULL,
  `policy_doc_url` varchar(255) DEFAULT NULL,
  `ack_duration` double DEFAULT NULL,
  `domain_fk` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_pd_domain` (`domain_fk`),
  CONSTRAINT `fk_sharing_pd_domain` FOREIGN KEY (`domain_fk`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);
--
-- Table structure for table `sharing_acl_definition`
--


CREATE TABLE `sharing_acl_definition` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `role` varchar(255) DEFAULT NULL,
  `permission` varchar(255) DEFAULT NULL,
  `action_outcome` varchar(255) DEFAULT NULL,
  `policy_fk` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_policy` (`policy_fk`),
  CONSTRAINT `fk_sharing_policy` FOREIGN KEY (`policy_fk`) REFERENCES `sharing_policy_definition` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);


--
-- Table structure for table `sharing_actor`
--


CREATE TABLE `sharing_actor` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `oid` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `actor_type` varchar(255) DEFAULT NULL,
  `secure` tinyint(1) DEFAULT NULL,
  `endpoint` varchar(255) DEFAULT NULL,
  `id_facility_name` varchar(255) DEFAULT NULL,
  `id_application_id` varchar(255) DEFAULT NULL,
  `domain_fk` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_domain` (`domain_fk`),
  CONSTRAINT `fk_sharing_domain` FOREIGN KEY (`domain_fk`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_clinic_info`
--


CREATE TABLE `sharing_clinic_info` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_oid` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `application_name` varchar(255) DEFAULT NULL,
  `facility_name` varchar(255) DEFAULT NULL,
  `universal_id` varchar(255) DEFAULT NULL,
  `namespace` varchar(255) DEFAULT NULL,
  `source_id` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `sharing_code_mapping`
--


CREATE TABLE `sharing_code_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute` varchar(255) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `domain_fk` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_cm_domain` (`domain_fk`),
  CONSTRAINT `fk_sharing_cm_domain` FOREIGN KEY (`domain_fk`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_code_value`
--


CREATE TABLE `sharing_code_value` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code_system` varchar(255) DEFAULT NULL,
  `code` varchar(255) DEFAULT NULL,
  `display_name` varchar(255) DEFAULT NULL,
  `code_system_name` varchar(255) DEFAULT NULL,
  `mapping_fk` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_mapping` (`mapping_fk`),
  CONSTRAINT `fk_sharing_mapping` FOREIGN KEY (`mapping_fk`) REFERENCES `sharing_code_mapping` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_document_export`
--


CREATE TABLE `sharing_document_export` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `document_type` varchar(10) NOT NULL,
  `document` blob NOT NULL,
  `demographic_no` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_document_export_demographic_no` (`demographic_no`),
  CONSTRAINT `fk_sharing_document_export_demographic_no` FOREIGN KEY (`demographic_no`) REFERENCES `demographic` (`demographic_no`) ON DELETE CASCADE ON UPDATE CASCADE
);

--
-- Table structure for table `sharing_exported_doc`
--


CREATE TABLE `sharing_exported_doc` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `affinity_domain` int(11) NOT NULL,
  `demographic_no` int(11) NOT NULL,
  `local_doc_id` int(11) DEFAULT NULL,
  `document_type` varchar(10) NOT NULL,
  `document_uid` varchar(255) NOT NULL,
  `document_uuid` varchar(255) NOT NULL,
  `date_exported` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_exported_doc_domain` (`affinity_domain`),
  CONSTRAINT `fk_sharing_exported_doc_domain` FOREIGN KEY (`affinity_domain`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_infrastructure`
--


CREATE TABLE `sharing_infrastructure` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `alias` varchar(255) DEFAULT NULL,
  `common_name` varchar(255) DEFAULT NULL,
  `organizational_unit` varchar(255) DEFAULT NULL,
  `organization` varchar(255) DEFAULT NULL,
  `locality` varchar(255) DEFAULT NULL,
  `state` varchar(255) DEFAULT NULL,
  `country` varchar(255) DEFAULT NULL,
  `public_key` text,
  `private_key` text,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `sharing_mapping_code`
--


CREATE TABLE `sharing_mapping_code` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute` varchar(255) DEFAULT NULL,
  `code` varchar(255) DEFAULT NULL,
  `code_system` varchar(255) DEFAULT NULL,
  `code_system_name` varchar(255) DEFAULT NULL,
  `display_name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `sharing_mapping_edoc`
--


CREATE TABLE `sharing_mapping_edoc` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `affinity_domain` int(11) NOT NULL,
  `doc_type` varchar(255) NOT NULL,
  `source` varchar(255) NOT NULL,
  `class_code` int(11) DEFAULT NULL,
  `type_code` int(11) DEFAULT NULL,
  `format_code` int(11) DEFAULT NULL,
  `content_type_code` int(11) DEFAULT NULL,
  `event_code_list` int(11) DEFAULT NULL,
  `folder_code_list` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_mapping_edoc_class_code` (`class_code`),
  KEY `fk_sharing_mapping_edoc_type_code` (`type_code`),
  KEY `fk_sharing_mapping_edoc_format_code` (`format_code`),
  KEY `fk_sharing_mapping_edoc_content_type_code` (`content_type_code`),
  KEY `fk_sharing_mapping_edoc_event_code_list` (`event_code_list`),
  KEY `fk_sharing_mapping_edoc_folder_code_list` (`folder_code_list`),
  CONSTRAINT `fk_sharing_mapping_edoc_class_code` FOREIGN KEY (`class_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_edoc_content_type_code` FOREIGN KEY (`content_type_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_edoc_event_code_list` FOREIGN KEY (`event_code_list`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_edoc_folder_code_list` FOREIGN KEY (`folder_code_list`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_edoc_format_code` FOREIGN KEY (`format_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_edoc_type_code` FOREIGN KEY (`type_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_mapping_eform`
--


CREATE TABLE `sharing_mapping_eform` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `affinity_domain` int(11) NOT NULL,
  `eform_id` int(11) NOT NULL,
  `source` varchar(255) NOT NULL,
  `class_code` int(11) DEFAULT NULL,
  `type_code` int(11) DEFAULT NULL,
  `format_code` int(11) DEFAULT NULL,
  `content_type_code` int(11) DEFAULT NULL,
  `event_code_list` int(11) DEFAULT NULL,
  `folder_code_list` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_mapping_eform_class_code` (`class_code`),
  KEY `fk_sharing_mapping_eform_type_code` (`type_code`),
  KEY `fk_sharing_mapping_eform_format_code` (`format_code`),
  KEY `fk_sharing_mapping_eform_content_type_code` (`content_type_code`),
  KEY `fk_sharing_mapping_eform_event_code_list` (`event_code_list`),
  KEY `fk_sharing_mapping_eform_folder_code_list` (`folder_code_list`),
  CONSTRAINT `fk_sharing_mapping_eform_class_code` FOREIGN KEY (`class_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_eform_content_type_code` FOREIGN KEY (`content_type_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_eform_event_code_list` FOREIGN KEY (`event_code_list`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_eform_folder_code_list` FOREIGN KEY (`folder_code_list`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_eform_format_code` FOREIGN KEY (`format_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_eform_type_code` FOREIGN KEY (`type_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_mapping_misc`
--


CREATE TABLE `sharing_mapping_misc` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `affinity_domain` int(11) NOT NULL,
  `type` varchar(255) NOT NULL,
  `source` varchar(255) NOT NULL,
  `class_code` int(11) DEFAULT NULL,
  `type_code` int(11) DEFAULT NULL,
  `format_code` int(11) DEFAULT NULL,
  `content_type_code` int(11) DEFAULT NULL,
  `event_code_list` int(11) DEFAULT NULL,
  `folder_code_list` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_mapping_misc_class_code` (`class_code`),
  KEY `fk_sharing_mapping_misc_type_code` (`type_code`),
  KEY `fk_sharing_mapping_misc_format_code` (`format_code`),
  KEY `fk_sharing_mapping_misc_content_type_code` (`content_type_code`),
  KEY `fk_sharing_mapping_misc_event_code_list` (`event_code_list`),
  KEY `fk_sharing_mapping_misc_folder_code_list` (`folder_code_list`),
  CONSTRAINT `fk_sharing_mapping_misc_class_code` FOREIGN KEY (`class_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_misc_content_type_code` FOREIGN KEY (`content_type_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_misc_event_code_list` FOREIGN KEY (`event_code_list`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_misc_folder_code_list` FOREIGN KEY (`folder_code_list`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_misc_format_code` FOREIGN KEY (`format_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_misc_type_code` FOREIGN KEY (`type_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_mapping_site`
--


CREATE TABLE `sharing_mapping_site` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `affinity_domain` int(11) NOT NULL,
  `source` varchar(255) NOT NULL,
  `facility_type_code` int(11) DEFAULT NULL,
  `practice_setting_code` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_mapping_site_facility_type_code` (`facility_type_code`),
  KEY `fk_sharing_mapping_site_practice_setting_code` (`practice_setting_code`),
  CONSTRAINT `fk_sharing_mapping_site_facility_type_code` FOREIGN KEY (`facility_type_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_mapping_site_practice_setting_code` FOREIGN KEY (`practice_setting_code`) REFERENCES `sharing_mapping_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_patient_document`
--


CREATE TABLE `sharing_patient_document` (
  `patientDocumentId` int(11) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(11) DEFAULT NULL,
  `uniqueDocumentId` varchar(255) DEFAULT NULL,
  `repositoryUniqueId` varchar(45) DEFAULT NULL,
  `creationTime` datetime DEFAULT NULL,
  `isDownloaded` tinyint(1) DEFAULT NULL,
  `affinityDomain` varchar(255) DEFAULT NULL,
  `title` varchar(255) DEFAULT NULL,
  `mimetype` varchar(255) DEFAULT NULL,
  `author` varchar(255) DEFAULT NULL,
  `affinityDomain_fk` int(11) DEFAULT NULL,
  PRIMARY KEY (`patientDocumentId`),
  KEY `fk_sharing_pat_doc_affinityDomain` (`affinityDomain_fk`),
  CONSTRAINT `fk_sharing_pat_doc_affinityDomain` FOREIGN KEY (`affinityDomain_fk`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_patient_network`
--


CREATE TABLE `sharing_patient_network` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(11) DEFAULT NULL,
  `affinity_domain` int(11) DEFAULT NULL,
  `sharing_enabled` tinyint(1) DEFAULT NULL,
  `sharing_key` varchar(255) DEFAULT NULL,
  `date_enabled` date DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_pat_netwk_affinity_domain` (`affinity_domain`),
  CONSTRAINT `fk_sharing_pat_netwk_affinity_domain` FOREIGN KEY (`affinity_domain`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `sharing_patient_policy_consent`
--


CREATE TABLE `sharing_patient_policy_consent` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(11) NOT NULL,
  `affinity_domain_id` int(11) NOT NULL,
  `consent_date` datetime NOT NULL,
  `policy_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_consent_policy_definition` (`policy_id`),
  KEY `fk_sharing_consent_affinity_domain` (`affinity_domain_id`),
  CONSTRAINT `fk_sharing_consent_affinity_domain` FOREIGN KEY (`affinity_domain_id`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `fk_sharing_consent_policy_definition` FOREIGN KEY (`policy_id`) REFERENCES `sharing_policy_definition` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);


--
-- Table structure for table `sharing_value_set`
--


CREATE TABLE `sharing_value_set` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value_set_id` varchar(255) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `attribute` varchar(255) DEFAULT NULL,
  `domain_fk` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_sharing_vs_domain` (`domain_fk`),
  CONSTRAINT `fk_sharing_vs_domain` FOREIGN KEY (`domain_fk`) REFERENCES `sharing_affinity_domain` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
);

--
-- Table structure for table `site`
--


CREATE TABLE `site` (
  `site_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `short_name` varchar(10) NOT NULL DEFAULT '',
  `phone` varchar(50) DEFAULT '',
  `fax` varchar(50) DEFAULT '',
  `bg_color` varchar(20) NOT NULL DEFAULT '',
  `address` varchar(255) DEFAULT '',
  `city` varchar(25) DEFAULT '',
  `province` varchar(25) DEFAULT '',
  `postal` varchar(10) DEFAULT '',
  `status` tinyint(4) NOT NULL DEFAULT '0',
  `providerId_from` int(11) DEFAULT NULL,
  `providerId_to` int(11) DEFAULT NULL,
  `siteLogoId` int(11) DEFAULT NULL,
  `siteUrl` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`site_id`),
  UNIQUE KEY `unique_name` (`name`),
  UNIQUE KEY `unique_shortname` (`short_name`)
);

--
-- Table structure for table `specialistsJavascript`
--


CREATE TABLE `specialistsJavascript` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `setId` char(1) DEFAULT NULL,
  `javascriptString` mediumtext,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `specialty`
--


CREATE TABLE `specialty` (
  `region` varchar(5) DEFAULT '',
  `specialty` char(2) DEFAULT '',
  `specialtydesc` varchar(100) DEFAULT '',
  KEY (`region`)
);

--
-- Table structure for table `study`
--


CREATE TABLE `study` (
  `study_no` int(3) NOT NULL AUTO_INCREMENT,
  `study_name` varchar(20) NOT NULL DEFAULT '',
  `study_link` varchar(255) NOT NULL DEFAULT '',
  `description` varchar(255) NOT NULL DEFAULT '',
  `form_name` varchar(30) DEFAULT NULL,
  `current1` tinyint(1) DEFAULT '0',
  `remote_serverurl` varchar(50) DEFAULT NULL,
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`study_no`)
);

--
-- Table structure for table `studydata`
--


CREATE TABLE `studydata` (
  `studydata_no` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `deleted` tinyint(4) NOT NULL,
  `study_no` int(3) NOT NULL DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `status` varchar(30) DEFAULT NULL,
  `content` text,
  `keyname` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`studydata_no`)
);

--
-- Table structure for table `studylogin`
--


CREATE TABLE `studylogin` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `provider_no` varchar(6) DEFAULT NULL,
  `study_no` int(3) DEFAULT NULL,
  `remote_login_url` varchar(100) DEFAULT NULL,
  `url_name_username` varchar(20) NOT NULL DEFAULT '',
  `url_name_password` varchar(20) NOT NULL DEFAULT '',
  `username` varchar(30) NOT NULL DEFAULT '',
  `password` varchar(100) NOT NULL DEFAULT '',
  `current1` tinyint(1) DEFAULT NULL,
  `creator` varchar(6) NOT NULL DEFAULT '',
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `surveyData`
--


CREATE TABLE `surveyData` (
  `surveyDataId` int(10) NOT NULL AUTO_INCREMENT,
  `surveyId` varchar(40) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `status` char(2) DEFAULT NULL,
  `survey_date` date DEFAULT NULL,
  `answer` varchar(10) DEFAULT NULL,
  `processed` int(10) DEFAULT NULL,
  `period` int(10) DEFAULT NULL,
  `randomness` int(10) DEFAULT NULL,
  `version` int(10) DEFAULT NULL,
  PRIMARY KEY (`surveyDataId`),
  KEY `surveyId_index` (`surveyId`(5)),
  KEY `demographic_no_index` (`demographic_no`),
  KEY `provider_no_index` (`provider_no`),
  KEY `status_index` (`status`),
  KEY `survey_date_index` (`survey_date`),
  KEY `answer_index` (`answer`),
  KEY `processed_index` (`processed`)
);

--
-- Table structure for table `table_modification`
--


CREATE TABLE `table_modification` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT '0',
  `provider_no` varchar(6) NOT NULL DEFAULT '',
  `modification_date` datetime DEFAULT NULL,
  `modification_type` varchar(20) DEFAULT NULL,
  `table_name` varchar(255) DEFAULT NULL,
  `row_id` varchar(20) DEFAULT NULL,
  `resultSet` text,
  PRIMARY KEY (`id`),
  KEY `table_modification_demographic_no` (`demographic_no`),
  KEY `table_modification_provider_no` (`provider_no`),
  KEY `table_modification_modification_type` (`modification_type`(10))
);

--
-- Table structure for table `tickler`
--


CREATE TABLE `tickler` (
  `tickler_no` int(10) NOT NULL AUTO_INCREMENT,
  `demographic_no` int(10) DEFAULT '0',
  `program_id` int(11) DEFAULT NULL,
  `message` text,
  `status` char(1) DEFAULT NULL,
  `update_date` datetime DEFAULT '0001-01-01 00:00:00',
  `service_date` datetime DEFAULT NULL,
  `creator` varchar(6) DEFAULT NULL,
  `priority` varchar(6) DEFAULT 'Normal',
  `task_assigned_to` varchar(255) DEFAULT NULL,
  `category_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`tickler_no`),
  KEY `statusIndex` (`status`),
  KEY `demo_status_date_Index` (`demographic_no`,`status`,`service_date`)
);

--
-- Table structure for table `tickler_category`
--


CREATE TABLE `tickler_category` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `category` varchar(55) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `active` bit(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `tickler_link`
--


CREATE TABLE `tickler_link` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `table_name` char(3) NOT NULL,
  `table_id` int(10) NOT NULL,
  `tickler_no` int(10) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `tickler_text_suggest`
--


CREATE TABLE `tickler_text_suggest` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `creator` varchar(6) NOT NULL,
  `suggested_text` varchar(255) NOT NULL,
  `create_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `active` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `UAO`
--


CREATE TABLE IF NOT EXISTS `UAO` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `started` timestamp,
  `providerNo` varchar(25),
  `friendlyName` varchar(255),
  `name` varchar(255),
  `demographicNo` int(10),
  `resultCode` int(10),
  `defaultUAO` tinyint(1),
  `active` tinyint(1),
  `addedBy` varchar(25),
  `dateCreated` timestamp,
  `dateUpdated` timestamp,
  PRIMARY KEY (`id`)
  );

--
-- Table structure for table `uploadfile_from`
--


CREATE TABLE `uploadfile_from` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `from_name` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `user_ds_message_prefs`
--


CREATE TABLE `user_ds_message_prefs` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `resource_type` varchar(255) DEFAULT NULL,
  `resource_id` varchar(255) DEFAULT NULL,
  `resource_updated_date` date DEFAULT NULL,
  `provider_no` varchar(6) DEFAULT NULL,
  `record_created` date DEFAULT NULL,
  `archived` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `archived` (`archived`),
  KEY `provider_no` (`provider_no`),
  KEY `resource_id` (`resource_id`),
  KEY `resource_type` (`resource_type`)
);

--
-- Table structure for table `vacancy`
--


CREATE TABLE `vacancy` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vacancyName` varchar(255) NOT NULL,
  `templateId` int(11) NOT NULL,
  `status` varchar(24) NOT NULL,
  `dateClosed` timestamp NULL DEFAULT NULL,
  `reasonClosed` varchar(255) DEFAULT NULL,
  `wlProgramId` int(11) NOT NULL,
  `dateCreated` datetime NOT NULL,
  `emailNotificationAddressesCsv` varchar(255) DEFAULT NULL,
  `statusUpdateUser` varchar(25) DEFAULT NULL,
  `statusUpdateDate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `vacancy_client_match`
--


CREATE TABLE `vacancy_client_match` (
  `match_id` int(11) NOT NULL AUTO_INCREMENT,
  `vacancy_id` int(11) DEFAULT NULL,
  `client_id` int(11) DEFAULT NULL,
  `contact_attempts` int(11) DEFAULT NULL,
  `last_contact_date` datetime DEFAULT NULL,
  `status` varchar(30) DEFAULT NULL,
  `rejection_reason` text,
  `form_id` int(10) DEFAULT NULL,
  `match_percent` double DEFAULT NULL,
  `proportion` varchar(8) DEFAULT NULL,
  PRIMARY KEY (`match_id`),
  UNIQUE KEY `vacancy_id` (`vacancy_id`,`client_id`,`form_id`)
);

--
-- Table structure for table `vacancy_template`
--


CREATE TABLE `vacancy_template` (
  `TEMPLATE_ID` int(11) NOT NULL AUTO_INCREMENT,
  `NAME` varchar(100) NOT NULL,
  `ACTIVE` tinyint(1) NOT NULL,
  `WL_PROGRAM_ID` int(11) NOT NULL,
  PRIMARY KEY (`TEMPLATE_ID`)
);

--
-- Table structure for table `validations`
--


CREATE TABLE `validations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `regularExp` varchar(250) DEFAULT NULL,
  `maxValue1` double DEFAULT NULL,
  `minValue` double DEFAULT NULL,
  `maxLength` int(3) DEFAULT NULL,
  `minLength` int(3) DEFAULT NULL,
  `isNumeric` tinyint(1) DEFAULT NULL,
  `isTrue` tinyint(1) DEFAULT NULL,
  `isDate` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `view`
--


CREATE TABLE `view` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `view_name` varchar(255) NOT NULL DEFAULT '',
  `name` varchar(255) NOT NULL DEFAULT '',
  `value` text,
  `role` varchar(255) NOT NULL DEFAULT '',
  `providerNo` varchar(6) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

--
-- Table structure for table `waitingList`
--


CREATE TABLE `waitingList` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `listID` int(11) DEFAULT NULL,
  `demographic_no` int(10) NOT NULL DEFAULT '0',
  `note` varchar(255) DEFAULT NULL,
  `position` bigint(20) NOT NULL DEFAULT '0',
  `onListSince` datetime NOT NULL,
  `is_history` char(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `listID` (`listID`)
);

--
-- Table structure for table `waitingListName`
--


CREATE TABLE `waitingListName` (
  `ID` bigint(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL DEFAULT '',
  `group_no` varchar(10) DEFAULT '',
  `provider_no` varchar(6) DEFAULT '',
  `create_date` datetime NOT NULL,
  `is_history` char(1) DEFAULT 'N',
  PRIMARY KEY (`ID`)
);

--
-- Table structure for table `workflow`
--


CREATE TABLE `workflow` (
  `ID` int(10) NOT NULL AUTO_INCREMENT,
  `workflow_type` varchar(100) DEFAULT NULL,
  `provider_no` varchar(20) DEFAULT NULL,
  `demographic_no` int(10) DEFAULT NULL,
  `completion_date` date DEFAULT NULL,
  `current_state` varchar(50) DEFAULT NULL,
  `create_date_time` datetime DEFAULT NULL,
  PRIMARY KEY (`ID`)
);

CREATE TABLE `SystemPreferences` (
  `id`         INT AUTO_INCREMENT PRIMARY KEY,
  `name`       VARCHAR(40) NULL,
  `updateDate` DATETIME    NULL,
  `value`      VARCHAR(40) NULL
);

CREATE TABLE `rbt_groups` (
  `id` int(11) AUTO_INCREMENT,
  `tid` int(11) DEFAULT NULL,
  `group_name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

