/*

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

*/
angular.module("demographicServices", [])
	.service("demographicService", function ($http,$q,$log, $httpParamSerializerJQLike) {
		return {
		apiPath:'/oscar/ws/rs/',
		configHeaders: {headers: {"Content-Type": "application/json","Accept":"application/json"}},
		configHeadersWithCache: {headers: {"Content-Type": "application/json","Accept":"application/json"},cache: true},
		
        getDemographic: function (demographicNo) {
            //$log.error("2Debug: calling getDemographic");
            var deferred = $q.defer();
            $http.get(this.apiPath+'demographics/'+demographicNo,this.configHeadersWithCache).then(function (response){
            	console.log(response.data);
            	deferred.resolve(response.data);
            },function(){
            	console.log("error fetching demographic");
            	deferred.reject("An error occured while fetching items");
            });
     
          return deferred.promise;
            
        },
        
        saveDemographic: function (demographic) {
        	var deferred = $q.defer();
        	$http.post(this.apiPath+'demographics',demographic).then(function (response){
            	console.log(response.data);
            	deferred.resolve(response.data);
          },function(){
        	  console.log("error fetching items");
        	  deferred.reject("An error occured while fetching items");
          });
     
          return deferred.promise;
        },
        
        updateDemographic: function(demographic){
        	var deferred = $q.defer();
        	$http.put(this.apiPath+'demographics',demographic).then(function (response){
            	console.log(response.data);
                deferred.resolve(response.data.demographicTo1);
            },function(){
          	  console.log("error fetching items");
              deferred.reject("An error occured while fetching items");
            });
       
            return deferred.promise;
        	
        },
        
        search: function(search,startIndex,itemsToReturn){
        	var deferred = $q.defer();
        	$http.post(this.apiPath+'demographics/search?startIndex='+startIndex + "&itemsToReturn="+itemsToReturn,search).then(function (response){
        		deferred.resolve(response.data);
            },function(){
          	  console.log("error fetching items");
              deferred.reject("An error occured while fetching items");
            });
       
            return deferred.promise;
        },
        
        searchIntegrator: function(search,itemsToReturn){
        	var deferred = $q.defer();
        	$http.post(this.apiPath+'demographics/searchIntegrator?itemsToReturn='+itemsToReturn,search).then(function (response){
        		deferred.resolve(response.data);
            },function(){
          	  console.log("error fetching integrator items");
              deferred.reject("An error occured while fetching items");
            });
       
            return deferred.promise;
        },
        
        matchDemographic: function(searchPatient) {
            let deferred = $q.defer();
            $http.post(this.apiPath+'demographics/matchDemographic', searchPatient).then(function(response){
                deferred.resolve(response);
            }, function(response){
                console.log("error matching demographic");
                deferred.reject(response);
            });

            return deferred.promise;
        }
    };
});