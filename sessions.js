/*
sessions[{
        uuid: auuid,
        userId: user,
        userName: name,
        logintime: atime,
        loginIP: anIP,
        lasttime: atime,
        userAgent: anAgent,
        userAccept: accept,
        UserLang: aLang,
        userEncoding: encoding,

        failCount: 0;
        perhaps keep state here too.
        }];

req.app.abusiveIPs[             //list of IP's that won't set a cookie.
        {ip: givenip,
        beginTime: aTime,
        lastTime: aTime}
        ]

req.app.abusiveCookies[         //list of Cookies that are not valid or have repeatedly failed login
        {uuid: aUuid,
        sourceIP,
        beginTime: aTime,
        lastTime: aTime}
        ]
*/

const uuid = require('uuid/v4');
//var sessions=[];
//var abusiveIPs=[];
//var abusiveCookies=[];

exports.createSession=function(req){    //set the cookie to expire  at end of century, so we can re-use.
        //              'Set-Cookie':   '12345678939406893737ae3; SameSite=Strict; Expires=Wed, 21 Oct 2099 07:28:00 GMT;',
        var xuuid=uuid();       //new uuid
        //insert the uuid and session record into the db, and into the sessions array.
        var realIP=req.headers['x-real-ip'];
        var uAgent=left(req.headers['user-agent'],128);
        var uAccept=left(req.headers.accept,64);
        var uLanguage=left(req.headers['accept-language'],16);
        var uEncoding=left(req.headers['accept-encoding'],16);
        var d = new Date();
        var ts = d.getTime();

        var csv='';
        csv+='0,'+quoted(xuuid)+',"","",'+quoted(realIP)+',0,'+ts;
        csv=csvAppend(csv,req.app.sql.escape(uAgent));
        csv=csvAppend(csv,req.app.sql.escape(uAccept));
        csv=csvAppend(csv,req.app.sql.escape(uLanguage));
        csv=csvAppend(csv,req.app.sql.escape(uEncoding));
        csv+=',0,"N"';          //failcount, logged in
        var sql='insert Sessions values ('+csv+');';
        req.app.sql.insert(sql);

        var sess={
                userName: '',
                location: '',
                loginIP: realIP,
                logintime: 0,
                lasttime: ts,
                userAgent: uAgent,
                userAccept: uAccept,
                UserLang: uLanguage,
                userEncoding: uEncoding,
                failCount: 0,
                loggedIn: 'N'
                };

        req.app.sessions[xuuid]=sess;
        console.log('created session: '+xuuid);
        return xuuid;
        };//createSession

exports.cookieForSession=function(aUuid){
        return aUuid+'; SameSite=Strict; Expires=Wed, 21 Oct 2099 07:28:00 GMT;';
        }//cookie for session


exports.createSessionFromData=function(dat,req,fLogged){        //create and return a session object based on data from database,
                                                                //add to mem sessions and update database if needed
                                                                //dat will have an existing uuid
                                                                //also clear from abusivecookies

        var uAgent=left(req.headers['user-agent'],128);
        var uAccept=left(req.headers.accept,64);
        var uLanguage=left(req.headers['accept-language'],16);
        var uEncoding=left(req.headers['accept-encoding'],16);
        var d = new Date();
        var ts = d.getTime();
        if (fLogged){sLoginTime=dat.sLoginTime;sLogged='Y';}else{sLoginTime=ts;sLogged='N';};

        var csv='';
        csv=csvAppend(csv,'sLastAccess='+ts);
        csv=csvAppend(csv,'sLoginTime='+sLoginTime);
        csv=csvAppend(csv,'sAgent='+req.app.sql.escape(uAgent));
        csv=csvAppend(csv,'sAccept='+req.app.sql.escape(uAccept));
        csv=csvAppend(csv,'sLanguage='+req.app.sql.escape(uLanguage));
        csv=csvAppend(csv,'sEncoding='+req.app.sql.escape(uEncoding));
        csv=csvAppend(csv,'sFailCount=0');
        csv=csvAppend(csv,'sLoggedIn='+quoted(sLogged));
        updateDb(csv,req);
//        var sql='update Sessions set '+csv;
//      sql+=' where sId='+dat.sId+';';
//        req.app.sql.query(sql,'');                            //update the database

        var sess={                                      //create in-memory session record
                userName: dat.sUserName,
                location: dat.sLocation,
                loginIP: dat.sLastIP,
                logintime: sLoginTime,
                lasttime: ts,
                userAgent: uAgent,
                userAccept: uAccept,
                UserLang: uLanguage,
                userEncoding: uEncoding,
                failCount: 0,
                loggedIn: sLogged
                };
        req.app.sessions[dat.sUuid]=sess;
//        console.log('restored session:'+dat.sUuid);
//        console.log(sessions);
//      return sess;
        };//create session from data


function updateDb(csv,req){
        var sql='update Sessions set '+csv;
        sql+=' where sUuid='+req.app.sql.escape(req.headers.cookie)+';';
        req.app.sql.query(sql,'');                            //update the database
        console.log(sql);
        console.log('db update for: '+req.headers.cookie);
        }//update db


exports.login=function(req,dat){
        var d = new Date();
        var ts = d.getTime();

        //update the in-memory session
        req.app.sessions[req.headers.cookie].userName= dat.clUserName;
        req.app.sessions[req.headers.cookie].location=dat.sLocation;
        req.app.sessions[req.headers.cookie].loginIP=req.headers['x-real-ip'];
        req.app.sessions[req.headers.cookie].logintime=ts;
        req.app.sessions[req.headers.cookie].lasttime=ts;
        req.app.sessions[req.headers.cookie].failCount=0;
        req.app.sessions[req.headers.cookie].loggedIn='Y';



        var csv='';
        csv=csvAppend(csv,'sLastIP='+quoted(req.headers['x-real-ip']));
        csv=csvAppend(csv,'sLastAccess='+ts);
        csv=csvAppend(csv,'sLoginTime='+ts);
        csv=csvAppend(csv,'sFailCount=0');
        csv=csvAppend(csv,'sLoggedIn='+quoted('Y'));
        console.log('logged in: '+req.headers.cookie);
        updateDb(csv,req);
        };//login

exports.loggedIn=function(req){
        if (req.app.sessions[req.headers.cookie]){
                if (req.app.sessions[req.headers.cookie].loggedIn=='Y'){
                        console.log('checked login: '+req.headers.cookie);
                        return true;
                        };
                };//if session
        return false;
        };//login

exports.failcount=function(req){
//console.log('failcount');
//console.log(sessions[req.headers.cookie].failCount);
        if (req.app.sessions[req.headers.cookie]){
                return req.app.sessions[req.headers.cookie].failCount;
                };//if session
        return 0;
        };//login


exports.location=function(req){
        if (req.app.sessions[req.headers.cookie]){
                return req.app.sessions[req.headers.cookie].location;
                };//if session
        return 'not set';
        };//login



exports.activeSessionInMemory=function(req){    //this is the memory based, fast access for active sessions
                                                        //check sessions array for the cookie, and update the last access time.
//      console.log(sessions);
        if (req.app.sessions[req.headers.cookie]){
                if (req.headers['x-real-ip']==req.app.sessions[req.headers.cookie].loginIP){    //connection from same IP as last time
                        var d = new Date();
                        req.app.sessions[req.headers.cookie].lasttime=d.getTime();;
                        console.log('session in memory: '+req.headers.cookie);
                        return true;    //aSession;
                        };//realIP
                };//aSession
        console.log('session not in memory: '+req.headers.cookie);
        return false;
        };//activeSessionInMemory


exports.loginFailed=function(req){              //increment the failed count and return the new count
        var d = new Date();
        req.app.sessions[req.headers.cookie].logintime=0;
        req.app.sessions[req.headers.cookie].lasttime=d.getTime();
        req.app.sessions[req.headers.cookie].loggedIn='N';
        req.app.sessions[req.headers.cookie].failCount++;
        return req.app.sessions[req.headers.cookie].failCount;
        };//loginFailed


exports.logout=logout;
function logout(req){                                           //called from logout.js
                                                                //NOTE:  we are not deleting session, just logging out
        console.log('logged out: '+req.headers.cookie);

        var d = new Date();
        var ts = d.getTime();

        req.app.sessions[req.headers.cookie].logintime=ts;
        req.app.sessions[req.headers.cookie].failCount=0;
        req.app.sessions[req.headers.cookie].loggedIn='N';

        var csv='';
        csv=csvAppend(csv,'sFailCount=0');
        csv=csvAppend(csv,'sLoggedIn='+quoted('N'));
        updateDb(csv,req);
        };//login

                                                        //called from dologin.js for failed logins and server.js for bogus cookie (not in our db)
exports.setAbusiveCookie=function(req){         //add the session to the abusive cookies list.
                                                        //no need to count, it is either an invalid cookie, or repeated login failure.
                                                        //set from db query on cookie, not found, or dologin repeated failures.
        var d = new Date();
        var ts = d.getTime();
        abusiveCookie={
                sourceIP:req.headers['x-real-ip'],
                beginTime: ts,
                lastTime: ts};

        req.app.abusiveCookies[req.headers.cookie]=abusiveCookie;
        console.log('set abusive cookie: '+req.headers.cookie);

        removeActiveSession(req);
        };//setAbusive

function removeActiveSession(req){                      //called internally from setAbusiveCookie, may not be a session, and never loggedIn
        //logout(req);                          //abusive cookie is never logged in
        delete req.app.sessions[req.headers.cookie];    //but may have an active session
        console.log('session removed from memory: '+req.headers.cookie);
        }//remove Active Session

exports.abusiveCookie=function(req){    //check for abusive Cookie, and increment the count and last time.
                                        //cookie is abusive if it repeatedly presents, but does not represent a valid session.
                                        //  NOTE: this test occurs before the database access,
                                        // so cookie will be added to the array if fails db access, or exceeds login attempts.
                                        //  so we just want to check if it exists here.
        if (req.app.abusiveCookies[req.headers.cookie]){
                console.log('abusive cookie found: '+req.headers.cookie);
                return true;
        }else{
                console.log('abusive cookie not: '+req.headers.cookie);
                return false;
                };
        };//abusiveCookie

exports.abusiveIP=function(req){                //check for abusive IP and increment the count and last time.
        var ip=req.headers['x-real-ip'];
        var d = new Date();
        var ts = d.getTime();
        if (req.app.abusiveIPs[ip]){
                req.app.abusiveIPs[ip].count++;
                req.app.abusiveIPs[ip].last=ts;
        }else{
                req.app.abusiveIPs[ip]={count:1, last: ts};
                };
        console.log('check abusive IP: '+ip);
        if (req.app.abusiveIPs[ip].count>30){return true;}else{return false;};  //abusive, more than thirty requests, but won't accept cookie.
        };//abusiveIP

function purgeAbusiveCookies(){         //purge Cookies from list whom have not been active recently

        };//purgeAbusiveCookies

function purgeAbusiveIPs(){             //purge IP's from list after they have been inactive.

        };//purgeAbusiveIPs

function purgeActiveSessions(){         //purge the active Sessions of stale session records

        };//purgeActiveSessions

function quoted(a){ return '"'+a+'"';}

function csvAppend(csv,dat){
        if (csv==''){return dat;};
        return csv+','+dat;
        }//csvAppend

function left(a,b){return a.substr(0,b);};
