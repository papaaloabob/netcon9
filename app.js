var env=require('../../.environment.conf.js');
var site=require('./.app.conf.js');
var path=require('path');
var ht=require('../common/ht');
var css=require('./css');
var std=require("./stdPage");
//var sqlconfig= require('./.mysqlconfig');
var mysql=require('../common/mysqlfun')
var mypool=mysql.init(require('./.mysqlconfig').config);
var app={
        sql:{
                escape:function(aStr){return mypool.escape(aStr);},
                insert:function(a$){return mysql.insert(mypool,a$);},
                query:function(a$,cb){return mysql.query(mypool,a$,cb);},
                hash:function(aStr){return mysql.hash(aStr);},
                hashCompare:function(dat,hash,salt){return mysql.hashCompare(dat,hash,salt);}
                },//sql
        sess:   require('../common/sessions'),
        sessions:       [],
        abusiveIPs:     [],
        abusiveCookies: [],
        std:    std,
        srv:    require('../common/srvfun')
        };

var dologin = require("../common/dologin");
var login =require("./login");
var dashboard = require("./dashboard");
var about = require("./about");
var legal = require("./legal");
var legalg = require("./legalg");
var legalp = require("./legalp");
var process1 = require("./process1");
var getstarted = require("./getstarted");
var createacct = require("./createacct");
var doaccount = require("./doaccount");
var faq = require("./faq");
var test = require("./test");
//var  = require("./");
//var  = require("./");


var url = require("url");

var index = require("./index");

exports.registerIO=function(ioSock){

        ioSock.sockets.on('connection', function (socket) {
//              socket['lang']=translate.getDefaults();
                console.log(socket['lang']);

                //lang is the session settings for language and keyboard, etc.
//              socket.on('saveSessionLang', function (data){lang.saveSessionVar(socket,'sessLang',data);});
//              socket.on('saveAuxKb', function (data){lang.saveSessionVar(socket,'auxKb',data);});

                //lang settings in translate are settings for translation
//              socket.on('translate', function (data){translate.input(socket,data);});
  //            socket.on('saveInLang', function (data){translate.setInLang(socket,data);});
//              socket.on('saveOut1Lang', function (data){translate.setOut2Lang(socket,data);});
//              socket.on('saveOut2Lang', function (data){translate.setOut2Lang(socket,data);});
  //            socket.on('getTranslateLangs', function (data){translate.getLangSels(socket,data);});
                });//io.sockets.on

        }//function registerIO


/*
pages are either free, not requiring a session or cookies,
  or they require a session.
sessions always originate with the login page, which is the only page that will return a cookie.

if cookie,
  if present session found,
    if sourceip and sessionip equal,
        if logged in proceed to page
        if not logged in,
           if page requires login, redirect to login else return page
    if sourceip and sessionip not equal, redirect to login.
  if no previous session found,


a session is abusive and will be locked out on repeated failed login attempts.
        cleared on successful login, or after two hours.

a cookie is abusive if it does not represent a real session and is repeatedly presented.
        will try to set a new cookie, clear after two hours

an ip is abusive it it repeatedly presents but will not set a cookie.
        clear after two hours
*/

                //we'd like to handle logged in clients, followed by logged out clients, followed by those with a sessionId
                //here, we will check the in memory sessions array for the cookie first...if not valid, check the db
exports.doReq=function(req,res){
        req.app=app;
        app.srv.logRequest(req, res);
        var apath = url.parse(req.url).pathname;
        if (apath=='/'){var pathname='/index';}else{var pathname=apath;};
        //handle plain pages immediately, no need session
        switch(pathname){               //free gets, no session or password required,
                case "/index":{stdPage(req,res,index);break;};
                case "/about":{stdPage(req,res,about);break;};
                case "/legal":{stdPage(req,res,legal);break;};
                case "/legalg":{stdPage(req,res,legalg);break;};
                case "/legalp":{stdPage(req,res,legalp);break;};
                case "/process1":{stdPage(req,res,process1);break;};
                case "/getstarted":{stdPage(req,res,getstarted);break;};
                case "/createacct":{stdPage(req,res,createacct);break;};
                case "/faq":{stdPage(req,res,faq);break;};
                case "/lockout":{replyLockout(res);break;};
                case "/test":{stdPage(req,res,test);break;};
                case "/favicon.ico":{filestream(req,res,pathname);break;};

                case "/twilio-common.min.js":{filestream(req,res,pathname);break;};
                case "/twilio-video.js":{filestream(req,res,pathname);break;};
                case "/jquery.min.js":{filestream(req,res,pathname);break;};
                case "/quickstart.js":{filestream(req,res,pathname);break;};

                default:{ sessionRequired(req,res,pathname);break;};            //rest require a session
                }
        }

function sessionRequired(req,res,pathname){     //request for anything that requires a session
        if (req.headers.cookie){
                if (app.sess.activeSessionInMemory(req)){                                               //cookie found in current sessions array, also checks ip's
                        handleSessionReq(req,res,pathname);             //so just hadle the request
                }else{                                                  //not a current session, so check db, unless abusive.
                        if (app.sess.abusiveCookie(req)){replyAbusive(res);return;};    //if abusive, just end the session
                        //otherwise see if we can continue a saved session
                        //using a view, so we can get user prefs and anything else needed at one time.
                        sql='select * from Sessions where sUuid='+app.sql.escape(req.headers.cookie)+';';
                        //console.log(sql);
                        app.sql.query(sql,function(results){cbSession(results,req,res,pathname)});
                        };//else, not active session, but have cookie, so query and handle with callback
        }else{  //no cookie, so only serve the index page, but check ip for abuse
                if (app.sess.abusiveIP(req)){replyAbusive(res);return;};        //just end the response for abusive IP's
                app.srv.redirect(res,'/index');
                };//if cookie
        }//sessionRequired


//------------------------------------------------------------------------------------------------------------

function handleSessionReq(req,res,pathname){            //have session, but may or may not be logged in
        // get or put, logged or not
        var bLoggedIn=req.app.sess.loggedIn(req);

        if (bLogged && (req.method=='GET')){            //logged in get
                switch(pathname){
                        case "/logout":{logout(req,res);break;};
                        case "/dashboard":{stdPage(req,res,dashboard);break;};
                        default:  {console.log('App ERROR-not found: '+pathname);app.srv.send404(res);break;};        // not found
                                }//switch
        }else if (bLogged && (req.method=='POST')){     //logged in post
                switch(pathname){
                        default:  {console.log('App ERROR-not found: '+pathname);app.srv.send404(res);break;};        // not found
                        }//switch
        }else if (!bLogged && (req.method=='GET')){     //Not logged in get
                switch(pathname){
                        case "/login":{stdPage(req,res,login);break;};
                        default:  {console.log('App ERROR-not found: '+pathname);app.srv.send404(res);break;};        // not found
                        };//switch
        }else if (!bLogged && (req.method=='POST')){    //not logged in post
                switch(pathname){
                        case "/dologin":{dologin.doLogin(req,res);break;};      //post to login
                        case "/doaccount":{doAccount.doCreate(req,res);break;};  //post to create account
                        default:  {console.log('App ERROR-not found: '+pathname);app.srv.send404(res);break;};        // not found
                        };//switch
        }else{  //not a get or post method
                console.log('App ERROR-method not found: '+req.method+'  '+pathname);
                app.srv.send404(res);
                };//if

        }//handleSessionReq

//------------------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------------------

function stdPage(req,res,myPage){               //only called from logged In, or called for index unlogged
//      myPage.doPage(req,res);
        res.writeHead(200, myPage.headers());//write head.  note that we're passing a list of parms to set, NOT a string to send to the browser.

        var body=ht.body('standardBody',myPage.body(req));

        var styles=css.getStyles(body);

        var htmlHead=req.app.std.stdMeta()+ht.title(myPage.title());
        var head=std.stdHead(htmlHead+styles+myPage.headScript());

        res.write(std.stdHtml(head,body))
        res.end();
        }//stdPage

function cbSession(results,req,res,pathname){   //callback with results of session query
        //here because had a cookie, and was not abusive
        //if is a good cookie, setup a current session and return the desired page.
        //if not found in db, attempt to set a new cookie.
        // session ip should match the request ip, unless the user has moved physical location or received a new ip.
        //if ip has changed, need to get a new authentication.
        //if ip has not changed, may be a continuation of a previous session or a new session.
        //check the client options to see if we were supposed to keep them logged in or not?
        if (results && results.length > 0) {    //have a valid session id, check if ip matches
                var dat=results[0];
                var realIP=req.headers['x-real-ip'];
                if ((realIP==dat.sLastIP)&&(dat.sLoggedIn=='Y')&&(dat.sStayLoggedIn=='Y')){     //connection from same IP as prev login
                        app.sess.createSessionFromData(dat,req,true);                   //logged in session, also clears abusive Cookie
                        handleSessionReq(req,res,pathname);
                        return; //
                }else{          //in db, but different IP or not logged in or not preferred to stay logged in, so go to login page
                        app.sess.createSessionFromData(dat,req,false);  //logged out session
//                      app.srv.redirect(res,'/login');
                                handleSessionReq(req,res,pathname);
                        return; //
                        };// if realIp=lastIP and loggedIn and sStayLoggedIn

        }else{
                //cookie not in database,so set as abusive cookie.
                // here because a page was requested that requires a session,
                //so we can assume that someone tried to get a session required with
                //a forged cookie
                app.sess.setAbusiveCookie(req); //not in db, so not our cookie.
                replyAbusive(res);
                return;
                };// if results
        }//cbSession

function quoted(a){ return '"'+a+'"';}

function csvAppend(csv,dat){
        if (csv==''){return dat;};
        return csv+','+dat;
        }//csvAppend

function logout(req,res){
        app.srv.redirect(res, '/index');
        if (app.sess.activeSessionInMemory(req)){ //must have an active session to lo
                app.sess.logout(req);
                };//if
        }//logout

function replyAbusive(res){res.write('working');res.end();};

function replyLockout(res){res.write('locked out. try again in 10 minutes');res.end();};

function filestream(req,res,pathname){
        var fn=path.join(env.path, site.static, pathname);
        app.srv.fileStream(req,res,fn,'ico');
        }


