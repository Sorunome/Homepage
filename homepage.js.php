<?php
header('Content-Type: text/javascript');
echo 'LOGGEDIN='.($security->isLoggedIn()?'true':'false').';';
?>
homepage = (function(){
	var self = {
			network:{
				relog:function(fn,forceReload){
					$.getJSON("/getKeys?norelog").done(function(keys){
						$.getScript('/jsencrypt.min.js?norelog',function(){
							var encrypt = new JSEncrypt();
							encrypt.setPublicKey(atob(keys.hash.key));
							var pwdenc = encrypt.encrypt(localStorage.getItem("longtimePwd"));
							$.post("/account/verifyLogin?ltpwdv&norelog",{
								pwd:pwdenc,
								id:keys.hash.id,
								fkey:keys.form.key,
								fid:keys.form.id,
								uid:localStorage.getItem("id")
							}).done(function(data){
								if(data.success){
									document.cookie="session-id="+escape(data.sessid)+"; path=/";
									if(LOGGEDIN){
										if(typeof fn == 'function'){
											fn(data);
										}
									}else{
										window.location.reload();
									}
								}else{
									document.cookie="shouldlogin=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT";
									localStorage.removeItem("longtimePwd");
									localStorage.removeItem("id");
									if(LOGGEDIN){
										window.location.reload();
									}
								}
								if(forceReload===true){
									window.location.reload();
								}
							});
						});
					});
				},
				checkReLog:function(data,url,pdata,fn,status){
					if(data.relogin!==undefined && data.relogin){
						self.network.relog(function(){
							if(pdata===false){
								self.network.get(url,fn);
							}else{
								self.network.post(url,pdata,fn);
							}
						});
					}else{
						if(typeof fn == 'function'){
							fn(data,status);
						}
					}
				},
				get:function(url,fn){
					$.get(url).done(function(data){
						self.network.checkReLog(data,url,false,fn,200);
					}).error(function(data){
						self.network.checkReLog(data.responseJSON || data.responseText,url,false,fn,data.status);
					});
				},
				post:function(url,pdata,fn){
					$.post(url,pdata).done(function(data){
						self.network.checkReLog(data,url,pdata,fn,200);
					}).error(function(data){
						self.network.checkReLog(data.responseJSON || data.responseText,url,pdata,fn,data.status);
					});
				}
			}
		};
	return {
			get:function(url,fn){
				self.network.get(url+((url.indexOf('?')!=-1)?'&hps':'?hps'),fn);
			},
			post:function(url,data,fn){
				self.network.post(url+((url.indexOf('?')!=-1)?'&hps':'?hps'),data,fn);
			},
			relog:function(){
				self.network.relog(function(){
					window.location.reload();
				},true);
			}
		};
})();