<?php
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
error_reporting(-1);
session_start();
if(!isset($_SESSION['id']))
	$_SESSION['id']=false;
ob_start();
include_once('config.php');
$lang = 'en';
$queryNum = 0;
date_default_timezone_set('UTC');
/*
Settings:
1 - display normal page (header, footer etc)
2 - not be in nav

User
Power
1 - active
2 - omnomirc ops
*/
abstract class sql{
	private $mysqliConnection;
	private static function connectSql(){
		global $sql_username,$sql_password,$sql_host,$sql_db,$mysqliConnection;
		if(isset($mysqliConnection)){
			return $mysqliConnection;
		}
		$mysqli = new mysqli($sql_host,$sql_username,$sql_password,$sql_db);
		if ($mysqli->connect_errno) 
			die('Could not connect to SQL DB: '.$mysqli->connect_errno.' '.$mysqli->connect_error);
		$mysqli->autocommit(true);
		$mysqliConnection = $mysqli;
		return $mysqli;
	}
	public static function query($query,$args = [],$num = false){
		global $queryNum;
		$mysqli = self::connectSql();
		for($i=0;$i<count($args);$i++)
			$args[$i] = $mysqli->real_escape_string($args[$i]);
		$result = $mysqli->query(vsprintf($query,$args));
		$queryNum++;
		if($mysqli->errno==1065) //empty
			return array();
		if($mysqli->errno!=0) 
			die($mysqli->error.' Query: '.vsprintf($query,$args));
		if($result===true) //nothing returned
			return array();
		$res = array();
		$i = 0;
		while($row = $result->fetch_assoc()){
			$res[] = $row;
			if($num!==false && $i===$num){
				$result->free();
				return $row;
			}
			if($i++>=150)
				break;
		}
		if($res === []){
			$fields = $result->fetch_fields();
			for($i=0;$i<count($fields);$i++)
				$res[$fields[$i]->name] = NULL;
			if($num===false)
				$res = array($res);
		}
		$result->free();
		return $res;
	}
}
abstract class security{
	private static function clearOldKeys(){
		sql::query("DELETE FROM form_keys WHERE ts < (NOW() - INTERVAL 1 MINUTE)");
		sql::query("DELETE FROM rsa_keys WHERE ts < (NOW() - INTERVAL 1 MINUTE)");
	}
	private static function makeFormKey(){
		self::clearOldKeys();
		$s = self::generateRandomString(50);
		sql::query("INSERT INTO form_keys (fkey) VALUES ('%s')",[$s]);
		$id = sql::query("SELECT MAX(id) FROM form_keys",[],0);
		return [$s,$id['MAX(id)']];
	}
	private static function createKeys(){
		self::clearOldKeys();
		$res = openssl_pkey_new();
		openssl_pkey_export($res, $privKey);
		$pubKey = openssl_pkey_get_details($res);
		$pubKey = $pubKey['key'];
		sql::query("INSERT INTO rsa_keys (privKey,pubKey) VALUES ('%s','%s')",[$privKey,$pubKey]);
		$id = sql::query("SELECT MAX(id) FROM rsa_keys",[],0);
		return [$pubKey,$id['MAX(id)']];
	}
	public static function generateRandomString($length = 10) {
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$randomString = '';
		for($i = 0;$i < $length;$i++) {
			$randomString .= $characters[rand(0, strlen($characters) - 1)];
		}
		return $randomString;
	}
	public static function validateForm($id,$key){
		self::clearOldKeys();
		$key2 = sql::query("SELECT fkey FROM form_keys WHERE id='%s'",[$id],0);
		sql::query("DELETE FROM form_keys WHERE id='%s'",[$id]);
		if($key!=$key2['fkey'])
			return false;
		return true;
	}
	public static function getPwdFromKey($id,$pwd){
		self::clearOldKeys();
		$key = sql::query("SELECT privKey FROM rsa_keys WHERE id='%s'",[$id],0);
		sql::query("DELETE FROM rsa_keys WHERE id='%s'",[$id]);
		@openssl_private_decrypt(base64_decode($pwd),$end,@openssl_get_privatekey($key['privKey']));
		return $end;
	}
	public static function makeKeysJSON(){
		$fk = self::makeFormKey();
		$hk = self::createKeys();
		return '{"form":{"id":"'.$fk[1].'","key":"'.$fk[0].'"},"hash":{"id":"'.$hk[1].'","key":"'.base64_encode($hk[0]).'"}}';
	}
	public static function checkPwdAndForm($id,$pwd1,$salt,$hash,$id2,$pwd2){
		global $private_salt_key;
		if(!self::validateForm($id2,$pwd2))
			return 1;
		$pwd = self::getPwdFromKey($id,$pwd1);
		$hSalt = Password::hash($salt,$private_salt_key);
		if(Password::hash($pwd,$hSalt)!=$hash)
			return 2;
		return false;
	}
}
function getVar($s){
	$r = sql::query("SELECT content FROM vars WHERE name='%s'",[$s],0);
	//$r = $res -> fetch_assoc();
	if(isset($r['content']))
		return $r['content'];
	return false;
}
function setVar($s,$c){
	$r = sql::query("SELECT id FROM vars WHERE name='%s'",[$s],0);
	//$r = $res -> fetch_assoc();
	if(isset($r['id'])){
		sql::query("UPDATE vars SET content='%s' WHERE name='%s'",[$c,$s]);
	}else{
		sql::query("INSERT INTO vars (name,content) VALUES('%s','%s')",[$s,$c]);
	}
}


include_once('bbCodeParser.php');
include_once('bbCodeParserDefaultTags.php');
abstract class page{
	private static function getImageNotFound() {
		$img = imagecreatetruecolor(180,17);
		imagestring($img,7,0,0,"Couldn't find image.",imagecolorallocate($img, 255, 255, 255));
		return $img;
	}
	private static function do404() {
		header('HTTP/1.0 404 Not Found');
		ob_end_clean();
		return 'I just don\'t know what went wrong!';
	}
	private static function getQuickLinks($lang,$pathPartsParsed){
		$quickLinks = '';
		$temp = $pathPartsParsed;
		$link = explode("/",$_SERVER['REQUEST_URI']);
		$getParams = 'title_%s';
		do{
			for($i=sizeof($temp)-1;$i>=0;$i--){
				if(sizeof($temp)==1){
					$query = "SELECT $getParams FROM pages WHERE name='%s' AND refId='1'";
					break;
				}
				if($i==sizeof($temp)-1){
					$query = "SELECT id FROM pages WHERE name='%s' AND refId='1' LIMIT 1";
				}elseif($i!=0){
					$query = "SELECT id FROM pages WHERE refId=($query) AND name='%s'";
				}else{
					$query = "SELECT $getParams FROM pages WHERE refId=($query) AND name='%s'";
				}
			}
			$page = sql::query($query,array_merge([$lang],$temp),0);
			$name = $page['title_'.$lang];
			if(!$name){
				$goodlink = explode('.',$link[sizeof($temp)]);
				$goodlink = explode('?',$goodlink[0]);
				$name = strtoupper(substr($goodlink[0],0,1)).substr($goodlink[0],1);
			}
			if($name!='' && $name!='Index')
				$quickLinks = '<a href="/'.join('/',$temp).'">'.$name.'</a> &gt; '.$quickLinks;
		}while(array_pop($temp) && count($temp)>0);
		return substr('<a href="/">Home</a> &gt; '.$quickLinks,0,-6);
	}
	private static function getHeader($title,$lang,$pathPartsParsed,$headStuff = ''){
		global $user_info;
		return implode(['<!DOCTYPE html>',
			'<html>',
				'<head>',
					"<title>$title</title>",
					$headStuff,
					'<link rel="stylesheet" type="text/css" href="/style.css">',
					'<link rel="icon" type="image/png" href="/media/favicon.png">',
					'<meta http-equiv="content-type" content="text/html; charset=UTF-8">',
					'<script type="text/javascript" src="/jquery-2.0.3.min.js"></script>',
				'</head>',
				'<body>',
					'<div id="main">',
					'<table style="margin:0;padding:0;border:none;width:100%;font-size:11px">',
						'<tr>',
							'<td style="width:50%;text-align:left"></td>',
							'<td style="width:50%;text-align:right">',
								($_SESSION['id']!==false?
									'<b>'.$user_info['name'].'</b> (<a href="/account/logout">Log Out</a>)':
									'(<a href="/account/login">Log In</a>|<a href="/account/register">Register</a>)'),
							'</td>',
						'</tr>',
					'</table>',
					'<a href="/"><img src="/media/header.jpg" alt="Home"></a>',
					($_SESSION['id']!==false?
						'<iframe src="/omnomirc/index.php" width="100%" height="280" frameborder="0" name="OmnomIRC">Your browser does not support frames.</iframe>'
						:''),
					'<div style="text-align:left;" id="quickLinks">'.self::getQuickLinks($lang,$pathPartsParsed).'</div>',
					'<div id="content">'
			],'');
	}
	private static function getFooter(){
		global $queryNum;
		$loginScript = '';
		if(isset($_COOKIE['shouldlogin']) && $_COOKIE['shouldlogin']=='true' && $_SESSION['id']==false){
			$loginScript = implode([
				'<script type="text/javascript" src="/jsencrypt.min.js"></script>',
				'<script type="text/javascript">',
					'$.getJSON("/getKeys").done(function(keys){',
						'var encrypt = new JSEncrypt();',
						'encrypt.setPublicKey(atob(keys.hash.key));',
						'pwdenc = encrypt.encrypt(localStorage.getItem("longtimePwd"));',
						'$.post("/account/verifyLogin?ltpwdv",{',
							'pwd:pwdenc,',
							'id:keys.hash.id,',
							'fkey:keys.form.key,',
							'fid:keys.form.id,',
							'uid:localStorage.getItem("id")',
						'}).done(function(data){',
							'if(data.success){',
								'document.cookie="session-id="+escape(data.sessid)+"; path=/";',
								'location.reload();',
							'}else{',
								'document.cookie="shouldlogin=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT";',
								'localStorage.removeItem("longtimePwd");',
								'localStorage.removeItem("id");',
							'}',
						'})',
					'});',
				'</script>'
			],'');
		}
		return implode([
					'</div>',
					'<script type="text/javascript">',
						'$("article").css("min-height",$("nav>ul").height()+20);',
					'</script>',
					'<footer>',
						'Page generated succesfully with <span id="queryNum">'.$queryNum.'</span> queries. ©Sorunome 2011-'.date('Y',time()),
					'</footer>',
					'</div>',
					'<script type="text/javascript">',
						'function parseLinks(){',
							'$(\'a[href^="http://'.$_SERVER['HTTP_HOST'].'"],a[href^="/"]\').off("click").click(function(e){',
								'if(e.button==0){',
									'e.preventDefault();',
									'var href = this.href;',
									'if(href.indexOf("/account/logout")!=-1){',
										'window.location="/account/logout";'.
									'}else{',
										'$.getJSON(href+((href.indexOf("?")!=-1)?"&json":"?json")).done(function(page){',
											'$("article").html(page.content);',
											'$("title").html(page.title);',
											'$("#quickLinks").html(page.quickLinks);',
											'$("#queryNum").text(page.queries);',
											'history.pushState({},page.title,href);',
											'parseLinks();',
										'});',
									'}',
								'}',
							'});',
						'}',
						'parseLinks();',
					'</script>',
					$loginScript,
				'</body>',
			'</html>'],'');
	}
	private static function getNavInner($i=1,$path=''){
		global $lang;
		$s = '';
		if($i==1){
			$s .= '<li><a href="/">Home</a></li>';
		}
		$rows = sql::query("SELECT id,name,title_%s,settings FROM pages WHERE refId='%s' ORDER BY sorder ASC",[$lang,(string)$i]);
		$i = 0;
		while(isset($rows[$i]) && ($row = $rows[$i++])){
			if($row['id']!=NULL && ($i!=1 || (int)$row['id']!=1) && ($row['settings'] & 2)==0){
				$s .= "<li><a href='$path/".$row['name']."'>".$row['title_'.$lang].'</a>';
				$s .= self::getNavInner((int)$row['id'],$path.'/'.$row['name']);
				$s .= '</li>';
			}
		}
		if($s!=''){
			$s = '<ul>'.$s.'</ul>';
		}
		return $s;
	}
	private static function getNav(){
		global $lang;
		if(isset($_GET['updateNav'])){
			setVar('cache_nav_'.$lang,self::getNavInner());
		}
		$s = getVar('cache_nav_'.$lang);
		return '<nav>'.$s.'</nav>';
	}
	private static function getContent($s){
		global $bbParser;
		return $bbParser->parse($s);
	}
	public static function cacheHeaders($s){
		if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= filemtime($s)){
			header('HTTP/1.0 304 Not Modified');
			exit;
		}
		header('Last-Modified: Sun, 27 Oct 2013 15:25:47 GMT');
		header('Expires: '.date('D, d M Y H:i:s e',strtotime('30 days')));
		header('Cache-Control: max-age=2592000');
	}
	public static function getPage($title,$content,$lang,$pathPartsParsed,$settings = 1){
		global $queryNum;
		if(!isset($_GET['json'])){
			$pageHTML = '';
			if((int)$settings & 1){
				$pageHTML.=self::getHeader($title,$lang,$pathPartsParsed);
				$pageHTML.=self::getNav();
				$pageHTML.='<article>'.$content.'</article>';
				$pageHTML.=self::getFooter();
			}else{
				$pageHTML.='<article>'.$content.'</article>';
			}
		}else{
			header('Content-Type: text/json');
			$quicklinksHTML = self::getQuickLinks($lang,$pathPartsParsed);
			$pageHTML = json_encode([
				'title' => $title,
				'content' => $content,
				'quickLinks' => $quicklinksHTML,
				'queries' => $queryNum
			]);
		}
		return $pageHTML;
	}
	public static function getPageFromSQL($pathPartsParsed,$lang){
		global $bbParser;
		if(isset($pathPartsParsed[0]) && $pathPartsParsed[sizeof($pathPartsParsed)-1]=='index'){
			unset($pathPartsParsed[sizeof($pathPartsParsed)-1]);
		}
		if(!isset($pathPartsParsed[0])){
			$pathPartsParsed[0] = 'index';
		}
		$query = '';
		$getParams = 'ts,content_%s,title_%s,settings';
		for($i=sizeof($pathPartsParsed)-1;$i>=0;$i--){
			if(sizeof($pathPartsParsed)==1){
				$query = "SELECT $getParams FROM pages WHERE name='%s' AND refId='1'";
				break;
			}
			if($i==sizeof($pathPartsParsed)-1){
				$query = "SELECT id FROM pages WHERE name='%s' AND refId='1' LIMIT 1";
			}elseif($i!=0){
				$query = "SELECT id FROM pages WHERE refId=($query) AND name='%s'";
			}else{
				$query = "SELECT $getParams FROM pages WHERE refId=($query) AND name='%s'";
			}
		}
		$page = sql::query($query,array_merge([$lang,$lang],$pathPartsParsed),0);
		if($page['ts']!=NULL){
			echo self::getPage($page['title_'.$lang],$bbParser->parse($page['content_'.$lang]),$lang,$pathPartsParsed,$page['settings']);
		}else{
			echo self::getPage('404 not found',self::do404(),$lang,$pathPartsParsed);
		}
	}
}

if(strpos($_SERVER['REQUEST_URI'],'/?') && strpos($_SERVER['REQUEST_URI'],'/?')<strpos($_SERVER['REQUEST_URI'],'?')){
	$_GET['path'] .= 'index.php';
}
if($_SESSION['id']!==false){
	$user_info = sql::query("SELECT session,name,settings,power FROM users WHERE id='%s'",[$_SESSION['id']],0);
	if(Password::hash($_COOKIE['session-id'],$_SERVER['REMOTE_ADDR'])!=$user_info['session']){
		$_SESSION['id'] = false;
		unset($user_info);
	}
}
if(isset($_COOKIE['shouldlogin'])){
	setcookie('shouldlogin', $_COOKIE['shouldlogin'], time()+3600*24*30,'/');
}
$fullPath=str_replace(' ','+',$_GET['path']);
$pathParts = explode('/',$fullPath);
$pathPartsParsed = array();
$fileExtention = '';
foreach ($pathParts as $part) {
	if ($part) {
		if (strpos($part,".")!==false) {
			$fileExtention = substr($part,strrpos($part,".")+1);
			$part = substr($part,0,strrpos($part,"."));
		}
		$pathPartsParsed[] = str_replace(' ','+',$part);
		//$pathPartsParsedUpper[] = str_replace(' ','+',$part);
	}
}
//die($_SERVER['DOCUMENT_ROOT'].'/'.join('/',$pathPartsParsedUpper).'.'.$fileExtention);
switch($pathPartsParsed[0]){
	case 'getKeys':
		header('Content-type: text/json');
		echo security::makeKeysJSON();
		break;
	case 'account':
		if(isset($pathPartsParsed[1])){
			switch($pathPartsParsed[1]){
				case 'key':
					$user = sql::query("SELECT randkey,power FROM users WHERE id='%s'",[$_GET['i']],0);
					$pageHTML=getHeader('Account Key',$lang,$pathPartsParsed);
					$pageHTML.=getNav();
					if(isset($user['randkey']) && $user['randkey']==$_GET['k']){
						if(!$user['power']&1){
							$user['power'] = ((int)$user['power']|1);
							$pageHTML.='<article>Activated account, now you can <a href="/account/login">log in</a>.</article>';
						}
						sql::query("UPDATE users SET randkey='',power='%s' WHERE id='%s'",[$user['power'],$_GET['i']]);
					}else{
						$pageHTML.='<article><b>ERROR</b> invalid key</b></article>';
					}
					$pageHTML.=getFooter();
					echo $pageHTML;
					break;
				case 'logout':
					$_SESSION['id'] = false;
					session_destroy();
					echo page::getPage('Log Out',implode([
						'You are now logged out.',
						'<script type="text/javascript">',
							'document.cookie="shouldlogin=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT";',
							'document.cookie="session-id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT";',
							'localStorage.removeItem("longtimePwd");',
							'localStorage.removeItem("id");',
						'</script>'
					],''),$lang,$pathPartsParsed);
					break;
				case 'verifyLogin':
					header('Content-type: text/json');
					if(isset($_GET['ltpwdv'])){
						if(!isset($_POST['pwd']) || !isset($_POST['id']) || !isset($_POST['fid']) || !isset($_POST['fkey']) || !isset($_POST['uid']))
							die('{"success":false}');
						$user = sql::query("SELECT id,power,longtimepwd,longtimesalt FROM users WHERE id='%s'",[$_POST['uid']],0);
						if(!isset($user['id']))
							die('{"success":false}');
						if(security::checkPwdAndForm($_POST['id'],$_POST['pwd'],$user['longtimesalt'],$user['longtimepwd'],$_POST['fid'],$_POST['fkey']))
							die('{"success":false}');
						$_SESSION['id'] = $user['id'];
						$session_id = security::generateRandomString(50);
						sql::query("UPDATE users SET session='%s' WHERE id='%s'",[Password::hash($session_id,$_SERVER['REMOTE_ADDR']),$user['id']]);
						echo json_encode([
							'success' => true,
							'sessid' => $session_id
						]);
					}elseif(isset($_GET['ltpwd'])){
						if(!isset($_POST['pwd']) || !isset($_POST['id']) || !isset($_POST['fid']) || !isset($_POST['fkey']))
							die('{"success":false,"message":"ERROR: Missing required field"}');
						if($_SESSION['id']===false)
							die('{"success":false,"message":"ERROR: Not logged in"}');
						if(!security::validateForm($_POST['fid'],$_POST['fkey']))
							die('{"success":false,"message":"ERROR: Invalid session, please refresh the page"}');
						$pwd = security::getPwdFromKey($_POST['id'],$_POST['pwd']);
						if(strlen($pwd)<1)
							die('{"success":false,"message":"ERROR: No password entered!"}');
						$salt = Password::generateSalt(50);
						$hSalt = Password::hash($salt,$private_salt_key);
						$hash = Password::hash($pwd,$hSalt);
						sql::query("UPDATE users SET longtimepwd='%s',longtimesalt='%s' WHERE id='%s'",[$hash,$salt,$_SESSION['id']]);
						echo '{"success":true,"message":"Success","id":"'.$_SESSION['id'].'"}';
					}else{
						if(!isset($_POST['name']) || !isset($_POST['pwd']) || !isset($_POST['id']) || !isset($_POST['fkey']) || !isset($_POST['fid']))
							die('{"success":false,"message":"ERROR: Missing required field"}');
						$user = sql::query("SELECT id,power,passwd,salt FROM users WHERE LOWER(name)=LOWER('%s')",[$_POST['name']],0);
						if(!isset($user['id']))
							die('{"success":false,"message":"ERROR: User doesn\'t exist!"}');
						if(security::checkPwdAndForm($_POST['id'],$_POST['pwd'],$user['salt'],$user['passwd'],$_POST['fid'],$_POST['fkey']))
							die('{"success":false,"message":"ERROR logging in, please refresh the page and try again."}');
						$_SESSION['id'] = $user['id'];
						$session_id = security::generateRandomString(50);
						sql::query("UPDATE users SET session='%s' WHERE id='%s'",[Password::hash($session_id,$_SERVER['REMOTE_ADDR']),$user['id']]);
						echo json_encode([
							'success' => true,
							'message' => 'Success',
							'sessid' => $session_id,
							'id' => $user['id']
						]);
					}
					break;
				case 'verifyRegister':
					if(!isset($_POST['name']) || !isset($_POST['pwd']) || !isset($_POST['id']) || !isset($_POST['email']) || !isset($_POST['fkey'])
							|| !isset($_POST['fid']))
						die('ERROR: Missing required field');
					if(!filter_var($_POST['email'],FILTER_VALIDATE_EMAIL))
						die('ERROR: Not a valid email!');
					if(!preg_match("/^[0-9a-zA-Z ]+$/",$_POST['name']))
						die('ERROR: Not a valid username!');
					$user = sql::query("SELECT id FROM users WHERE LOWER(name)=LOWER('%s')",[$_POST['name']],0);
					if(isset($user['id']))
						die('ERROR: Duplicate username');
					$pwd = security::getPwdFromKey($_POST['id'],$_POST['pwd']);
					if(strlen($pwd)<1)
						die('ERROR: No password entered!');
					if(!security::validateForm($_POST['fid'],$_POST['fkey']))
						die('ERROR: Invalid session, please refresh the page');
					$activationKey = security::generateRandomString(50);
					$salt = Password::generateSalt(50);
					$hSalt = Password::hash($salt,$private_salt_key);
					$hash = Password::hash($pwd,$hSalt);
					sql::query("INSERT INTO users (name,passwd,salt,email,randkey,joindate) VALUES ('%s','%s','%s','%s','%s','%s')",
						[$_POST['name'],$hash,$salt,$_POST['email'],$activationKey,time()]);
					$id = sql::query("SELECT id FROM users WHERE name='%s'",[$_POST['name']],0);
					$mailMessage = implode([
						'Hey there '.$_POST['name'].',',
						'',
						'welcome to http://www.sorunome.de !',
						'We are glad to have you here.',
						'In order to activate your account please follow the link below:',
						'http://www.sorunome.de/account/key?i='.$id['id'].'&k='.$activationKey,
						'',
						'Cheers, Sorunome.de Bot'
						],"\n");
					if(!mail($_POST['email'],'Verify your www.sorunome.de account',$mailMessage,'From: Sorunome.de Bot <bot@sorunome.de>'))
						die('Error sending verification email');
					echo 'Sent verification email, please check your spam folder!';
					break;
				default:
					page::getPageFromSQL($pathPartsParsed,$lang);
					break;
			}
		}else{
			echo 'yay';
		}
		break;
	default:
		switch ($fileExtention) {
			case 'zip':
				if($file = file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Description: File Transfer');
					header('Content-Type: application/'.$fileExtention);
					header('Content-Disposition: attachment; filename="'.$pathPartsParsed[len($pathPartsParsed)].'"');
					header('Content-Transfer-Encoding: binary');
					header('Content-Length: '.filesize($_SERVER['DOCUMENT_ROOT'].$fullPath));
					ob_end_flush();
					echo $file;
				}else{
					echo page::getPage('404 not found',page::do404(),$lang,$pathPartsParsed);
				}
			case 'css':
			case 'js':
				page::cacheHeaders($_SERVER['DOCUMENT_ROOT'].$fullPath);
				if($file = file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Type: text/'.$fileExtention);
					echo $file;
				}else{
					echo page::getPage('404 not found',page::do404(),$lang,$pathPartsParsed);
				}
				break;
			case 'jpg':
			case 'JPG':
			case 'jpeg':
			case 'JPEG':
			case 'png':
				$imgNewWidth = -1;
				$imgNewHeight = -1;
				if (preg_match("/^([\d]+|\*)$/i",$pathPartsParsed[0]) && preg_match("/^([\d]+|\*)$/i",$pathPartsParsed[1])) {
					if ($pathPartsParsed[0]!='*') $imgNewWidth=$pathPartsParsed[0]*1;
					if ($pathPartsParsed[1]!='*') $imgNewHeight=$pathPartsParsed[1]*1;
					unset($pathPartsParsed[0]);
					unset($pathPartsParsed[1]);
				}
				$imgFileName = $_SERVER['DOCUMENT_ROOT'].'/'.join('/',$pathPartsParsed).'.'.$fileExtention;
				page::cacheHeaders($imgFileName);
				list($width,$height) = @getimagesize($imgFileName);
				if ($imgNewHeight == -1 && $imgNewWidth == -1) {
					$imgNewHeight = $height;
					$imgNewWidth = $width;
				} else if ($imgNewHeight == -1) {
					$imgNewHeight = ($height/$width)*$imgNewWidth;
				} else  if ($imgNewWidth == -1) {
					$imgNewWidth = ($width/$height)*$imgNewHeight;
				}
				if($imgNewHeight>$height)$imgNewHeight = $height;
				if($imgNewWidth>$width)$imgNewWidth = $width;
				switch ($fileExtention) {
					case 'jpg':
					case 'JPG':
					case 'jpeg':
					case 'JPEG':
						header('Content-Type: image/jpeg');
						ob_end_clean();
						$img = @imagecreatefromjpeg($imgFileName);
						if (!$img) {
							imagejpeg(getImageNotFound());
						} else {
							if($imgNewHeight==$height && $imgNewWidth==$width){
								echo file_get_contents($imgFileName);
							}else{
								$imgout = imagecreatetruecolor($imgNewWidth,$imgNewHeight);
								imagecopyresized($imgout,$img,0,0,0,0,$imgNewWidth,$imgNewHeight,$width,$height);
								imagejpeg($imgout);
							}
						}
						break;
					case 'png':
						header('Content-Type: image/png');
						ob_end_clean();
						$img = @imagecreatefrompng($imgFileName);
						if (!$img) {
							imagepng(getImageNotFound());
						} else {
							if($imgNewHeight==$height && $imgNewWidth==$width){
								echo file_get_contents($imgFileName);
							}else{
								$imgout = imagecreatetruecolor($imgNewWidth,$imgNewHeight);
								imagecopyresized($imgout,$img,0,0,0,0,$imgNewWidth,$imgNewHeight,$width,$height);
								imagecolortransparent($imgout,imagecolorallocate($imgout,0,0,0));
								imagepng($imgout);
							}
						}
						break;
				}
				break;
			case 'gif':
				page::cacheHeaders($_SERVER['DOCUMENT_ROOT'].$fullPath);
				if($file = file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Type: image/'.$fileExtention);
					echo $file;
				}else{
					echo page::getPage('404 not found',page::do404(),$lang,$pathPartsParsed);
				}
				break;
			case 'php':
				if($file = @file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					session_write_close();
					include($_SERVER['DOCUMENT_ROOT'].$fullPath);
				}else{
					page::getPageFromSQL($pathPartsParsed,$lang);
				}
				break;
			default:
				ob_end_clean();
				if($file = @file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Type: text/'.$fileExtention);
					echo $file;
				}else{
					page::getPageFromSQL($pathPartsParsed,$lang);
				}
				break;
		}
		break;
}
?>
