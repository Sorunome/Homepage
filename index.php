<?php
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
error_reporting(-1);
session_start();
if((!isset($_SESSION['checkedCookies']) || !$_SESSION['checkedCookies']) && !isset($_GET['overrideCookieCheck']) && (!isset($_COOKIE['haveCookies']) || !$_COOKIE['haveCookies'])){
	$_SESSION['haveCookies'] = true;
	$_SESSION['oldPath'] = $_GET['path'];
	unset($_GET['path']);
	$params = '';
	foreach($_GET as $k => $v){
		$params .= urlencode($k).'='.urlencode($v).'&';
	}
	$_SESSION['params'] = substr($params,0,-1);
	header('Location: '.$_SESSION['oldPath'].'?'.$params.'overrideCookieCheck');
	die();
}elseif(isset($_GET['overrideCookieCheck']) || isset($_GET['json'])){
	$_SESSION['checkedCookies'] = true;
	if(!isset($_SESSION['haveCookies']) || !$_SESSION['haveCookies']){
		$_SESSION['haveCookies'] = false;
	}elseif(!isset($_GET['json'])){
		header('Location:'.$_SESSION['oldPath'].'?'.$_SESSION['params']);
	}
}
setcookie('haveCookies',1,time()+3600*24*30*9001,'/');
if(!isset($_SESSION['id'])){
	$_SESSION['id']=false;
}
ob_start();
include_once('config.php');
$lang = 'en';
$queryNum = 0;
date_default_timezone_set('UTC');
/*
Settings:
1 - display normal page (header, footer etc)
2 - not be in nav
4 - enable comments
8 - enable guest comments

User
Power
1 - active
2 - omnomirc ops
4 - edit pages
8 - view analytics
16 - edit page structure
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
		$queryNum++;
		if($num===true){
			$mysqli->multi_query(vsprintf($query,$args));
			do{
				if($result = $mysqli->store_result()){
					$result->free();
				}
				if(!$mysqli->more_results()){
					break;
				}
			}while($mysqli->next_result());
			return NULL;
		}else{
			$result = $mysqli->query(vsprintf($query,$args));
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
			return $res;
		}
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
	public static function isLoggedIn(){
		return $_SESSION['id']!==false;
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
class Analytics{
	/*
	 * types:
	 * 0 - global_views_all
	 * 1 - global_views_only_content
	 * 2 - page_hit
	 * 3 - visits (session)
	 * 4 - ident string
	 * 5 - referer
	 * 6 - user
	 * 7 - global_views_all_no_bots
	 * 8 - global_views_only_content_no_bots
	 * 9 - page_hit_no_bots
	 * 10 - visits (session) no bots
	 * 
	 */
	private $query;
	private $otherPages;
	private $params;
	private function addNum($t,$s = ''){
		$this->query .= "
			INSERT INTO analytics (type,path)
				SELECT %d,'%s' FROM analytics WHERE NOT EXISTS (
					SELECT %d AS tmp FROM analytics WHERE
						(MONTH(ts) = MONTH(NOW()) AND YEAR(ts) = YEAR(NOW()) AND type=%d AND path='%s')
					) LIMIT 1;
			UPDATE analytics SET counter = counter + 1 WHERE (MONTH(ts) = MONTH(NOW()) AND YEAR(ts) = YEAR(NOW()) AND path='%s' AND type=%d);";
		$this->params = array_merge($this->params,[$t,$s,$t,$t,$s,$s,$t]);
	}
	private function runQuery(){
		sql::query($this->query,$this->params,true);
		$this->query = '';
		$this->params = [];
	}
	private function getData($t,$m,$y,$i = false){
		$query = sql::query('SELECT counter AS c,path FROM analytics WHERE (type=%d AND MONTH(ts) = %d AND YEAR(ts) = %d) ORDER BY counter DESC LIMIT 10',[(int)$t,(int)$m,(int)$y]);
		if($i===false){
			return $query;
		}
		return ($query[0][$i]?(int)$query[0][$i]:0);
	}
	public function getTable($t,$m,$y){
		$pages = $this->getData($t,$m,$y);
		switch($t){
			case 2:
				$msg = ['pages','Page'];
				break;
			case 4:
				$msg = ['agents','Agent'];
				break;
			case 5:
				$msg = ['referers','Referer'];
				break;
			case 6:
				$msg = ['users','User'];
				break;
			case 9:
				$msg = ['pages','Page'];
				break;
			case 11:
				$msg = ['agents','Agent'];
				break;
			default:
				return;
		}
		$html = '<b>Top 10 '.$msg[0].' this month:</b><br><table class="statstable"><tr><th>'.$msg[1].'</th><th>hits</th></tr>';
		for($i=0;$i<sizeof($pages);$i++){
			$html .= '<tr><td>'.htmlspecialchars($pages[$i]['path']).'</td><td>'.$pages[$i]['c'].'</td></tr>';
		}
		$html .= '</table><br>';
		return $html;
	}
	public function getAllTables($m,$y){
		return $this->getTable(9,$m,$y).$this->getTable(11,$m,$y).$this->getTable(5,$m,$y).$this->getTable(6,$m,$y);
	}
	public function getMonth($m,$y){
		$date = DateTime::createFromFormat('m Y',$m.' '.$y);
		return '<b><u>Analytics for '.$date->format('F Y').'</u></b><br><br>'.
				'Total Hits: '.$this->getData(7,$m,$y,'c').'/'.$this->getData(0,$m,$y,'c').'<br>'.
				'Total Pages: '.$this->getData(8,$m,$y,'c').'/'.$this->getData(1,$m,$y,'c').'<br>'.
				'Total Visits: '.$this->getData(10,$m,$y,'c').'/'.$this->getData(3,$m,$y,'c').'<br>'.
				'<br>'.$this->getAllTables($m,$y);
	}
	public function __construct(){
		global $user_info,$fileExtention;
		$this->query = '';
		$this->params = [];
		$this->otherPages = ['jpg','png','gif','zip','jpeg','js','css','ico','mp3','ogg','ttf'];
		$this->addNum(0);
		$isNoBot = (isset($_SERVER['HTTP_USER_AGENT']) && strpos(strtolower($_SERVER['HTTP_USER_AGENT']),'bot')===false && strpos(strtolower($_SERVER['HTTP_USER_AGENT']),'spider')===false && strpos(strtolower($_SERVER['HTTP_USER_AGENT']),'crawl')===false);
		if($isNoBot){
			$this->addNum(7);
		}
		if(!in_array(strtolower($fileExtention),$this->otherPages)){
			$this->addNum(1);
			$this->addNum(2,$_GET['path']);
			$isVisit = ((!isset($_SESSION['counted_visit']) || !$_SESSION['counted_visit']) && isset($_SESSION['haveCookies']) && $_SESSION['haveCookies']);
			if($isVisit){
				$this->addNum(3);
			}
			if($isNoBot){
				$this->addNum(8);
				$this->addNum(9,$_GET['path']);
				if($isVisit){
					$this->addNum(10);
				}
			}
			if(isset($_SERVER['HTTP_USER_AGENT'])){
				$this->addNum(4,$_SERVER['HTTP_USER_AGENT']);
				if($isNoBot){
					$this->addNum(11,$_SERVER['HTTP_USER_AGENT']);
				}
			}
			if(isset($_SERVER['HTTP_REFERER'])){
				$ana_uri = parse_url($_SERVER['HTTP_REFERER']);
				if($ana_uri['host']!=$_SERVER['HTTP_HOST']){
					$this->addNum(5,$ana_uri['host']);
				}
			}
			if(security::isLoggedIn()){
				$this->addNum(6,$user_info['name']);
			}
		}
		$this->runQuery();
	}
}
abstract class page{
	private static function getImageNotFound() {
		$img = imagecreatetruecolor(180,17);
		imagestring($img,7,0,0,"Couldn't find image.",imagecolorallocate($img, 255, 255, 255));
		return $img;
	}
	public static function do404() {
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
	private static function getHeader($title,$lang,$pathPartsParsed,$headStuff = '',$id=0){
		global $user_info;
		return '<!DOCTYPE html>'.
			'<html>'.
				'<head>'.
					"<title>$title</title>".
					$headStuff.
					'<link rel="stylesheet" type="text/css" href="/style.css">'.
					'<link rel="icon" type="image/png" href="/media/favicon.png">'.
					'<meta http-equiv="content-type" content="text/html; charset=UTF-8">'.
					'<script type="text/javascript" src="/jquery-2.0.3.min.js"></script>'.
					'<script type="text/javascript" src="/jsencrypt.min.js"></script>'.
					'<script type="text/javascript">'.
						'LOGGEDIN='.(security::isLoggedIn()?'true':'false').';'.
						'function reLogIn(){'.
							'$.getJSON("/getKeys").done(function(keys){'.
								'var encrypt = new JSEncrypt();'.
								'encrypt.setPublicKey(atob(keys.hash.key));'.
								'var pwdenc = encrypt.encrypt(localStorage.getItem("longtimePwd"));'.
								'$.post("/account/verifyLogin?ltpwdv",{'.
									'pwd:pwdenc,'.
									'id:keys.hash.id,'.
									'fkey:keys.form.key,'.
									'fid:keys.form.id,'.
									'uid:localStorage.getItem("id")'.
								'}).done(function(data){'.
									'if(data.success){'.
										'console.log(data);'.
										'document.cookie="session-id="+escape(data.sessid)+"; path=/";'.
										'if(LOGGEDIN){'.
											'getPageJSON(document.URL,false);'.
										'}else{'.
											'window.location.reload();'.
										'}'.
									'}else{'.
										'document.cookie="shouldlogin=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT";'.
										'localStorage.removeItem("longtimePwd");'.
										'localStorage.removeItem("id");'.
										'if(LOGGEDIN){'.
											'window.location.reload();'.
										'}'.
									'}'.
								'})'.
							'});'.
						'}'.
						'function getPageJSON(url,doHistory){'.
							'if(doHistory===undefined){'.
								'doHistory = true;'.
							'}'.
							'if(history.pushState){'.
								'$.getJSON(url+((url.indexOf("?")!=-1)?"&json":"?json")).done(function(page){'.
									'if(page.relogin){'.
										'reLogIn();'.
									'}'.
									'$("article").html(page.content);'.
									'$("title").html(page.title);'.
									'$("#quickLinks").html(page.quickLinks);'.
									'$("#permalink > a").attr("pageid",page.id);'.
									'$("#queryNum").text(page.queries);'.
									'if(doHistory){'.
										'history.pushState({},page.title,url);'.
									'}'.
									'parseLinks();'.
								'});'.
							'}else{'.
								'window.location=url;'.
							'}'.
						'}'.
						'if(history.pushState){'.
							'(function($){'.
								'var firstTime = true;'.
								'$(window).bind("popstate",function(e){'.
									'if(!firstTime){'.
										'getPageJSON(document.URL,false);'.
									'}else{'.
										'firstTime = false;'.
									'}'.
								'});'.
							'})(jQuery);'.
						'}'.
					'</script>'.
				'</head>'.
				'<body>'.
					'<div id="main">'.
					'<table style="margin:0;padding:0;border:none;width:100%;font-size:11px">'.
						'<tr>'.
							'<td style="width:50%;text-align:left"><a href="/rssfeed.php" target="_blank" quick="false"><img src="/20/*/media/rss.png" alt="RSS Feed"></a></td>'.
							'<td style="width:50%;text-align:right">'.
								(security::isLoggedIn()?
									'<b>'.$user_info['name'].'</b> ('.
										($user_info['power']&8?'<a href="/analytics">Analytics</a> | ':'').
										'<a quick="false" href="/account/logout">Log Out</a>)':
									'(<a href="/account/login">Log In</a> | <a href="/account/register">Register</a>)').
							'</td>'.
						'</tr>'.
					'</table>'.
					'<a href="/"><img src="/media/header.jpg" alt="Home"></a>'.
					(security::isLoggedIn()?
						'<iframe src="/omnomirc/index.php" width="100%" height="280" frameborder="0" name="OmnomIRC"></iframe>':'').
					'<div style="height:1em;">'.
						'<div style="float:left;" id="quickLinks">'.self::getQuickLinks($lang,$pathPartsParsed).'</div>'.
						'<div style="float:right;" id="permalink"><a pageid="'.(int)$id.'">Permalink</a><input type="text" style="display:none"></input></div>'.
						'<script type="text/javascript">'.
							'(function(){'.
								'$("#permalink > a").mouseover(function(e){'.
									'$("#permalink > input").val("http://'.$_SERVER['HTTP_HOST'].'?pageid="+$(this).attr("pageid").toString()).css("display","inline").focus().select();'.
									'$("#permalink > a").css("display","none");'.
								'}).click(function(e){'.
									'e.preventDefault();'.
								'});'.
								'$("#permalink > input").mouseout(function(e){'.
									'$("#permalink > input").css("display","none");'.
									'$("#permalink > a").css("display","inline");'.
								'}).click(function(e){'.
									'$(this).focus().select();'.
								'});'.
							'})();'.
						'</script>'.
					'</div>'.
					'<div id="content">';
	}
	private static function getFooter(){
		global $queryNum;
		return '</div>'.
					'<script type="text/javascript">'.
						'$("article").css("min-height",$("nav>ul").height()+20);'.
					'</script>'.
					'<footer>'.
						'Page generated succesfully with <span id="queryNum">'.$queryNum.'</span> queries. ©Sorunome 2011-'.date('Y',time()).
					'</footer>'.
					'</div>'.
					'<script type="text/javascript">'.
						'function parseLinks(){'.
							'$(\'a[href^="http://'.$_SERVER['HTTP_HOST'].'"],a[href^="/"]\').off("click").click(function(e){'.
								'if(e.button==0){'.
									'if(!($(this).attr("quick")=="false" || this.href.indexOf(".zip")!=-1)){'.
										'e.preventDefault();'.
										'getPageJSON(this.href);'.
									'}'.
								'}'.
							'});'.
						'}'.
						'parseLinks();'.
						(isset($_COOKIE['shouldlogin'])&&$_COOKIE['shouldlogin']=='true'&&!security::isLoggedIn()?'reLogIn();':'').
					'</script>'.
				'</body>'.
			'</html>';
	}
	public static function getNavInner($i=1,$path='',$admin=false){
		global $lang;
		$s = '';
		if($i==1){
			$s .= '<li><a href="/"'.($admin?' class="page" pid="'.$i.'"':'').'>Home</a></li>';
		}
		$rows = sql::query("SELECT id,name,title_%s,settings FROM pages WHERE refId='%s' ORDER BY sorder ASC",[$lang,(string)$i]);
		$i = 0;
		while(isset($rows[$i]) && ($row = $rows[$i++])){
			if($row['id']!=NULL && ($i!=1 || (int)$row['id']!=1) && ($row['settings'] & 2)==0){
				$s .= '<li><a href="'.$path.'/'.$row['name'].'"'.($admin?' class="page" pid="'.$row['id'].'"':'').'>'.$row['title_'.$lang].'</a>';
				$s .= self::getNavInner((int)$row['id'],$path.'/'.$row['name'],$admin);
				$s .= '</li>';
			}
		}
		if($s!=''){
			$s = '<ul>'.$s.'</ul>';
		}
		return $s;
	}
	private static function getNav(){
		global $lang,$user_info;
		if(isset($_GET['updateNav'])){
			setVar('cache_nav_'.$lang,self::getNavInner());
		}
		$s = getVar('cache_nav_'.$lang);
		return '<nav>'.$s.'</nav>'.(security::isLoggedIn() && $user_info['power']&16?'<script type="text/javascript">'.
				'$("nav > ul").append('.
					'$("<li>")'.
						'.append('.
							'$("<a>")'.
								'.attr("href","/edit/structure")'.
								'.text("Edit")'.
						')'.
				');'.
			'</script>':'');
	}
	public static function cacheHeaders($s){
		if(isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= filemtime($s)){
			header('HTTP/1.0 304 Not Modified');
			exit;
		}
		header('Last-Modified: Sun, 27 Oct 2013 15:25:47 GMT');
		header('Expires: '.date('D, d M Y H:i:s e',strtotime('30 days')));
		header('Cache-Control: max-age=2592000');
	}
	public static function getPage($title,$content,$lang,$pathPartsParsed,$settings = 1,$id = 0){
		global $queryNum;
		if(!isset($_GET['json'])){
			$pageHTML = '';
			if((int)$settings & 1){
				$pageHTML.=self::getHeader($title,$lang,$pathPartsParsed,'',$id);
				$pageHTML.=self::getNav();
				$pageHTML.='<article>'.$content.'</article>';
				$pageHTML.=self::getFooter();
			}else{
				$pageHTML = $content;
			}
		}else{
			header('Content-Type: text/json');
			$quicklinksHTML = self::getQuickLinks($lang,$pathPartsParsed);
			$pageHTML = json_encode([
				'title' => $title,
				'content' => $content,
				'quickLinks' => $quicklinksHTML,
				'queries' => $queryNum,
				'relogin' => isset($_COOKIE['shouldlogin'])&&$_COOKIE['shouldlogin']=='true'&&!security::isLoggedIn(),
				'id' => $id
			]);
		}
		return $pageHTML;
	}
	public static function commentHTML($comment,$canComment,$depth=0){
		global $bbParser;
		$timestamp = strtotime($comment['ts']);
		return '<div style="margin-left:'.$depth.'px" class="comment">'.
					'<b>'.htmlspecialchars($comment['poster']).'</b>'.
					($comment['userId']==-1?' <i>guest post</i>':'').
					' <span class="commentDate">('.date('l, F jS, Y',$timestamp).' at '.date('g:i:s A T',$timestamp).')</span>'.
					'<p>'.$bbParser->parse($comment['content'],explode(',',$comment['allowedTags'])).'</p>'.
					($canComment?'<a href="'.$comment['id'].'" class="reply">Reply</a>':'').
				'</div>';
	}
	private static function getComments($pid,$canComment,$refId = -1,$depth = 0){
		$res = sql::query("SELECT id,ts,userId,poster,content,allowedTags FROM comments WHERE pageId='%s' AND refId='%s' ORDER BY ts DESC",[$pid,$refId]);
		$temp = $res[0];
		if($temp['id']==NULL && $refId == -1){
			return 'no comments';
		}
		$html = '';
		foreach($res as $comment){
			if($comment['id']!==NULL){
				$html .= self::commentHTML($comment,$canComment,$depth);
				$html .= self::getComments($pid,$canComment,$comment['id'],$depth+10);
			}
		}
		return $html;
	}
	public static function getPathFromId($id){
		$pathParts = [];
		do{
			$res = sql::query("SELECT refId,name FROM pages WHERE id=%d",[(int)$id],0);
			$id = $res['refId'];
			$pathParts[] = $res['name'];
		}while($id!=1);
		return '/'.implode('/',array_reverse($pathParts));
	}
	public static function getPageFromSQL($pathPartsParsed,$lang){
		global $bbParser,$user_info;
		//var_dump($user_info);
		if(isset($pathPartsParsed[0]) && $pathPartsParsed[sizeof($pathPartsParsed)-1]=='index'){
			unset($pathPartsParsed[sizeof($pathPartsParsed)-1]);
		}
		if(!isset($pathPartsParsed[0])){
			$pathPartsParsed[0] = 'index';
		}
		$query = '';
		$getParams = 'ts,content_%s,title_%s,settings,id';
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
		if($page['id']==1){ // index
			$bbParser->addTag('news',function($type,$s,$attrs,$bbParser){
				$res = sql::query("SELECT `news_en`,`ts`,`id` FROM news ORDER BY ts DESC",[]);
				$returnHTML = '<table style="background-color:#5D7859;border:1px solid black;border-collapse:collapse;"><tr><th>Date</th><th>News</th></tr>';
				foreach($res as $r){
					$returnHTML .= '<tr id="news'.$r['id'].'"><td style="border:1px solid black;border-collapse:collapse;">'.date('jS F Y',strtotime($r['ts'])).'</td><td style="border:1px solid black;border-collapse:collapse;">'.$bbParser->parse($r['news_en']).'</td></tr>';
				}
				return $returnHTML.'</table>';
			},[],'Creates the news table');
		}
		if($page['ts']!=NULL){
			$html = $bbParser->parse($page['content_'.$lang],['*']);
			if(security::isLoggedIn() && $user_info['power']&4){
				$html .= '<script type="text/javascript">'.
							'$("article").prepend('.
									'$("<div>")'.
										'.css({"font-size":"12px","text-align":"right"})'.
										'.append('.
											'$("<a>")'.
												'.attr("quick","false")'.
												'.text("Edit")'.
												'.click(function(e){'.
													'e.preventDefault();'.
													'$.getJSON("/edit/getBB&p='.$page['id'].'")'.
														'.done(function(data){'.
															'if(data.success){'.
																'$("article")'.
																	'.empty()'.
																	'.append('.
																		'$("<textarea>")'.
																			'.css({"width":"100%","height":"500px"})'.
																			'.val(data.code)'.
																			'.keydown(function(e){'.
																				'if(e.keyCode==9){'.
																					'e.preventDefault();'.
																					'var start = this.selectionStart;'.
																					'$(this).val($(this).val().substring(0,start)+"\\t"+$(this).val().substring(this.selectionEnd));'.
																					'this.selectionStart = this.selectionEnd = start+1;'.
																				'}'.
																			'}),'.
																		'$("<div>")'.
																			'.css({"font-size":"12px","text-align":"center","margin-bottom":"10px"})'.
																			'.append('.
																				'$("<a>")'.
																					'.attr("quick","false")'.
																					'.text("Save")'.
																					'.click(function(e){'.
																						'e.preventDefault();'.
																						'$.post("/edit/savePage?p='.$page['id'].'",{"c":$("article textarea").val()})'.
																							'.done(function(data){'.
																								'data = eval(data);'.
																								'if(data.success){'.
																									'getPageJSON(document.URL,false);'.
																								'}'.
																							'});'.
																					'}),'.
																				'" | ",'.
																				'$("<a>")'.
																					'.attr("quick","false")'.
																					'.text("Cancle")'.
																					'.click(function(e){'.
																						'e.preventDefault();'.
																						'getPageJSON(document.URL,false);'.
																					'})'.
																			')'.
																	');'.
															'}'.
														'});'.
												'})'.
										')'.
								');'.
						'</script>';
			}
			if($page['settings'] & 4){
				$commentsHTML = self::getComments($page['id'],security::isLoggedIn() || $page['settings'] & 8);
				$html .= '<hr>'.
						'<h2>Comments</h2>'.
						(security::isLoggedIn() || $page['settings'] & 8?
							'<span id="topComment"></span>':
							'You need to <a href="/account/login">Log In</a> or <a href="/account/register">Register</a> to leave a comment!').
						'<br>'.
						$commentsHTML.
						'<script type="text/javascript">'.
							'(function($){'.
								'var getReplyForm = function(refId){'.
										'return $("<div>")'.
											'.append('.
												'$("<span>")'.
													'.css("font-size","18px")'.
													'.text("Reply:"),'.
												'"<br>",'.
												'$("<form>")'.
													'.append('.
														(!security::isLoggedIn() && $page['settings'] & 8?
															'"Name: ",$("<input>").attr({"type":"text","name":"name","maxlength":"50"}).val("Guest"),':'').
														'$("<textarea>")'.
															'.attr("maxlength","500")'.
															'.css({"width":"90%","height":"105px"}),'.
														'$("<input>")'.
															'.attr({"type":"text","name":"pageId"})'.
															'.css("display","none")'.
															'.val("'.$page['id'].'"),'.
														'$("<input>")'.
															'.attr({"type":"text","name":"refId"})'.
															'.css("display","none")'.
															'.val(refId),'.
														'"<br>",'.
														'$("<input>")'.
															'.attr("type","submit")'.
															'.val("Post")'.
													')'.
													'.submit(function(e){'.
														'e.preventDefault();'.
														'var form = this;'.
														'$.getJSON("/getKeys").done(function(keys){'.
															'$.post("/comment",{'.
																(!security::isLoggedIn() && $page['settings'] & 8?
																	'name:$(form).find(\'[name="name"]\').val(),':'').
																'comment:$(form).find("textarea").val(),'.
																'pageId:$(form).find(\'[name="pageId"]\').val(),'.
																'refId:$(form).find(\'[name="refId"]\').val(),'.
																'fkey:keys.form.key,'.
																'fid:keys.form.id'.
															'}).done(function(data){'.
																'$(form).parent().html(data);'.
																'$(".reply").off("click").click(function(e){e.preventDefault();$(this).parent().after(getReplyForm($(this).attr("href")));});'.
															'});'.
														'})'.
													'})'.
											')'.
									'};'.
								'try{$(".reply").click(function(e){e.preventDefault();$(this).parent().after(getReplyForm($(this).attr("href")));});'.
								'$("#topComment").append(getReplyForm(-1));}catch(e){}'.
							'})(jQuery)'.
						'</script>'.
						'<br>';
			}
			echo self::getPage($page['title_'.$lang],$html,$lang,$pathPartsParsed,$page['settings'],$page['id']);
		}else{
			echo self::getPage('404 not found',self::do404(),$lang,$pathPartsParsed);
		}
	}
}

if(strpos($_SERVER['REQUEST_URI'],'/?') && strpos($_SERVER['REQUEST_URI'],'/?')<strpos($_SERVER['REQUEST_URI'],'?')){
	$_GET['path'] .= 'index.php';
}
if(security::isLoggedIn()){ // grab user info
	$user_info = sql::query("SELECT session,name,settings,power,id FROM users WHERE id='%s'",[$_SESSION['id']],0);
	if(Password::hash($_COOKIE['session-id'],$_SERVER['REMOTE_ADDR'])!=$user_info['session'] && !(isset($_SESSION['overrideLoginCheck']) && $_SESSION['overrideLoginCheck'])){
		$_SESSION['id'] = false;
		unset($user_info);
	}elseif(Password::hash($_COOKIE['session-id'],$_SERVER['REMOTE_ADDR'])==$user_info['session'] && (isset($_SESSION['overrideLoginCheck']) && $_SESSION['overrideLoginCheck'])){
		$_SESSION['overrideLoginCheck'] = false;
	}
}
if(isset($_COOKIE['shouldlogin'])){ // extend log in cookie
	setcookie('shouldlogin', $_COOKIE['shouldlogin'], time()+3600*24*30,'/');
}
$fullPath=str_replace(' ','+',$_GET['path']);
$pathParts = explode('/',$fullPath);
$pathPartsParsed = array();
$fileExtention = '';
foreach($pathParts as $part) {
	if ($part) {
		if (strpos($part,".")!==false) {
			$fileExtention = substr($part,strrpos($part,".")+1);
			$part = substr($part,0,strrpos($part,"."));
		}
		$pathPartsParsed[] = str_replace(' ','+',$part);
	}
}
$analytics = new Analytics();
if(isset($_GET['pageid'])){ // direct page ID, http forward
	header('Location: '.page::getPathFromId((int)$_GET['pageid']));
	exit; // good bye
}
switch($pathPartsParsed[0]){
	case 'analytics':
		if(security::isLoggedIn() && $user_info['power']&8){
			if(isset($_GET['m']) && isset($_GET['y'])){
				$pageHTML = '<h2>Analytics</h2><p><a href="/analytics">Back</a></p>';
				$pageHTML .= $analytics->getMonth($_GET['m'],$_GET['y']);
			}else{
				$hits = sql::query('SELECT counter AS c,UNIX_TIMESTAMP(ts) AS time FROM analytics WHERE type=0 ORDER BY ts DESC');
				$files = sql::query('SELECT counter AS c FROM analytics WHERE type=1 ORDER BY ts DESC');
				$visits = sql::query('SELECT counter AS c FROM analytics WHERE type=3 ORDER BY ts DESC');
				$hitsnb = sql::query('SELECT counter AS c FROM analytics WHERE type=7 ORDER BY ts DESC');
				$filesnb = sql::query('SELECT counter AS c FROM analytics WHERE type=8 ORDER BY ts DESC');
				$visitsnb = sql::query('SELECT counter AS c FROM analytics WHERE type=10 ORDER BY ts DESC');
				$pageHTML = '<h2>Analytics</h2><table class="statstable"><tr><th>Month</th><th>Hits</th><th>Pages</th><th>Visits</th></tr>';
				for($i=0;$i<sizeof($hits);$i++){
					$pageHTML .= '<tr><td><a href="/analytics?m='.date('m',$hits[$i]['time']).'&y='.date('Y',$hits[$i]['time']).'">'.date('F Y',$hits[$i]['time']).'</a></td><td>'.
									(array_key_exists($i,$hitsnb)?$hitsnb[$i]['c']:0).'/'.(array_key_exists($i,$hits)?$hits[$i]['c']:0).'</td><td>'.
									(array_key_exists($i,$filesnb)?$filesnb[$i]['c']:0).'/'.(array_key_exists($i,$files)?$files[$i]['c']:0).'</td><td>'.
									(array_key_exists($i,$visitsnb)?$visitsnb[$i]['c']:0).'/'.(array_key_exists($i,$visits)?$visits[$i]['c']:0).'</td></tr>';
				}
				$pageHTML .= '</table>';
			}
			$pageHTML .= '<style type="text/css">'.
							'.statstable,.statstable tr,.statstable th,.statstable td{'.
								'border:1px solid black;'.
								'border-collapse:collapse;'.
							'}'.
						'</style>';
		}else{
			$pageHTML = '<b>ERROR</b>: permission denied';
		}
		echo page::getPage('Analytics',$pageHTML,$lang,$pathPartsParsed);
		break;
	case 'getKeys':
		header('Content-type: text/json');
		echo security::makeKeysJSON();
		break;
	case 'comment':
		if(!isset($_POST['refId']) || !isset($_POST['pageId']) || !isset($_POST['comment']) || !isset($_POST['fid']) || !isset($_POST['fkey']))
			die('Missing required field');
		if(!security::validateForm($_POST['fid'],$_POST['fkey']))
			die('ERROR: Invalid session, please refresh the page');
		$page = sql::query("SELECT settings FROM pages WHERE id='%s'",[(int)$_POST['pageId']],0);
		if(!security::isLoggedIn() && !($page['settings'] & 8))
			die('ERROR: You need to log in to post');
		if(!security::isLoggedIn()){
			if(strlen($_POST['name']) > 50)
				die('ERROR: too long name');
			if(!preg_match("/^[0-9a-zA-Z ]+$/",$_POST['name']))
				die('ERROR: Not a valid name!');
			$uid = -1;
			$name = $_POST['name'];
		}else{
			$uid = $_SESSION['id'];
			$name = $user_info['name'];
		}
		if(strlen($_POST['comment']) > 500)
			die('ERROR: Comment too long');
		$page = sql::query("SELECT settings FROM pages WHERE id='%s'",[(int)$_POST['pageId']],0);
		if(!$page['settings'] & 4)
			die('ERROR: You can\'t post comments on this page');
		sql::query("INSERT INTO comments (pageId,refId,userId,poster,content,allowedTags) VALUES ('%s','%s','%s','%s','%s','b,i,url')",
			[(int)$_POST['pageId'],(int)$_POST['refId'],$uid,$name,$_POST['comment']]);
		$id = sql::query("SELECT MAX(id) FROM comments",[],0);
		$comment = sql::query("SELECT id,ts,userId,poster,content,allowedTags FROM comments WHERE id='%s'",[$id['MAX(id)']],0);
		echo page::commentHTML($comment,true);
		break;
	case 'account':
		if(isset($pathPartsParsed[1])){
			switch($pathPartsParsed[1]){
				case 'key':
					$user = sql::query("SELECT randkey,power FROM users WHERE id='%s'",[$_GET['i']],0);
					$pageHTML = '';
					if(isset($user['randkey']) && $user['randkey']==$_GET['k']){
						if(!$user['power']&1){
							$user['power'] = ((int)$user['power']|1);
							$pageHTML='Activated account, now you can <a href="/account/login">log in</a>.';
						}
						sql::query("UPDATE users SET randkey='',power='%s' WHERE id='%s'",[$user['power'],$_GET['i']]);
					}else{
						$pageHTML='<b>ERROR</b> invalid key</b>';
					}
					echo page::getPage('Account Key',$pageHTML,$lang,$pathPartsParsed);
					break;
				case 'logout':
					$_SESSION['id'] = false;
					session_destroy();
					echo page::getPage('Log Out','You are now logged out.'.
						'<script type="text/javascript">'.
							'document.cookie="shouldlogin=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT";'.
							'document.cookie="session-id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT";'.
							'localStorage.removeItem("longtimePwd");'.
							'localStorage.removeItem("id");'.
						'</script>',$lang,$pathPartsParsed);
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
						if(!$user['power']&1)
							die('{"success":false}');
						$_SESSION['id'] = $user['id'];
						$_SESSION['overrideLoginCheck'] = true;
						$session_id = security::generateRandomString(50);
						sql::query("UPDATE users SET session='%s' WHERE id='%s'",[Password::hash($session_id,$_SERVER['REMOTE_ADDR']),$user['id']]);
						echo json_encode([
							'success' => true,
							'sessid' => $session_id
						]);
					}elseif(isset($_GET['ltpwd'])){
						if(!isset($_POST['pwd']) || !isset($_POST['id']) || !isset($_POST['fid']) || !isset($_POST['fkey']))
							die('{"success":false,"message":"ERROR: Missing required field"}');
						if(!security::isLoggedIn())
							die('{"success":false,"message":"ERROR: Not logged in"}');
						if(!security::validateForm($_POST['fid'],$_POST['fkey']))
							die('{"success":false,"message":"ERROR: Invalid session, please refresh the page"}');
						if(!$user_info['power']&1)
							die('{"success":false,"message":"ERROR: Account not activated!"}');
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
						if(!$user['power']&1)
							die('{"success":false,"message":"ERROR: Account not activated!"}');
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
	case 'edit':
		if(isset($pathPartsParsed[1])){
			switch($pathPartsParsed[1]){
				case 'getBB':
					header('Content-type: text/json');
					$page = sql::query("SELECT content_$lang FROM pages WHERE id='%s'",[$_GET['p']],0);
					if(security::isLoggedIn() && $user_info['power']&4){
						if($page['content_'.$lang]){
							echo json_encode([
								'success' => true,
								'code' => $page['content_'.$lang]
							]);
						}else{
							die('{"success":false,"code":"ERROR: page not found"}');
						}
					}else{
						die('{"success":false,"code":"ERROR: You may not edit pages"}');
					}
					break;
				case 'savePage':
					header('Content-type: text/json');
					if(security::isLoggedIn() && $user_info['power']&4){
						sql::query("UPDATE pages SET content_$lang='%s' WHERE id='%s'",[$_POST['c'],$_GET['p']]);
						echo('{"success":true,"message":"success"}');
					}else{
						die('{"success":false,"message":"ERROR: You may not edit pages"}');
					}
					break;
				case 'structure':
					if(isset($_GET['new'])){
						
					}else{
						if(security::isLoggedIn() && $user_info['power']&16){
							$pageHTML = '';
							$pageHTML .= page::getNavInner(1,'',true);
							$pageHTML .= '<script type="text/javascript">'.
									'$(".page")'.
										'.after('.
											'$("<div>")'.
												'.append('.
													'$("<a>")'.
														'.text("new")'.
														'.click(function(e){'.
															'e.preventDefault();'.
															''.
														'})'.
												')'.
										');'.
								'</script>';
							echo page::getPage('Edit Structure',$pageHTML,$lang,$pathPartsParsed);
						}else{
							echo page::getPage('Error','<b>Error:</b> Permission denied',$lang,$pathPartsParsed);
						}
					}
			}
		}else{
			echo 'nope';
		}
		break;
	default:
		switch($fileExtention) {
			case 'zip':
				if($file = file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Description: File Transfer');
					header('Content-Type: application/'.$fileExtention);
					header('Content-Disposition: attachment; filename="'.$pathPartsParsed[sizeof($pathPartsParsed)-1].'.'.$fileExtention.'"');
					header('Content-Transfer-Encoding: binary');
					header('Content-Length: '.filesize($_SERVER['DOCUMENT_ROOT'].$fullPath));
					readfile($_SERVER['DOCUMENT_ROOT'].$fullPath);
				}else{
					echo page::getPage('404 not found',page::do404(),$lang,$pathPartsParsed);
				}
				break;
			case 'mp3':
				page::cacheHeaders($_SERVER['DOCUMENT_ROOT'].$fullPath);
				if(file_exists($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Type: audio/mpeg');
					header('Content-length: '.filesize($fullPath));
					header('Content-Disposition: inline;filename="'.$pathPartsParsed[sizeof($pathPartsParsed)-1].'.'.$fileExtention.'"');
					readfile($_SERVER['DOCUMENT_ROOT'].$fullPath);
				}else{
					header("HTTP/1.0 404 Not Found");
				}
				break;
			case 'css':
			case 'js':
				page::cacheHeaders($_SERVER['DOCUMENT_ROOT'].$fullPath);
				if($file = @file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
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
				if($fullPath!='/index.php' && $file = @file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					session_write_close();
					include($_SERVER['DOCUMENT_ROOT'].$fullPath);
					break;
				}
				page::getPageFromSQL($pathPartsParsed,$lang);
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
