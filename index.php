<?php
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
error_reporting(-1);
session_start();
date_default_timezone_set('UTC');
$startTime = microtime(true);
include_once('scrypt.php');
include_once('vars.php');
include_once('sql.php');
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
/*
Settings:
1 - display normal page (header, footer etc)
2 - not be in nav
4 - enable comments
8 - enable guest comments
16 - redirect page (content is new page id)

User
Power
1 - active
2 - omnomirc ops
4 - edit pages
8 - view analytics
16 - edit page structure
32 - view reuben3
*/

class Security{
	private $checkedSessKey;
	public function __construct(){
		$this->checkedSessKey = false;
		$this->newestPwdType = 1;
	}
	private function clearOldKeys(){
		global $sql;
		$sql->query("DELETE FROM form_keys WHERE ts < (NOW() - INTERVAL 1 MINUTE)");
		$sql->query("DELETE FROM rsa_keys WHERE ts < (NOW() - INTERVAL 1 MINUTE)");
	}
	private function makeFormKey(){
		global $sql;
		$this->clearOldKeys();
		$s = $this->generateRandomString(50);
		$sql->query("INSERT INTO form_keys (fkey) VALUES ('%s')",[$s]);
		$id = $sql->query("SELECT MAX(id) FROM form_keys",[],0);
		return [$s,$id['MAX(id)']];
	}
	private function createKeys(){
		global $sql;
		$this->clearOldKeys();
		$res = openssl_pkey_new();
		openssl_pkey_export($res, $privKey);
		$pubKey = openssl_pkey_get_details($res);
		$pubKey = $pubKey['key'];
		$sql->query("INSERT INTO rsa_keys (privKey,pubKey) VALUES ('%s','%s')",[$privKey,$pubKey]);
		$id = $sql->query("SELECT MAX(id) FROM rsa_keys",[],0);
		return [$pubKey,$id['MAX(id)']];
	}
	public function hash($pwd,$salt,$type = -1){
		switch($type){
			case 0:
				return Password::hash($pwd,$salt);
			case 1:
			default:
				return hash_hmac('sha512',$pwd,$salt);
		}
	}
	public function generateRandomString($length = 10) {
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$randomString = '';
		for($i = 0;$i < $length;$i++) {
			$randomString .= $characters[rand(0, strlen($characters) - 1)];
		}
		return $randomString;
	}
	public function validateForm($id,$key){
		global $sql;
		$this->clearOldKeys();
		$key2 = $sql->query("SELECT fkey FROM form_keys WHERE id='%s'",[$id],0);
		$sql->query("DELETE FROM form_keys WHERE id='%s'",[$id]);
		if($key!=$key2['fkey']){
			return false;
		}
		return true;
	}
	public function getPwdFromKey($id,$pwd){
		global $sql;
		$this->clearOldKeys();
		$key = $sql->query("SELECT privKey FROM rsa_keys WHERE id='%s'",[$id],0);
		$sql->query("DELETE FROM rsa_keys WHERE id='%s'",[$id]);
		@openssl_private_decrypt(base64_decode($pwd),$end,@openssl_get_privatekey($key['privKey']));
		return $end;
	}
	public function makeKeysJSON(){
		$fk = $this->makeFormKey();
		$hk = $this->createKeys();
		return '{"form":{"id":"'.$fk[1].'","key":"'.$fk[0].'"},"hash":{"id":"'.$hk[1].'","key":"'.base64_encode($hk[0]).'"}}';
	}
	public function checkPwdAndForm($id,$pwd1,$salt,$hash,$id2,$pwd2,$passwdtype,$updateOld = false){
		global $vars,$sql;
		if(!$this->validateForm($id2,$pwd2)){
			return 1;
		}
		$pwd = $this->getPwdFromKey($id,$pwd1);
		$hSalt = $this->hash($salt,$vars->get('private_salt_key'),$passwdtype);
		if($this->hash($pwd,$hSalt,$passwdtype)!=$hash){
			return 2;
		}
		if($updateOld!==false && $passwdtype != $this->newestPwdType){
			// ALERT! Not the newest hash type! So let's re-hash the passwd
			$hSalt = $this->hash($salt,$vars->get('private_salt_key'));
			$hash = $this->hash($pwd,$hSalt);
			$sql->query("UPDATE `users` SET `passwd`='%s',`passwdtype`=%d WHERE `id`=%d",[$hash,(int)$this->newestPwdType,(int)$updateOld]);
		}
		return false;
	}
	public function isLoggedIn(){
		global $sql;
		if(!isset($_COOKIE['session-id']) || !isset($_COOKIE['PHPSESSID'])){
			return false;
		}
		if($this->checkedSessKey){
			return $_SESSION['id']!==false;
		}
		$res = $sql->query("SELECT session FROM users WHERE id=%d",[(int)$_SESSION['id']],0);
		if($this->hash($_COOKIE['session-id'],$_SERVER['REMOTE_ADDR'])!=$res['session'] && !(isset($_SESSION['overrideLoginCheck']) && $_SESSION['overrideLoginCheck'])){
			$_SESSION['id'] = false;
			unset($_COOKIE['session-id']);
			setcookie('session-id',null,-1);
			return false;
		}
		if($this->hash($_COOKIE['session-id'],$_SERVER['REMOTE_ADDR'])==$res['session'] && (isset($_SESSION['overrideLoginCheck']) && $_SESSION['overrideLoginCheck'])){
			$_SESSION['overrideLoginCheck'] = false;
		}
		$this->checkedSessKey = true;
		return $_SESSION['id']!==false;
	}
}
$security = new Security();


include_once('bbCodeParser.php');
include_once('bbCodeParserDefaultTags.php');
include_once('bbCodeParserCustomTags.php');
$otherPages = ['jpg','png','gif','zip','jpeg','js','css','ico','mp3','ogg','ttf','wav'];
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
			INSERT INTO `analytics` (`type`,`path`)
				SELECT %d,'%s' FROM `analytics` WHERE NOT EXISTS (
					SELECT %d AS tmp FROM `analytics` WHERE
						(MONTH(`ts`) = MONTH(NOW()) AND YEAR(`ts`) = YEAR(NOW()) AND `type`=%d AND `path`='%s')
					) LIMIT 1;
			UPDATE `analytics` SET `counter` = `counter` + 1 WHERE (MONTH(`ts`) = MONTH(NOW()) AND YEAR(`ts`) = YEAR(NOW()) AND `path`='%s' AND `type`=%d);";
		$this->params = array_merge($this->params,[$t,$s,$t,$t,$s,$s,$t]);
	}
	private function runQuery(){
		global $sql;
		$sql->query($this->query,$this->params,true,MYSQLI_ASYNC);
		$this->query = '';
		$this->params = [];
	}
	private function getData($t,$m,$y,$i = false){
		global $sql;
		$query = $sql->query('SELECT counter AS c,path FROM analytics WHERE (type=%d AND MONTH(ts) = %d AND YEAR(ts) = %d) ORDER BY counter DESC LIMIT 10',[(int)$t,(int)$m,(int)$y]);
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
	public function run(){
		global $user_info,$fileExtention,$security,$otherPages;
		$this->query = '';
		$this->params = [];
		$this->addNum(0);
		$isNoBot = (isset($_SERVER['HTTP_USER_AGENT']) && strpos(strtolower($_SERVER['HTTP_USER_AGENT']),'bot')===false && strpos(strtolower($_SERVER['HTTP_USER_AGENT']),'spider')===false && strpos(strtolower($_SERVER['HTTP_USER_AGENT']),'crawl')===false);
		if($isNoBot){
			$this->addNum(7);
		}
		if(!in_array(strtolower($fileExtention),$otherPages)){
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
			if($security->isLoggedIn()){
				$this->addNum(6,$user_info['name']);
			}
		}
		$this->runQuery();
	}
}
class Page{
	private function getImageNotFound() {
		$img = imagecreatetruecolor(180,17);
		imagestring($img,7,0,0,"Couldn't find image.",imagecolorallocate($img, 255, 255, 255));
		return $img;
	}
	private function getBasePath($pathPartsParsed){
		return 'http://'.$_SERVER['HTTP_HOST'].'/'.implode('/',$pathPartsParsed);
	}
	public function do404() {
		header('HTTP/1.0 404 Not Found');
		return 'Error 404: page not found<br>I just don\'t know what went wrong!';
	}
	private function getQuickLinks($lang,$pathPartsParsed){
		global $sql;
		$quickLinks = '';
		$temp = $pathPartsParsed;
		if(sizeof($temp) > 1 && strtolower($temp[sizeof($temp)-1])=='index'){
			array_pop($temp);
		}
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
			$p = $sql->query($query,array_merge([$lang],$temp),0);
			$name = $p['title_'.$lang];
			if(!$name && isset($link[sizeof($temp)])){
				$goodlink = explode('.',$link[sizeof($temp)]);
				$goodlink = explode('?',$goodlink[0]);
				$name = strtoupper(substr($goodlink[0],0,1)).substr($goodlink[0],1);
			}
			if($name!='' && $name!='Index')
				$quickLinks = '<a href="/'.join('/',$temp).'">'.$name.'</a> &gt; '.$quickLinks;
		}while(array_pop($temp) && count($temp)>0);
		return substr('<a href="/">Home</a> &gt; '.$quickLinks,0,-6);
	}
	private function getHeader($title,$lang,$pathPartsParsed,$headStuff = '',$id=0){
		global $user_info,$security;
		return '<!DOCTYPE html>'.
			'<html>'.
				'<head>'.
					"<title>$title</title>".
					$headStuff.
					'<link rel="stylesheet" type="text/css" href="/style.css">'.
					'<link rel="icon" type="image/png" href="/media/favicon.png">'.
					'<base href="'.$this->getBasePath($pathPartsParsed).'">'.
					'<meta http-equiv="content-type" content="text/html; charset=UTF-8">'.
					'<script type="text/javascript" src="/jquery-2.0.3.min.js"></script>'.
					'<script type="text/javascript" src="/homepage.js.php"></script>'.
					'<script type="text/javascript">'.
						'function getPageJSON(url,doHistory){'.
							'if(doHistory===undefined){'.
								'doHistory = true;'.
							'}'.
							'doHistory = true;'.
							'if(history.pushState){'.
								'homepage.get(url+((url.indexOf("?")!=-1)?"&json":"?json"),function(page){'.
									'if(!page.content){'.
										'window.location=url;'.
									'}else{'.
										'$("article").html(page.content);'.
										'$("title").html(page.title);'.
										'$("#quickLinks").html(page.quickLinks);'.
										'$("#permalink > a").attr("data-pageid",page.id);'.
										'$("#queryNum").text(page.queries);'.
										'$("#secondsCount").text(page.seconds);'.
										'$("base").attr("href",page.basePath);'.
										'if(doHistory){'.
											'history.pushState({},page.title,(page.url!=undefined?page.url:url));'.
										'}'.
										'parseLinks();'.
									'}'.
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
							'<td style="width:50%;text-align:left"><a href="/rssfeed.php" target="_blank" data-quick="false"><img src="/20/*/media/rss.png" alt="RSS Feed"></a></td>'.
							'<td style="width:50%;text-align:right">'.
								($security->isLoggedIn()?
									'<b>'.$user_info['name'].'</b> ('.
										($user_info['power']&8?'<a href="/analytics">Analytics</a> | ':'').
										'<a data-quick="false" href="/account/logout">Log Out</a>)':
									'(<a href="/account/login">Log In</a> | <a href="/account/register">Register</a>)').
							'</td>'.
						'</tr>'.
					'</table>'.
					'<a href="/"><img src="/media/header.jpg" alt="Home"></a>'.
					($security->isLoggedIn()?
						'<iframe src="http://www.omnimaga.org/omnomirc/?network=5" width="100%" height="280" frameborder="0" name="OmnomIRC"></iframe>':'').
					'<div style="height:1em;">'.
						'<div style="float:left;" id="quickLinks">'.$this->getQuickLinks($lang,$pathPartsParsed).'</div>'.
						'<div style="float:right;" id="permalink"><a data-pageid="'.(int)$id.'">Permalink</a><input type="text" style="display:none"></div>'.
						'<script type="text/javascript">'.
							'(function(){'.
								'$("#permalink > a").mouseover(function(e){'.
									'$("#permalink > input").val("http://'.$_SERVER['HTTP_HOST'].'/"+$(this).attr("data-pageid").toString()).css("display","inline").focus().select();'.
									'$("#permalink > a").css("display","none");'.
								'}).click(function(e){'.
									'e.preventDefault();'.
								'});'.
								'$("#permalink > input").mouseout(function(e){'.
									'$("#permalink > input").css("display","none");'.
									'$("#permalink > a").css("display","");'.
								'}).click(function(e){'.
									'$(this).focus().select();'.
								'});'.
							'})();'.
						'</script>'.
					'</div>'.
					'<div id="content">';
	}
	private function getAdScript(){ // this is triggered AFTER the getFooter scripts
		return '<script type="text/javascript">'.
				'function newAds(){'.
					'var prevHTML = $("#ads").html();'.
					'$("#ads").empty().append('.
						'$("<script>").attr({'.
							'async:"",'.
							'src:"//pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"'.
						'}),'.
						'$("<ins>").addClass("adsbygoogle").css({'.
							'display:"inline-block",'.
							'width:200,'.
							'height:600,'.
							'float:"left",'.
							'marginTop:$("nav>ul").height()+20,'.
							'marginRight:10'.
						'}).attr({'.
							'"data-ad-client":"ca-pub-9434029170873885",'.
							'"data-ad-slot":"3220009654"'.
						'}).html(prevHTML)'.
					');'.
					'(adsbygoogle = window.adsbygoogle || []).push({});'.
					'$("article").css("min-height",$("nav>ul").height()+20+600);'.
				'}'.
				'newAds();'.
			'</script>';
	}
	private function getFooter(){
		global $security,$sql,$startTime;
		return '</div>'.
					'<script type="text/javascript">'.
						'$("article").css("min-height",$("nav>ul").height()+20);'.
					'</script>'.
					'<footer>'.
						'Page generated succesfully with <span id="queryNum">'.$sql->getQueryNum().'</span> queries in <span id="secondsCount">'.(microtime(true)-$startTime).'</span> seconds. ©Sorunome 2011-'.date('Y',time()).
					'</footer>'.
					'</div>'.
					'<script type="text/javascript">'.
						'function parseLinks(){'.
							'$(\'a[href^="http://'.$_SERVER['HTTP_HOST'].'"],a:not([href*="://"])\').filter(\'[data-quick!="false"]\').filter(\'[href]\').filter(\'[target!="_blank"]\').off("click").click(function(e){'.
								'if(e.button==0){'.
									'if(!($(this).attr("data-quick")=="false" || this.href.indexOf(".zip")!=-1)){'.
										'e.preventDefault();'.
										'getPageJSON(this.href);'.
									'}'.
								'}'.
							'});'.
						'}'.
						'parseLinks();'.
					'</script>'.
					$this->getAdScript().
				'</body>'.
			'</html>';
	}
	private function createNavInner($i=1,$path=''){
		global $lang,$sql;
		$pages = [];
		$s = '';
		if($i==1){
			$pages[] = [
				'name' => 'Home',
				'href' => '/',
				'inner' => [],
				'settings' => 1,
				'id' => 1
			];
		}
		$rows = $sql->query("SELECT id,name,title_%s,settings FROM pages WHERE refId='%s' ORDER BY sorder ASC",[$lang,(string)$i]);
		foreach($rows as $row){
			if($row['id']!=NULL && ($i!=1 || (int)$row['id']!=1)){
				$pages[] = [
					'name' => $row['title_'.$lang],
					'href' => $path.'/'.$row['name'],
					'inner' => $this->createNavInner((int)$row['id'],$path.'/'.$row['name']),
					'settings' => $row['settings'],
					'id' => (int)$row['id']
				];
			}
		}
		return $pages;
	}
	public function createNav(){
		return [
			'name' => 'root',
			'href' => '/',
			'inner' => $this->createNavInner(),
			'settings' => 1,
			'id' => NULL
		];
	}
	private function createNavHTML($obj){
		$s = '';
		foreach($obj as $o){
			if(($o['settings'] & 2)==0){
				$s .= '<li><a href="'.$o['href'].'">'.$o['name'].'</a>'.$this->createNavHTML($o['inner']).'</li>';
			}
		}
		if($s!==''){
			$s = '<ul>'.$s.'</ul>';
		}
		return $s;
	}
	private function getNav(){
		global $lang,$user_info,$security,$vars;
		if(isset($_GET['updateNav'])){
			$vars->set('cache_nav_'.$lang,$this->createNav());
		}
		$navJSON = $vars->get('cache_nav_'.$lang);
		if($security->isLoggedIn()){
			if($user_info['power']&32){
				$navJSON['inner'][] = [
					'name' => 'Reuben3 Dev',
					'href' => '/reuben3',
					'inner' => [
						[
							'name' => 'Sprite editor',
							'href'=> '/reuben3/sprites',
							'inner' => [],
							'settings' => 0,
							'id' => NULL
						],
						[
							'name' => 'Tilemap editor',
							'href' => '/reuben3/tilemaps',
							'inner' => [],
							'settings' => 0,
							'id' => NULL
						],
						[
							'name' => 'Create',
							'href' => '/reuben3/create',
							'inner' => [],
							'settings' => 0,
							'id' => NULL
						]
					],
					'settings' => 0,
					'id' => NULL
				];
			}
			if($user_info['power']&16){
				$navJSON['inner'][] = [
					'name' => 'Edit',
					'href' => '/edit/structure',
					'inner' => [],
					'settings' => 1,
					'id' => NULL
				];
			}
		}
		return '<nav>'.$this->createNavHTML($navJSON['inner']).'</nav>';
	}
	public function cacheHeaders($s){
		if(isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= filemtime($s)){
			header('HTTP/1.0 304 Not Modified');
			exit;
		}
		header('Last-Modified: Sun, 27 Oct 2013 15:25:47 GMT');
		header('Expires: '.date('D, d M Y H:i:s e',strtotime('30 days')));
		header('Cache-Control: max-age=2592000');
	}
	public function getPage($title,$content,$lang,$pathPartsParsed,$settings = 1,$id = 0){
		global $sql,$security,$startTime;
		if(!isset($_GET['json'])){
			$pageHTML = '';
			if((int)$settings & 1){
				$pageHTML.=$this->getHeader($title,$lang,$pathPartsParsed,'',$id);
				$pageHTML.=$this->getNav();
				$pageHTML.='<div id="ads">Please support me by enabling ads!</div>';
				$pageHTML.='<article>'.$content.'</article>';
				$pageHTML.=$this->getFooter();
			}else{
				$pageHTML = $content;
			}
		}else{
			header('Content-Type: text/json');
			$basePath = $this->getBasePath($pathPartsParsed);
			$quicklinksHTML = $this->getQuickLinks($lang,$pathPartsParsed);
			if(strtolower($pathPartsParsed[sizeof($pathPartsParsed)-1])=='index'){
				array_pop($pathPartsParsed);
			}
			$pageHTML = json_encode([
				'title' => $title,
				'content' => $content,
				'quickLinks' => $quicklinksHTML,
				'queries' => $sql->getQueryNum(),
				'seconds' => (microtime(true)-$startTime),
				'relogin' => isset($_COOKIE['shouldlogin'])&&$_COOKIE['shouldlogin']=='true'&&!$security->isLoggedIn(),
				'id' => $id,
				'url' => '/'.implode('/',$pathPartsParsed),
				'basePath' => $basePath
			]);
		}
		return $pageHTML;
	}
	public function commentHTML($comment,$canComment,$depth=0){
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
	private function getComments($pid,$canComment,$refId = -1,$depth = 0){
		global $sql;
		$res = $sql->query("SELECT id,ts,userId,poster,content,allowedTags FROM comments WHERE pageId='%s' AND refId='%s' ORDER BY ts DESC",[$pid,$refId]);
		$temp = $res[0];
		if($temp['id']==NULL && $refId == -1){
			return 'no comments';
		}
		$html = '';
		foreach($res as $comment){
			if($comment['id']!==NULL){
				$html .= $this->commentHTML($comment,$canComment,$depth);
				$html .= $this->getComments($pid,$canComment,$comment['id'],$depth+10);
			}
		}
		return $html;
	}
	public function getCommentsHTML($pid,$canComment){
		return '<hr>'.
					'<h2>Comments</h2>'.
					($canComment?
						'<span id="topComment"></span>':
						'You need to <a href="/account/login">Log In</a> or <a href="/account/register">Register</a> to leave a comment!').
					'<br>'.
					($this->getComments($pid,$canComment)).
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
													(!$canComment?
														'"Name: ",$("<input>").attr({"type":"text","name":"name","maxlength":"50"}).val("Guest"),':'').
													'$("<textarea>")'.
														'.attr("maxlength","500")'.
														'.css({"width":"90%","height":"105px"}),'.
													'$("<input>")'.
														'.attr({"type":"text","name":"pageId"})'.
														'.css("display","none")'.
														'.val("'.$pid.'"),'.
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
													'homepage.get("/getKeys",function(keys){'.
														'homepage.post("/comment",{'.
															(!$canComment?
																'name:$(form).find(\'[name="name"]\').val(),':'').
															'comment:$(form).find("textarea").val(),'.
															'pageId:$(form).find(\'[name="pageId"]\').val(),'.
															'refId:$(form).find(\'[name="refId"]\').val(),'.
															'fkey:keys.form.key,'.
															'fid:keys.form.id'.
														'},function(data){'.
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
	public function getPathFromId($id){
		global $sql;
		$pathParts = [];
		do{
			$res = $sql->query("SELECT refId,name,id FROM pages WHERE id=%d",[(int)$id],0);
			if($res['id']!==NULL){
				$id = $res['refId'];
				$pathParts[] = $res['name'];
			}else{
				$pathParts = ['err404'];
				break;
			}
		}while($id!=1);
		return '/'.implode('/',array_reverse($pathParts));
	}
	public function getIdFromSQL($pathPartsParsed){
		global $sql;
		if(isset($pathPartsParsed[0]) && $pathPartsParsed[sizeof($pathPartsParsed)-1]=='index'){
			unset($pathPartsParsed[sizeof($pathPartsParsed)-1]);
		}
		if(!isset($pathPartsParsed[0])){
			$pathPartsParsed[0] = 'index';
		}
		$query = '';
		$getParams = 'ts';
		for($i=sizeof($pathPartsParsed)-1;$i>=0;$i--){
			if(sizeof($pathPartsParsed)==1){
				$query = "SELECT id FROM pages WHERE name='%s' AND refId='1'";
				break;
			}
			if($i==sizeof($pathPartsParsed)-1){
				$query = "SELECT id FROM pages WHERE name='%s' AND refId='1' LIMIT 1";
			}elseif($i!=0){
				$query = "SELECT id FROM pages WHERE refId=($query) AND name='%s'";
			}else{
				$query = "SELECT id FROM pages WHERE refId=($query) AND name='%s'";
			}
		}
		$p = $sql->query($query,$pathPartsParsed,0);
		return $p['id'];
	}
	public function getPageFromSQL($pathPartsParsed,$lang,$id){
		global $bbParser,$user_info,$sql,$security;
		$p = $sql->query("SELECT ts,content_%s,title_%s,settings,id FROM pages WHERE id=%d",[$lang,$lang,$id],0);
		if($p['id']==1){ // index
			$bbParser->addTag('news',function($type,$s,$attrs,$bbParser){
				global $sql;
				$res = $sql->query("SELECT `news_en`,`ts`,`id` FROM `news` ORDER BY `ts` DESC LIMIT 5",[]);
				$returnHTML = '<table style="background-color:#5D7859;border:1px solid black;border-collapse:collapse;width:100%;"><tr><th>Date</th><th>News</th></tr>';
				foreach($res as $r){
					$returnHTML .= '<tr id="news'.$r['id'].'"><td style="border:1px solid black;border-collapse:collapse;">'.date('jS F Y',strtotime($r['ts'])).'</td><td style="border:1px solid black;border-collapse:collapse;">'.$bbParser->parse($r['news_en']).'</td></tr>';
				}
				return $returnHTML.'</table>';
			},[],'Creates the news table');
		}
		if($id!==NULL && $p['id']!=NULL){
			if($p['settings'] & 16){ // page link thingy
				if(!isset($_GET['json'])){ // if user visits directly then redirect
					header('Location: /?pageid='.(int)$p['content_'.$lang]);
					die();
				}
				$pathPartsParsed = explode('/',$this->getPathFromId((int)$p['content_'.$lang]));
				$pathPartsParsed[] = 'index'; // for <base>
				array_shift($pathPartsParsed); // get rid of first empty element
				$p = $sql->query("SELECT $getParams FROM pages WHERE id=%d",[$lang,$lang,(int)$p['content_'.$lang]],0);
			}
			$html = $bbParser->parse($p['content_'.$lang],['*']);
			if($security->isLoggedIn() && $user_info['power']&4){
				$html .= '<script type="text/javascript">'.
							'$("article").prepend('.
									'$("<div>")'.
										'.css({"font-size":"12px","text-align":"right"})'.
										'.append('.
											'$("<a>")'.
												'.attr("data-quick","false")'.
												'.text("Edit")'.
												'.click(function(e){'.
													'e.preventDefault();'.
													'homepage.get("/edit/getBB&p='.$p['id'].'",'.
														'function(data){'.
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
																					'.attr("data-quick","false")'.
																					'.text("Save")'.
																					'.click(function(e){'.
																						'e.preventDefault();'.
																						'homepage.post("/edit/savePage?p='.$p['id'].'",{"c":$("article textarea").val()},'.
																							'function(data){'.
																								'data = eval(data);'.
																								'if(data.success){'.
																									'getPageJSON(document.URL,false);'.
																								'}'.
																							'});'.
																					'}),'.
																				'" | ",'.
																				'$("<a>")'.
																					'.attr("data-quick","false")'.
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
			if($p['settings'] & 4){
				$html .= $this->getCommentsHTML($p['id'],$security->isLoggedIn() || $p['settings'] & 8);
			}
			echo $this->getPage($p['title_'.$lang],$html,$lang,$pathPartsParsed,$p['settings'],$p['id']);
		}else{
			echo $this->getPage('404 not found',$this->do404(),$lang,$pathPartsParsed);
		}
	}
}
$page = new Page();
class Edit{
	private function createStructureHTML($obj,$refId = 1){
		global $lang;
		
		$s = '';
		$t = '';
		$btns = ' <a class="structureUp">^</a> <a class="structureDown">v</a>';
		
		$first1 = true;
		$first2 = true;
		foreach($obj as $o){
			if(($o['settings'] & 16)==1){
				$s .= '<li>'.$o['name'].'</li>';
			}else{
				if($o['settings']&2){
					if($first1){
						$moreBtns = '';
					}else{
						$moreBtns = ' <a class="structureRight">&gt;</a>';
					}
					if($refId!=1){
						$moreBtns = ' <a class="structureLeft">&lt;</a>'.$moreBtns;
					}
					
					if($o['id']!==NULL){
						$t .= '<li data-id="'.$o['id'].'"><a href="/edit/structure?pid='.$o['id'].'">'.$o['name'].'</a>'.$moreBtns.$this->createStructureHTML($o['inner'],$o['id']).'</li>';
					}else{
						$t .= '<li>'.$o['name'].'</a>'.$this->createStructureHTML($o['inner'],-1).'</li>';
					}
					$first1 = false;
				}else{
					if($first2){
						$moreBtns = '';
					}else{
						$moreBtns = ' <a class="structureRight">&gt;</a>';
					}
					if($refId!=1){
						$moreBtns = ' <a class="structureLeft">&lt;</a>'.$moreBtns;
					}
					
					if($o['id']!==NULL){
						$s .= '<li data-id="'.$o['id'].'"><a href="/edit/structure?pid='.$o['id'].'">'.$o['name'].'</a>'.$btns.$moreBtns.$this->createStructureHTML($o['inner'],$o['id']).'</li>';
					}else{
						$s .= '<li>'.$o['name'].'</a>'.$btns.$this->createStructureHTML($o['inner'],-1).'</li>';
					}
					$first2 = false;
				}
			}
		}
		if($refId!=-1){
			$j = '<li><a href="/edit/new?refid='.$refId.'"> + New</a></li>';
		}else{
			$j = '';
		}
		if($s!==''){
			$s .= $j;
			$s = '<ul>'.$s.'</ul>';
		}
		if($t!==''){
			$t .= $j;
			$s .= '<hr><ul>'.$t.'</ul>';
		}
		return $s;
	}
	public function saveOrder($data){
		global $security,$user_info,$page,$vars,$lang,$pathPartsParsed,$sql;
		header('Content-Type: text/json');
		if($security->isLoggedIn() && $user_info['power']&16){
			$json = json_decode($data,true);
			if($json!==NULL){
				foreach($json as $j){
					if(isset($j['id']) && isset($j['sorder'])){
						$sql->query("UPDATE `pages` SET `sorder`=%d WHERE `id`=%d",[(int)$j['sorder'],(int)$j['id']]);
					}
				}
				$vars->set('cache_nav_'.$lang,$page->createNav());
				echo '{"success":true}';
			}else{
				echo '{"success":false,"msg":"invalid data"}';
			}
		}else{
			echo '{"success":false,"msg":"permission denied"}';
		}
	}
	public function deleteStructure($id){
		global $security,$user_info,$sql,$vars,$page,$lang;
		header('Content-Type: text/json');
		if($security->isLoggedIn() && $user_info['power']&16){
			$p = $sql->query("SELECT `id` FROM `pages` WHERE `id`=%d",[(int)$id],0);
			if($p['id']!==NULL){
				$sql->query("DELETE FROM `pages` WHERE `id`=%d",[(int)$id]);
				$vars->set('cache_nav_'.$lang,$page->createNav());
				echo '{"success":true}';
			}else{
				echo '{"success":false,"msg":"page not found"}';
			}
		}else{
			echo '{"success":false,"msg":"permission denied"}';
		}
	}
	public function saveStructure($id,$data){
		global $security,$user_info,$sql,$vars,$page,$lang;
		header('Content-Type: text/json');
		if($security->isLoggedIn() && $user_info['power']&16){
			if(isset($data['name']) && isset($data['title_en']) && isset($data['settings'])){
				$p = $sql->query("SELECT `id` FROM `pages` WHERE `id`=%d",[(int)$id],0);
				if($p['id']!==NULL){
					$sql->query("UPDATE `pages` SET `name`='%s',`title_en`='%s',`settings`=%d WHERE `id`=%d",[$data['name'],$data['title_en'],(int)$data['settings'],(int)$id]);
					$vars->set('cache_nav_'.$lang,$page->createNav());
					echo '{"success":true}';
				}else{
					echo '{"success":false,"msg":"page not found"}';
				}
			}else{
				echo '{"success":false,"msg":"missing required fields"}';
			}
		}else{
			echo '{"success":false,"msg":"permission denied"}';
		}
	}
	public function dispStructure(){
		global $security,$user_info,$page,$vars,$lang,$pathPartsParsed,$sql;
		if($security->isLoggedIn() && $user_info['power']&16){
			if(isset($_GET['pid'])){
				$p = $sql->query("SELECT `name`,`title_en`,`id`,`settings` FROM `pages` WHERE `id`=%d",[(int)$_GET['pid']],0);
				if($p['id']!==NULL){
					$pageHTML = '<h1>'.htmlspecialchars($p['name']).'</h1>'.
						'<form id="structureEditForm">'.
							'Name (url):<input type="text" name="name" value="'.htmlspecialchars($p['name']).'"><br>'.
							'Title (en):<input type="text" name="title_en" value="'.htmlspecialchars($p['title_en']).'"><br>'.
							'Settings:<br>'.
							'&nbsp;Display with header etc:<input type="checkbox" name="settings_1" '.($p['settings']&1?'checked="checked"':'').'><br>'.
							'&nbsp;Not be in nav:<input type="checkbox" name="settings_2" '.($p['settings']&2?'checked="checked"':'').'><br>'.
							'&nbsp;Enable comments:<input type="checkbox" name="settings_4" '.($p['settings']&4?'checked="checked"':'').'><br>'.
							'&nbsp;Enable guest comments:<input type="checkbox" name="settings_8" '.($p['settings']&8?'checked="checked"':'').'><br>'.
							'&nbsp;Redirect page:<input type="checkbox" name="settings_16" '.($p['settings']&16?'checked="checked"':'').'><br>'.
							'<input type="submit" value="save">'.
						'</form>'.
						'<button id="deleteStructure" style="float:right;">Delete</button>'.
						'<script type="text/javascript">'.
							'(function(){'.
								'$("#structureEditForm").submit(function(e){'.
									'e.preventDefault();'.
									'var sendSettings = {};'.
									'sendSettings.name = this.name.value;'.
									'sendSettings.title_en = this.title_en.value;'.
									'sendSettings.settings = (this.settings_1.checked?1:0)'.
												'+(this.settings_2.checked?2:0)'.
												'+(this.settings_4.checked?4:0)'.
												'+(this.settings_8.checked?8:0)'.
												'+(this.settings_16.checked?16:0);'.
									'homepage.post("/edit/savestructure?id='.$p['id'].'",sendSettings,function(data){'.
										'if(data.success){'.
											'alert("Saved!");'.
										'}else{'.
											'alert("Error Saving: "+(data.msg!==undefined?data.msg:""));'.
										'}'.
									'});'.
								'});'.
								'$("#deleteStructure").click(function(e){'.
									'e.preventDefault();'.
									'if(confirm("Are you sure you want to delete this page?")){'.
										'homepage.get("/edit/deletestructure?id='.$p['id'].'",function(data){'.
											'if(data.success){'.
												'alert("Page deleted!");'.
												'getPageJSON("/edit/structure");'.
											'}else{'.
												'alert("Error Deleting: "+(data.msg!==undefined?data.msg:""));'.
											'}'.
										'});'.
									'}'.
								'});'.
							'})();'.
						'</script>';
				}else{
					$pageHTML = '<b>ERROR</b>: page not found';
				}
				$pageHTML .= '<br><br><a href="/edit/structure">&lt;&lt; Back</a>';
				echo $page->getPage('Edit Page Structure',$pageHTML,$lang,$pathPartsParsed);
			}else{
				$navJSON = $vars->get('cache_nav_'.$lang);
				$pageHTML = '<div>'.$this->createStructureHTML($navJSON['inner']).'</div>'.
					'<script type="text/javascript">'.
						'(function(){'.
							'var saveStructure = function($elem){'.
									'var id;'.
									'if($elem[0].tagName == "article"){'.
										'id = 0;'.
									'}else{'.
										'id = parseInt($elem.attr("data-id"));'.
									'}'.
									'var i = 0,'.
										'ids = $.map($elem.find("ul:first").children(),function(v){'.
											'return {id:parseInt($(v).attr("data-id"),10),sorder:++i};'.
										'});'.
									'homepage.post("/edit/saveorder",{data:JSON.stringify(ids)},function(data){'.
										'if(!data.success){'.
											'alert("Error Saving: "+(data.msg!==undefined?data.msg:""));'.
										'}'.
									'});'.
								'};'.
							'$(".structureUp").click(function(e){'.
								'e.preventDefault();'.
								'$elem = $(this).parent();'.
								'if($elem.prev().length != 0){'.
									'$elem.prev().before($elem);'.
									'saveStructure($elem.parent().parent());'.
								'}'.
							'});'.
							'$(".structureDown").click(function(e){'.
								'e.preventDefault();'.
								'$elem = $(this).parent();'.
								'if($elem.next().length != 0){'.
									'$elem.next().after($elem);'.
									'saveStructure($elem.parent().parent());'.
								'}'.
							'});'.
							
						'})();'.
					'</script>';
				echo $page->getPage('Edit Structure',$pageHTML,$lang,$pathPartsParsed);
			}
		}else{
			echo $page->getPage('Error','<b>Error:</b> Permission denied',$lang,$pathPartsParsed);
		}
	}
	public function newPage($refid){
		global $security,$user_info,$page,$vars,$lang,$pathPartsParsed,$sql;
		if($security->isLoggedIn() && $user_info['power']&16){
			$r = $sql->query("SELECT `id` FROM `pages` WHERE `id`=%d",[$refid],0);
			if($r!==NULL){
				$newSorder = $sql->query("SELECT MAX(`sorder`)+1 as `n` FROM `pages` WHERE `refId`=%d",[$refid],0);
				$sql->query("INSERT INTO `pages` (`refId`,`sorder`) VALUES (%d,%d)",[$refid,$newSorder['n']]);
				echo $page->getPage('Nope','<script type="text/javascript">getPageJSON("/edit/structure?pid='.($sql->insertId()).'");</script>Redirecting...',$lang,$pathPartsParsed);
			}else{
				echo $page->getPage('Error','<b>Error:</b> refid not found',$lang,$pathPartsParsed);
			}
		}else{
			echo $page->getPage('Error','<b>Error:</b> Permission denied',$lang,$pathPartsParsed);
		}
	}
}
$edit = new Edit();

if(strpos($_SERVER['REQUEST_URI'],'/?') && strpos($_SERVER['REQUEST_URI'],'/?')<strpos($_SERVER['REQUEST_URI'],'?')){
	$_GET['path'] .= 'index.php';
}

$fullPath=str_replace(' ','+',$_GET['path']);
$pathParts = explode('/',$fullPath);
$pathPartsParsed = array();
$fileExtention = '';
foreach($pathParts as $part) {
	if ($part) {
		if (strpos($part,'.')!==false) {
			$fileExtention = substr($part,strrpos($part,".")+1);
			$part = substr($part,0,strrpos($part,"."));
		}
		$pathPartsParsed[] = str_replace(' ','+',$part);
	}
}

if($security->isLoggedIn()){ // grab user info
	$user_info = $sql->query("SELECT session,name,settings,power,id FROM users WHERE id=%d",[(int)$_SESSION['id']],0);
}elseif(!isset($_GET['norelog']) && isset($_COOKIE['shouldlogin'])&&$_COOKIE['shouldlogin']=='true'&&!$security->isLoggedIn()){
	if(isset($_GET['hps'])){
		header('Content-Type: text/json');
		echo json_encode([
			'relogin' => true
		]);
		exit;
	}elseif(!in_array(strtolower($fileExtention),$otherPages)){
		echo '<!DOCTYPE html>'.
			'<html>'.
				'<head>'.
					'<meta http-equiv="content-type" content="text/html; charset=UTF-8">'.
					'<script type="text/javascript" src="/jquery-2.0.3.min.js?norelog"></script>'.
					'<script type="text/javascript" src="/homepage.js.php?norelog"></script>'.
					'<script type="text/javascript">homepage.relog();</script>'.
				'</head>'.
				'<body>'.
					'Logging in...'.
				'</body>'.
			'</html>';
		exit;
	}
}


if(isset($_COOKIE['shouldlogin'])){ // extend log in cookie
	setcookie('shouldlogin', $_COOKIE['shouldlogin'], time()+3600*24*30,'/');
}


if(isset($_GET['pageid'])){ // direct page ID, http forward
	header('Location: '.$page->getPathFromId((int)$_GET['pageid']));
	exit; // good bye
}
if(sizeof($pathPartsParsed) == 1 && preg_match('/^[0-9]+$/',$pathPartsParsed[0])){
	header('Location: '.$page->getPathFromId((int)$pathPartsParsed[0]));
	exit; // good bye
}
if(sizeof($pathPartsParsed) == 0){
	$pathPartsParsed = ['index'];
}
$analytics = new Analytics(); //sloooooow
$analytics->run();
ob_end_clean();
switch($pathPartsParsed[0]){
	case 'analytics':
		if($security->isLoggedIn() && $user_info['power']&8){
			if(isset($_GET['m']) && isset($_GET['y'])){
				$pageHTML = '<h2>Analytics</h2><p><a href="/analytics">Back</a></p>';
				$pageHTML .= $analytics->getMonth($_GET['m'],$_GET['y']);
			}else{
				$hits = $sql->query('SELECT counter AS c,UNIX_TIMESTAMP(ts) AS time FROM analytics WHERE type=0 ORDER BY ts DESC');
				$files = $sql->query('SELECT counter AS c FROM analytics WHERE type=1 ORDER BY ts DESC');
				$visits = $sql->query('SELECT counter AS c FROM analytics WHERE type=3 ORDER BY ts DESC');
				$hitsnb = $sql->query('SELECT counter AS c FROM analytics WHERE type=7 ORDER BY ts DESC');
				$filesnb = $sql->query('SELECT counter AS c FROM analytics WHERE type=8 ORDER BY ts DESC');
				$visitsnb = $sql->query('SELECT counter AS c FROM analytics WHERE type=10 ORDER BY ts DESC');
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
		echo $page->getPage('Analytics',$pageHTML,$lang,$pathPartsParsed);
		break;
	case 'getKeys':
		header('Content-type: text/json');
		echo $security->makeKeysJSON();
		break;
	case 'comment':
		if(!isset($_POST['refId']) || !isset($_POST['pageId']) || !isset($_POST['comment']) || !isset($_POST['fid']) || !isset($_POST['fkey']))
			die('Missing required field');
		if(!$security->validateForm($_POST['fid'],$_POST['fkey']))
			die('ERROR: Invalid session, please refresh the page');
		$p = $sql->query("SELECT settings FROM pages WHERE id='%s'",[(int)$_POST['pageId']],0);
		if(!$security->isLoggedIn() && !($p['settings'] & 8))
			die('ERROR: You need to log in to post');
		if(!$security->isLoggedIn()){
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
		$p = $sql->query("SELECT settings FROM pages WHERE id='%s'",[(int)$_POST['pageId']],0);
		if(!$p['settings'] & 4)
			die('ERROR: You can\'t post comments on this page');
		$sql->query("INSERT INTO comments (pageId,refId,userId,poster,content,allowedTags) VALUES ('%s','%s','%s','%s','%s','b,i,url,nobbc')",
			[(int)$_POST['pageId'],(int)$_POST['refId'],$uid,$name,$_POST['comment']]);
		$id = $sql->query("SELECT MAX(id) FROM comments",[],0);
		$comment = $sql->query("SELECT id,ts,userId,poster,content,allowedTags FROM comments WHERE id='%s'",[$id['MAX(id)']],0);
		echo $page->commentHTML($comment,true);
		break;
	case 'account':
		if(isset($pathPartsParsed[1])){
			switch($pathPartsParsed[1]){
				case 'key':
					$user = $sql->query("SELECT randkey,power FROM users WHERE id='%s'",[$_GET['i']],0);
					$pageHTML = '';
					if(isset($user['randkey']) && $user['randkey']==$_GET['k']){
						if(!$user['power']&1){
							$user['power'] = ((int)$user['power']|1);
							$pageHTML='Activated account, now you can <a href="/account/login">log in</a>.';
						}
						$sql->query("UPDATE users SET randkey='',power='%s' WHERE id='%s'",[$user['power'],$_GET['i']]);
					}else{
						$pageHTML='<b>ERROR</b> invalid key</b>';
					}
					echo $page->getPage('Account Key',$pageHTML,$lang,$pathPartsParsed);
					break;
				case 'logout':
					setcookie('shouldlogin','',time()-10,'/');
					$_SESSION['id'] = false;
					session_destroy();
					echo $page->getPage('Log Out','You are now logged out.'.
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
						$user = $sql->query("SELECT id,power,longtimepwd,longtimesalt FROM users WHERE id='%s'",[$_POST['uid']],0);
						if(!isset($user['id']))
							die('{"success":false}');
						if($security->checkPwdAndForm($_POST['id'],$_POST['pwd'],$user['longtimesalt'],$user['longtimepwd'],$_POST['fid'],$_POST['fkey'],-1)) // for checking the longtimepwd we force the user to have the newest hash
							die('{"success":false}');
						if(!$user['power']&1)
							die('{"success":false}');
						$_SESSION['id'] = $user['id'];
						$_SESSION['overrideLoginCheck'] = true;
						$session_id = $security->generateRandomString(50);
						$sql->query("UPDATE users SET session='%s' WHERE id='%s'",[$security->hash($session_id,$_SERVER['REMOTE_ADDR']),$user['id']]);
						echo json_encode([
							'success' => true,
							'sessid' => $session_id
						]);
					}elseif(isset($_GET['ltpwd'])){
						if(!isset($_POST['pwd']) || !isset($_POST['id']) || !isset($_POST['fid']) || !isset($_POST['fkey']))
							die('{"success":false,"message":"ERROR: Missing required field"}');
						if(!$security->isLoggedIn())
							die('{"success":false,"message":"ERROR: Not logged in"}');
						if(!$security->validateForm($_POST['fid'],$_POST['fkey']))
							die('{"success":false,"message":"ERROR: Invalid session, please refresh the page"}');
						if(!$user_info['power']&1)
							die('{"success":false,"message":"ERROR: Account not activated!"}');
						$pwd = $security->getPwdFromKey($_POST['id'],$_POST['pwd']);
						if(strlen($pwd)<1)
							die('{"success":false,"message":"ERROR: No password entered!"}');
						$salt = Password::generateSalt(50);
						$hSalt = $security->hash($salt,$vars->get('private_salt_key')); // as this is the long time pwd we just use the most recent hash method. User will get logged out if we add a new one
						$hash = $security->hash($pwd,$hSalt);
						$sql->query("UPDATE users SET longtimepwd='%s',longtimesalt='%s' WHERE id='%s'",[$hash,$salt,$_SESSION['id']]);
						echo '{"success":true,"message":"Success","id":"'.$_SESSION['id'].'"}';
					}else{
						if(!isset($_POST['name']) || !isset($_POST['pwd']) || !isset($_POST['id']) || !isset($_POST['fkey']) || !isset($_POST['fid']))
							die('{"success":false,"message":"ERROR: Missing required field"}');
						$user = $sql->query("SELECT id,power,passwd,salt,passwdtype FROM users WHERE LOWER(name)=LOWER('%s')",[$_POST['name']],0);
						if(!isset($user['id']))
							die('{"success":false,"message":"ERROR: User doesn\'t exist!"}');
						if(!$user['power']&1)
							die('{"success":false,"message":"ERROR: Account not activated!"}');
						if($errno = $security->checkPwdAndForm($_POST['id'],$_POST['pwd'],$user['salt'],$user['passwd'],$_POST['fid'],$_POST['fkey'],(int)$user['passwdtype'],(int)$user['id'])){
							switch($errno){
								case 1:
									die('{"success":false,"message":"ERROR logging in, please refresh the page and try again."}');
								case 2:
									die('{"success":false,"message":"ERROR wrong password."}');
								default:
									die('{"success":false,"message":"ERROR logging in, unkown error.  Please report this! Errno:'.$errno.'"}');
							}
						}
						$_SESSION['id'] = $user['id'];
						$session_id = $security->generateRandomString(50);
						$sql->query("UPDATE users SET session='%s' WHERE id='%s'",[$security->hash($session_id,$_SERVER['REMOTE_ADDR']),$user['id']]);
						// we successfully logged in
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
					if(!preg_match("/^[0-9a-zA-Z]+[0-9a-zA-Z _]*[0-9a-zA-Z]+$/",$_POST['name']))
						die('ERROR: Not a valid username!');
					$user = $sql->query("SELECT id FROM users WHERE LOWER(name)=LOWER('%s')",[$_POST['name']],0);
					if(isset($user['id']))
						die('ERROR: Duplicate username');
					$pwd = $security->getPwdFromKey($_POST['id'],$_POST['pwd']);
					if(strlen($pwd)<1)
						die('ERROR: No password entered!');
					if(!$security->validateForm($_POST['fid'],$_POST['fkey']))
						die('ERROR: Invalid session, please refresh the page');
					$activationKey = $security->generateRandomString(50);
					$salt = Password::generateSalt(50);
					$hSalt = $security->hash($salt,$vars->get('private_salt_key')); // we register and thus use the newest hash method
					$hash = $security->hash($pwd,$hSalt);
					$sql->query("INSERT INTO users (name,passwd,salt,email,randkey,joindate,passwdtype) VALUES ('%s','%s','%s','%s','%s','%s',%d)",
						[$_POST['name'],$hash,$salt,$_POST['email'],$activationKey,time(),(int)$security->newestPwdType]);
					$id = $sql->query("SELECT id FROM users WHERE name='%s'",[$_POST['name']],0);
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
					$page->getPageFromSQL($pathPartsParsed,$lang,$page->getIdFromSQL($pathPartsParsed));
					break;
			}
		}else{
			echo $page->getPage('Nope','<script type="text/javascript">getPageJSON("/");</script>Redirecting...',$lang,$pathPartsParsed);
		}
		break;
	case 'edit':
		if(isset($pathPartsParsed[1])){
			switch($pathPartsParsed[1]){
				case 'getBB':
					header('Content-type: text/json');
					$p = $sql->query("SELECT content_$lang,id FROM pages WHERE id='%s'",[$_GET['p']],0);
					if($security->isLoggedIn() && $user_info['power']&4){
						if($p['id'] !== NULL){
							echo json_encode([
								'success' => true,
								'code' => $p['content_'.$lang]
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
					if($security->isLoggedIn() && $user_info['power']&4){
						$sql->query("UPDATE pages SET content_$lang='%s' WHERE id='%s'",[$_POST['c'],$_GET['p']]);
						echo('{"success":true,"message":"success"}');
					}else{
						die('{"success":false,"message":"ERROR: You may not edit pages"}');
					}
					break;
				case 'structure':
					$edit->dispStructure();
					break;
				case 'new':
					if(isset($_GET['refid']) && (int)$_GET['refid']==$_GET['refid']){
						$edit->newPage((int)$_GET['refid']);
					}else{
						echo $page->getPage('Error','<b>Error:</b> missing parameter',$lang,$pathPartsParsed);
					}
					break;
				case 'savestructure':
					$edit->saveStructure($_GET['id'],$_POST);
					break;
				case 'deletestructure':
					$edit->deleteStructure($_GET['id']);
					break;
				case 'saveorder':
					if(isset($_POST['data'])){
						$edit->saveOrder($_POST['data']);
					}else{
						header('Content-Type: text/json');
						echo '{"success":false,"msg":"missing required fields"}';
					}
					break;
			}
		}else{
			echo $page->getPage('Nope','<script type="text/javascript">getPageJSON("/");</script>Redirecting...',$lang,$pathPartsParsed);
		}
		break;
	default:
		switch(strtolower($fileExtention)){
			case 'zip':
				if($file = file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Description: File Transfer');
					header('Content-Type: application/'.$fileExtention);
					header('Content-Disposition: attachment; filename="'.$pathPartsParsed[sizeof($pathPartsParsed)-1].'.'.$fileExtention.'"');
					header('Content-Transfer-Encoding: binary');
					header('Content-Length: '.filesize($_SERVER['DOCUMENT_ROOT'].$fullPath));
					readfile($_SERVER['DOCUMENT_ROOT'].$fullPath);
				}else{
					echo $page->getPage('404 not found',$page->do404(),$lang,$pathPartsParsed);
				}
				break;
			case 'mp3':
				$page->cacheHeaders($_SERVER['DOCUMENT_ROOT'].$fullPath);
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
				$page->cacheHeaders($_SERVER['DOCUMENT_ROOT'].$fullPath);
				if($file = @file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Type: text/'.$fileExtention);
					echo $file;
				}else{
					echo $page->getPage('404 not found',$page->do404(),$lang,$pathPartsParsed);
				}
				break;
			case 'jpg':
			case 'jpeg':
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
				$page->cacheHeaders($imgFileName);
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
				switch(strtolower($fileExtention)){
					case 'jpg':
					case 'jpeg':
						header('Content-Type: image/jpeg');
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
				$page->cacheHeaders($_SERVER['DOCUMENT_ROOT'].$fullPath);
				if($file = file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Type: image/'.$fileExtention);
					echo $file;
				}else{
					echo $page->getPage('404 not found',$page->do404(),$lang,$pathPartsParsed);
				}
				break;
			case 'php':
				if($fullPath!='/index.php' && file_exists($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					session_write_close();
					include_once($_SERVER['DOCUMENT_ROOT'].$fullPath);
					break;
				}
				if(strtolower($pathPartsParsed[sizeof($pathPartsParsed)-1])!='index'){
					$pathPartsParsed[] = 'index';
				}
				$page->getPageFromSQL($pathPartsParsed,$lang,$page->getIdFromSQL($pathPartsParsed));
				break;
			default:
				$pid = $page->getIdFromSQL($pathPartsParsed);
				if($pid!==NULL){
					if(strtolower($pathPartsParsed[sizeof($pathPartsParsed)-1])!='index'){
						$pathPartsParsed[] = 'index';
					}
					$page->getPageFromSQL($pathPartsParsed,$lang,$pid);
				}elseif($fullPath!='/' && file_exists($_SERVER['DOCUMENT_ROOT'].$fullPath.'/index.php')){
					session_write_close();
					$pathPartsParsed[] = 'index';
					$fileExtention = 'php';
					include_once($_SERVER['DOCUMENT_ROOT'].$fullPath.'/index.php');
					break;
				}elseif($fullPath!='/index' && file_exists($_SERVER['DOCUMENT_ROOT'].$fullPath.'.php')){
					session_write_close();
					$fileExtention = 'php';
					include_once($_SERVER['DOCUMENT_ROOT'].$fullPath.'.php');
					break;
				}elseif($file = @file_get_contents($_SERVER['DOCUMENT_ROOT'].$fullPath)){
					header('Content-Type: text/'.$fileExtention);
					echo $file;
				}else{
					echo $page->getPage('404 not found',$page->do404(),$lang,$pathPartsParsed);
				}
				break;
		}
		break;
}
?>
