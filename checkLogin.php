<?php
$encriptKeyToUse = 'key created while config';
$oircUrl = 'link to omnomirc';
$network = 1;

date_default_timezone_set('UTC');
function base64_url_encode($input) {
	return strtr(base64_encode($input),'+/=','-_,');
}

function base64_url_decode($input){
	return base64_decode(strtr($input,'-_,','+/=')); 
}

ob_start();
if(!isset($_GET['op'])){
	if(isset($_GET['txt'])){
		header('Content-Type: text/plain');
	}elseif(!isset($_GET['textmode'])){
		header('Content-Type: text/javascript');
	}
	$nick = '';
	$signature = '';
	$uid = 0;
	if(isset($_GET['sid']) && isset($_GET['network']) && $_GET['network'] == $network){
		$ts = time();
		$key = htmlspecialchars(str_replace(';','%^%',$_GET['sid']));
		$keyParts = explode('|',$key);
		if(isset($keyParts[1]) && (int)$keyParts[1] < ($ts + 60) && (int)$keyParts[1] > ($ts - 60) && hash_hmac('sha512',(isset($_SERVER['HTTP_X_FORWARDED_FOR'])?$_SERVER['HTTP_X_FORWARDED_FOR']:$_SERVER['REMOTE_ADDR']),$encriptKeyToUse.$keyParts[1].$network) == $keyParts[0]
				&& $user_info['id']!==false && $user_info['power']&1){
			$nick = $user_info['name'];
			$signature = hash_hmac('sha512',$nick,$network.$encriptKeyToUse);
			$uid = $user_info['id'];
		}
	}
}

ob_end_clean();
if(isset($_GET['op'])) {
	header('Content-type: text/json');
	$id = $_GET['u'];
	$usr = $sql->query("SELECT name,power FROM users WHERE id='%s'",[$id],0);
	if(base64_decode(strtr($_GET['nick'],'-_,','+/='))==$usr['name'] && $usr['power']&2){
		echo json_encode(Array(
			'group' => 'true'
		));
	}else{
		echo json_encode(Array(
			'group' => 'false'
		));
	}
}elseif(isset($_GET['time'])){
	header('Content-Type: text/json');
	echo json_encode(Array(
		'time' => time()
	));
}else{
	if(isset($_GET['txt'])){
		echo $signature."\n".$nick."\n".$uid;
	}elseif (isset($_GET['textmode'])){
		header('Location: '.$oircUrl.'/textmode.php?login&nick='.base64_url_encode($nick).'&signature='.base64_url_encode($signature).'&id='.$uid.(isset($_GET['network'])?'&network='.(int)$_GET['network']:''));
	}else{
		header('Content-Type: text/json');
		$json = json_encode(Array(
			'nick' => $nick,
			'signature' => $signature,
			'uid' => $uid
		));
		if(isset($_GET['jsoncallback'])){
			echo $_GET['jsoncallback'].'('.$json.')';
		}else{
			echo $json;
		}
	}
}
?>
