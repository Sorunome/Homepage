<?php
$bbParser = new bbParser();
$bbParser->addTag('b',function($type,$s,$attrs,$bbParser){
	return '<b>'.$bbParser->parse($s).'</b>';
},[],'bold');
$bbParser->addTag('i',function($type,$s,$attrs,$bbParser){
	return '<i>'.$bbParser->parse($s).'</i>';
},[],'italic');
$bbParser->addTag('url',function($type,$s,$attrs,$bbParser){
	if (isset($attrs['url'])) {
		if (filter_var($attrs['url'],FILTER_VALIDATE_URL) || filter_var('http://www.sorunome.de/'.$attrs['url'],FILTER_VALIDATE_URL))
			return '<a href="'.$attrs['url'].'">'.$bbParser->parse($s).'</a>';
		return $bbParser->returnBB($type,$s,$attrs);
	}
	if (filter_var($s,FILTER_VALIDATE_URL) || filter_var('http://www.sorunome.de/'.$s,FILTER_VALIDATE_URL))
		return '<a href="'.$s.'">'.$s.'</a>';
	return $bbParser->returnBB($type,$s,$attrs);
},['url'],'Display URL');
$bbParser->addTag('img',function($type,$s,$attrs,$bbParser){
	if (filter_var($s,FILTER_VALIDATE_URL) || filter_var('http://www.sorunome.de/'.$s,FILTER_VALIDATE_URL)) {
		$alt = $s;
		if (isset($attrs['alt']))
			$alt = htmlspecialchars($attrs['alt']);
		$style = '';
		if (isset($attrs['width']) && preg_match('/^[0-9]+(px|%)$/i',$attrs['width']))
			$style .= 'width:'.$attrs['width'].';';
		if (isset($attrs['height']) && preg_match('/^[0-9]+(px|%)$/i',$attrs['height']))
			$style .= 'height:'.$attrs['height'].';';
		return '<img src="'.$s.'" alt="'.$alt.'" style="margin:0;padding:0;'.$style.'">';
	}
	return $bbParser->returnBB($type,$s,$attrs);
},['width','height','alt'],'Display Image');
$bbParser->addTag('center',function($type,$s,$attrs,$bbParser){
	return '<div style="text-align:center;width:100%;">'.$bbParser->parse($s).'</div>'."\r\b\r";
},[],'centers content');
$bbParser->addTag('p',function($type,$s,$attrs,$bbParser){
	return '<p>'.$bbParser->parse($s).'</p>';
},[],'paragraph');
$bbParser->addTag('table',function($type,$s,$attrs,$bbParser){
	return '<table style="border:none;">'.$bbParser->parse($s,false).'</table>';
},[],'table');
$bbParser->addTag('tr',function($type,$s,$attrs,$bbParser){
	return '<tr>'.$bbParser->parse($s,false).'</tr>';
},[],'tr');
$bbParser->addTag('td',function($type,$s,$attrs,$bbParser){
	return '<td>'.$bbParser->parse($s).'</td>';
},[],'td');
$bbParser->addTag('list',function($type,$s,$attrs,$bbParser){
	return '<ul>'.$bbParser->parse($s,false).'</ul>';
},[],'list');
$bbParser->addTag('li',function($type,$s,$attrs,$bbParser){
	return '<li>'.$bbParser->parse($s).'</li>';
},[],'li');
$bbParser->addTag('youtube',function($type,$s,$attrs,$bbParser){
	if(strpos($s,'&')===false && strpos($s,'"')===false && strpos($s,"'")===false && strpos($s,'<')===false)
		return '<iframe style="width:560px;height:315px;border-style:none;" src="https://www.youtube.com/embed/'.$s.'" allowfullscreen></iframe>';
	return $bbParser->returnBB($type,$s,$attrs);
},[],'youtube video');
$bbParser->addTag('slideshow',function($type,$s,$attrs,$bbParser){
	if(isset($attrs['slideshow']) && preg_match('/^[0-9]+$/',$attrs['slideshow']))
		return '<iframe style="width:100%;height:600px;border-style:none;" src="/webdeveloping/slideshow/?embed=newest&amp;collection='.$attrs['slideshow'].'" allowfullscreen></iframe>';
	if(filter_var('http://www.sorunome.de/?='.$s,FILTER_VALIDATE_URL) && strpos($s,'&')===false)
		return '<iframe style="width:100%;height:600px;border-style:none;" src="/webdeveloping/slideshow/?embed=newest&amp;pics='.$s.'" allowfullscreen></iframe>';
	return $bbParser->returnBB($type,$s,$attrs);
},['slideshow'],'slideshow!');
$bbParser->addTag('h1',function($type,$s,$attrs,$bbParser){
	return '<h1>'.$bbParser->parse($s).'</h1>'."\r\b\r";
},[],'h1');
$bbParser->addTag('h2',function($type,$s,$attrs,$bbParser){
	return '<h2>'.$bbParser->parse($s).'</h2>'."\r\b\r";
},[],'h2');
$bbParser->addTag('instructables',function($type,$s,$attrs,$bbParser){
	if(!preg_match('/^[a-zA-Z0-9-+]+$/',$s))
		return $bbParser->returnBB($type,$s,$attrs);
	return '<div id="iblemain"></div><script type="text/javascript" src="http://ibles.sorunome.de/ible.php?id='.$s.'&idPrev=ible&js"></script>';
},[],'Instructables embed');
$bbParser->addTag('instruction',function($type,$s,$attrs,$bbParser){
	if(!preg_match('/^[0-9]+$/',$s)){
		return $bbParser->returnBB($type,$s,$attrs);
	}
	return '<div id="instructionInstructionMain"></div><script type="text/javascript" src="http://www.sorunome.de/webdeveloping/instruction/?id='.$s.'&idPrev=instruction&js"></script>';
},[],'makes an instruction');
$bbParser->addTag('nobbc',function($type,$s,$attrs,$bbParser){
	return htmlspecialchars($s);
},[],'Escapes bb-code');
$bbParser->addTag('html',function($type,$s,$attrs,$bbParser){
	return $s;
},[],'HTML');
?>
