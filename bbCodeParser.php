<?php
class bbParserTag {
	private $type;
	private $functionToCall;
	private $attrs;
	private $help;
	public function returnBB($type,$s,$attrs,$p) {
		$str = "";
		foreach ($attrs as $attr => $cont) {
			if ($cont!=NULL)
				$str .= " $attr=$cont";
			else
				unset($attrs[$attr]);
		}
		if (isset($attrs[$type]))
			return "[".substr($str,1)."]".$p->parse($s)."[/$type]";
		return "[$type$str]".$p->parse($s)."[/$type]";
	}
	private function inArray($a,$v) {
		foreach ($a as $e) {
			if ($e==$v) {
				return true;
			}
		}
		return false;
	}
	private function correctAttrs($t,$a) {
		foreach ($a as $key => $value) {
			if (!$this->inArray($this->attrs,$key))
				if (!($key==$t && $value==NULL))
					return false;
		}
		return true;
	}
	public function __construct($t,$f,$a,$h) {
		$this->type = $t;
		$this->functionToCall = $f;
		$this->attrs = $a;
		$this->help = $h;
	}
	public function getHTML($t,$s,$a,$p) {
		if ($t!=$this->type) return false;
		$fn = $this->functionToCall;
		if ($this->correctAttrs($t,$a))
			return $fn($t,$s,$a,$p);
		else
			return $this->returnBB($t,$s,$a,$p);
	}
	public function isType($t) {
		if ($t==$this->type)
			return true;
		return false;
	}
}
class bbParser {
	private $tags = Array();
	private $allowedTags = Array('*');
	public function returnBB($t,$s,$a) {
		return $this->tags[0]->returnBB($t,$s,$a,$this);
	}
	private function getTagContent($type,$s,$attrs) {
		$type = strtolower($type);
		if($this->tagExists($type)){
			foreach($this->tags as $tag){
				if($tag->isType($type)){
					return $tag->getHTML($type,$s,$attrs,$this);
				}
			}
		}
		return $this->returnBB($type,$s,$attrs);
	}
	private function getAttributes($s) { // TODO: use regex
		$s = htmlspecialchars($s);
		$temp = explode("=",$s);
		$attrs = Array();
		for ($j=0;$j<sizeof($temp);$j++) {
			if ($j==0) {
				if (isset($temp[$j+1]) && isset($temp[$j+2]) && $temp2 = strrpos($temp[$j+1]," ")) {
					if ($temp3 = strrpos($temp[$j]," "))
						$attrs[strtolower(substr($temp[$j],$temp3+1))] = substr($temp[$j+1],0,$temp2);
					else
						$attrs[strtolower($temp[$j])] = substr($temp[$j+1],0,$temp2);
				} else {
					if (isset($temp[$j+1])) {
						if (($temp3 = strrpos($temp[$j]," "))!==false)
							$attrs[strtolower(substr($temp[$j],$temp3+1))] = $temp[$j+1];
						else
							$attrs[strtolower($temp[$j])] = $temp[$j+1];
					} else
						$attrs[strtolower($temp[$j])] = NULL;
				}
			} elseif (isset($temp[$j+1]) && $temp2 = strrpos($temp[$j]," ")) {
				if (isset($temp[$j+1]) && $temp3 = strrpos($temp[$j+1]," "))
					$attrs[strtolower(substr($temp[$j],$temp2+1))] = substr($temp[$j+1],0,$temp3);
				else
					$attrs[strtolower(substr($temp[$j],$temp2+1))] = $temp[$j+1];
			}
		}
		return $attrs;
	}
	private function tagExists($type) {
		foreach ($this->tags as $tag)
			if ($tag->isType($type))
				return true;
		return false;
	}
	public function addTag($type,$function,$attrs,$help) {
		$type = strtolower($type);
		if($this->tagExists($type)){
			return false;
		}
		$this->tags[] = new bbParserTag($type,$function,$attrs,$help);
		return true;
	}
	public function parse($s,$br=true){
		if(is_array($br)){
			$this->allowedTags = $br;
			$br = true;
		}
		preg_match_all('/()\[([a-zA-Z0-9]+)(|=[^\]\[]+)( [^\]\[]+=[^\]\[]+)*\]()/i',$s,$matches,PREG_SET_ORDER | PREG_OFFSET_CAPTURE); // find all start tags
		$tags = Array();
		$i = 0;
		foreach($matches as $match){ // grab all tags
			$tags[$i]["start"] = $match[0][1];
			$tags[$i]["type"] = $match[2][0];
			$tags[$i]["attribute"] = substr($match[3][0],1);
			$tags[$i]["end"] = $match[5][1];
			$tags[$i]["endTagPos"] = -1;
			$tags[$i]["resultHTML"] = "";
			$i++;
		}
		for($i = sizeof($tags)-1;$i>=0;$i--){ // find the corresponding close tag, pay attention to nesting and store the size of the string inside
			$startPos = $tags[$i]["start"];
			for($j = $i;$j<sizeof($tags);$j++){ // basically loop through the entirepart to find the last closing tag
				if($j != sizeof($tags)-1){ // get the starting pos of the next tag, else get the end position of the string
					$lastPos = $tags[$j+1]["start"];
				}else{
					$lastPos = strlen($s);
				}
				if($find = strpos(substr(strtolower($s),$startPos,$lastPos-$startPos),"[/".$tags[$i]["type"]."]")){ // find the end tag, if it exists
					$lastFind = $tags[$j]["endTagPos"]-$startPos;
					if($find!=$lastFind) {
						$tags[$i]["endTagPos"] = $find+$startPos;
						break;
					}else{
						$startPos += $find+1;
						$j--;
					}
				}
			}
		}
		$firstTime = true;
		$oldTags = [];
		while(true){ // only fetch the first level tags
			$reducedTags = [];
			for($i=0;$i<sizeof($tags);$i++){ // loop through all tags to only fetch the outer ones
				if((sizeof($tags)<=1 || ($i!=0 && $tags[$i]['endTagPos']>$tags[$i-1]['endTagPos']) || $i==0 )){
					$reducedTags[] = $tags[$i];
				}
			}
			$tags = $reducedTags;
			if($tags==$oldTags && !$firstTime){
				break;
			}
			$firstTime = false;
			$oldTags = $tags;
		}
		if(sizeof($tags)!=0){ // parse the actual tags
			$newS = substr($s,0,$tags[0]['start']); // stuff before the first tag
			if($br){
				$newS = str_replace("\n",'<br>',$newS);
			}
			for($i = 0;$i<sizeof($tags);$i++){ // loop through all tags
				if(($this->allowedTags[0] == '*' xor in_array($tags[$i]['type'],$this->allowedTags))){ // check if tag is allowed
					$attrs = $this->getAttributes(substr($s,$tags[$i]['start']+1,$tags[$i]['end']-$tags[$i]['start']-2)); // fetch the attributes of the tag
					$newS .= $this->getTagContent($tags[$i]['type'],substr($s,$tags[$i]['end'],$tags[$i]['endTagPos']-$tags[$i]['end']),$attrs); // parse it to the handler
				}else{
					$newS .= htmlspecialchars(substr($s,$tags[$i]['start'],$tags[$i]['end']-$tags[$i]['start'])).
							$this->parse(substr($s,$tags[$i]['end'],$tags[$i]['endTagPos']-$tags[$i]['end'])).
							htmlspecialchars(substr($s,$tags[$i]['endTagPos'],strlen($tags[$i]['type'])+3)); // well, just return the tag how it was before
				}
				if($i<sizeof($tags)-1){ // escape text before tag
					$temp = $tags[$i]['endTagPos']+strlen($tags[$i]['type'])+3;
					$temp2 = htmlspecialchars(substr($s,$temp,$tags[$i+1]['start']-$temp));
					if($temp2 != '' && $temp2[0] == "\n"){ // don't have a <br> on initial linebreak
						$temp2 = substr($temp2,1);
					}
					if($br){
						$newS .= str_replace("\n",'<br>',$temp2);
					}else{
						$newS .= $temp2;
					}
				}
				if($i == sizeof($tags)-1){ // escape text after last tag
					$temp2 = htmlspecialchars(substr($s,$tags[$i]['endTagPos']+strlen($tags[$i]['type'])+3));
					if($temp2 != '' && $temp2[0] == "\n"){ // don't have a <br> on initial linebreak
						$temp2 = substr($temp2,1);
					}
					if($br){
						$newS .= str_replace("\n",'<br>',$temp2);
					}else{
						$newS .= $temp2;
					}
				}
			}
		}else{
			$newS = htmlspecialchars($s);
			if($br){
				$newS = str_replace("\n",'<br>',$newS);
			}
		}
		
		$newS = str_replace("\n",'',$newS); // HTML doesn't need these, so get rid of 'em
		$newS = str_replace("\r",'',$newS);
		$newS = str_replace("\t",'',$newS);
		
		if(substr($newS,0,4)=='<br>'){ // stripe too much <br>
			$newS = substr($newS,4);
		}
		if(substr($newS,strlen($newS)-4)=='<br>'){
			$newS = substr($newS,0,strlen($newS)-4);
		}
		return $newS;
	}
}
?>