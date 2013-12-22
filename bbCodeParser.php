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
	private $allowedTags = Array();
	public function returnBB($t,$s,$a) {
		return $this->tags[0]->returnBB($t,$s,$a,$this);
	}
	private function getTagContent($type,$s,$attrs) {
		$type = strtolower($type);
		if(($this->allowedTags[0]=='*' && !in_array($type,$this->allowedTags))||($this->allowedTags[0]!='*' && in_array($type,$this->allowedTags)))
			if($this->tagExists($type))
				foreach($this->tags as $tag)
					if($tag->isType($type))
						return $tag->getHTML($type,$s,$attrs,$this);
		return $this->returnBB($type,$s,$attrs);
	}
	private function getAttributes($s) {
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
		if ($this->tagExists($type))
			return false;
		$this->tags[] = new bbParserTag($type,$function,$attrs,$help);
		return true;
	}
	public function parse($s,$attr=true) {
		if(gettype($attr)=='array'){
			$this->allowedTags = $attr;
			$br = true;
		}else{
			$br = $attr;
		}
		preg_match_all('/()\[([a-zA-Z0-9]+)(|=[^\]\[]+)( [^\]\[]+=[^\]\[]+)*\]()/i', $s, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
		$tags = Array();
		$i = 0;
		foreach ($matches as $match) {
			$tags[$i]["start"] = $match[0][1];
			$tags[$i]["type"] = $match[2][0];
			$tags[$i]["attribute"] = substr($match[3][0],1);
			$tags[$i]["end"] = $match[5][1];
			$tags[$i]["endTagPos"] = -1;
			$tags[$i]["resultHTML"] = "";
			$i++;
		}
		for ($i = sizeof($tags)-1;$i>=0;$i--) {
			$startPos = $tags[$i]["start"];
			for ($j = $i;$j<sizeof($tags);$j++) {
				if ($j != sizeof($tags)-1)
					$lastPos = $tags[$j+1]["start"];
				else
					$lastPos = strlen($s);
				if ($find = strpos(substr($s,$startPos,$lastPos-$startPos),"[/".$tags[$i]["type"]."]")) {
					$lastFind = $tags[$j]["endTagPos"]-$startPos;
					if ($find!=$lastFind) {
						$tags[$i]["endTagPos"] = $find+$startPos;
						break;
					} else {
						$startPos += $find+1;
						$j--;
					}
				}
			}
		}
		$firstTime = true;
		$oldTags = [];
		while(true){
			$reducedTags = [];
			$change = false;
			for ($i=0;$i<sizeof($tags);$i++){
				if (sizeof($tags)<=1 || ($i!=0 && $tags[$i]['endTagPos']>$tags[$i-1]['endTagPos']) || $i==0){
					$change = true;
					if (sizeof($tags)<=1)
						$change = false;
					$reducedTags[] = $tags[$i];
				}
			}
			$tags = $reducedTags;
			if ($tags==$oldTags && !$firstTime)
				break;
			$firstTime = false;
			$oldTags = $tags;
		}
		if (sizeof($tags)!=0) {
			$newS = substr($s,0,$tags[0]['start']);
			if($br)
				$newS = str_replace("\n",'<br>',$newS);
			for ($i = 0;$i<sizeof($tags);$i++) {
				$attrs = $this->getAttributes(substr($s,$tags[$i]['start']+1,$tags[$i]['end']-$tags[$i]['start']-2));
				$newS .= $this->getTagContent($tags[$i]['type'],substr($s,$tags[$i]['end'],$tags[$i]['endTagPos']-$tags[$i]['end']),$attrs);
				if ($i<sizeof($tags)-1) {
					$temp = $tags[$i]['endTagPos']+strlen($tags[$i]['type'])+3;
					$temp2 = htmlspecialchars(substr($s,$temp,$tags[$i+1]['start']-$temp));
					if($br)
						$newS .= str_replace("\n",'<br>',$temp2);
					else
						$newS .= $temp2;
				}
				if ($i == sizeof($tags)-1){
					$temp2 = htmlspecialchars(substr($s,$tags[$i]['endTagPos']+strlen($tags[$i]['type'])+3));
					if($br)
						$newS .= str_replace("\n",'<br>',$temp2);
					else
						$newS .= $temp2;
				}
			}
		}else{
			$newS = htmlspecialchars($s);
			if($br)
				$newS = str_replace("\n",'<br>',$newS);
		}
		return $newS;
	}
}
?>