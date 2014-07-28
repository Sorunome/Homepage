<?php
class Sql{
	private $mysqliConnection;
	private $queryNum;
	public function __construct(){
		$this->queryNum = 0;
		$this->mysqliConnection = false;
	}
	private function connectSql(){
		global $options;
		if($this->mysqliConnection !== false){
			return $this->mysqliConnection;
		}
		$mysqli = new mysqli($options->get('sql_host'),$options->get('sql_user'),$options->get('sql_password'),$options->get('sql_database'));
		if ($mysqli->connect_errno){
			die('Could not connect to SQL DB: '.$mysqli->connect_errno.' '.$mysqli->connect_error);
		}
		$mysqli->autocommit(true);
		$this->mysqliConnection = $mysqli;
		return $mysqli;
	}
	public function query($query,$args = [],$num = false){
		$mysqli = $this->connectSql();
		for($i=0;$i<count($args);$i++)
			$args[$i] = $mysqli->real_escape_string($args[$i]);
		$this->queryNum++;
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
			if($mysqli->errno==1065){ //empty
				return array();
			}
			if($mysqli->errno!=0){
				die($mysqli->error.' Query: '.vsprintf($query,$args));
			}
			if($result===true){ //nothing returned
				return array();
			}
			$res = array();
			$i = 0;
			while($row = $result->fetch_assoc()){
				$res[] = $row;
				if($num!==false && $i===$num){
					$result->free();
					return $row;
				}
				if($i++>=1000)
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
	public function getQueryNum(){
		return $this->queryNum;
	}
}
$sql = new Sql();
?>