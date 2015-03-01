<?php
class Sql{
	private $mysqliConnection;
	private $queryNum;
	private $curDb;
	public function __construct(){
		$this->queryNum = 0;
		$this->mysqliConnection = false;
		$this->curDb = NULL;
	}
	private function connectSql(){
		global $vars;
		if($this->mysqliConnection !== false){
			return $this->mysqliConnection;
		}
		if($this->curDb==NULL){
			$this->curDb = $vars->get('sql_database');
		}
		$mysqli = new mysqli($vars->get('sql_host'),$vars->get('sql_user'),$vars->get('sql_password'),$this->curDb);
		if ($mysqli->connect_errno){
			die('Could not connect to SQL DB: '.$mysqli->connect_errno.' '.$mysqli->connect_error);
		}
		$mysqli->autocommit(true);
		$this->mysqliConnection = $mysqli;
		return $mysqli;
	}
	public function query($query,$args = [],$num = false,$queryMode = MYSQLI_STORE_RESULT){
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
			$result = $mysqli->query(vsprintf($query,$args),$queryMode);
			if($mysqli->errno==1065){ //empty
				$result->free();
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
			$result->free();
			return $res;
		}
	}
	public function getQueryNum(){
		return $this->queryNum;
	}
	public function switchDb($db){
		$this->curDb = $db;
		return $this->connectSql()->select_db($db);
	}
	public function insertId(){
		$mysqli = $this->connectSql();
		return $mysqli->insert_id;
	}
}
$sql = new Sql();
?>