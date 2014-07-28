<?php
header('Content-type: text/xml');
echo '<?xml version="1.0" encoding="UTF-8" ?>';
?>
<rss version="2.0">
<channel>

<title>Sorunome</title>
<link>http://www.sorunome.de/</link>
<description>Everything about Sorunome</description>
<language>en</language>
<pubDate>24.12.2011</pubDate>
<lastBuildDate><?php $now = time(); echo $now; ?></lastBuildDate>
<docs>http://www.sorunome.de/rssfeed.php</docs>
<generator>Rss Feed Engine</generator>
<managingEditor>mail@sorunome.de</managingEditor>
<webMaster>mail@sorunome.de</webMaster>
<?php
$res = $sql->query("SELECT `id`,`news_en`,`ts` FROM news ORDER BY ts DESC LIMIT 5");
foreach($res as $r){
	echo '<item>
<title>'.date('jS F Y',strtotime($r['ts'])).'</title>
<link>'.$_SERVER['HTTP_HOST'].'#news'.$r['id'].'</link>
<description><![CDATA['.$bbParser->parse($r['news_en'],['*']).']]></description>
<pubDate>'.date('D, d M Y H:i:s O',strtotime($r['ts'])).'</pubDate>
<guide>'.$_SERVER['HTTP_HOST'].'#news'.$r['id'].'</guide>
</item>';
}

?>

</channel>
</rss>