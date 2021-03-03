<?php

set_time_limit(0);
error_reporting(0);

class PROTECTOR {

  	public $dir_logs = __DIR__ . "/logs";

	public $logs_block = "blacklisted.txt";

	public function getIp() {

	    if (filter_var(@$_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP)) {
	      return $_SERVER['HTTP_CLIENT_IP'];
	    } elseif (filter_var(@$_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
	      return $_SERVER['HTTP_X_FORWARDED_FOR'];
	    } else {
	      return $_SERVER['REMOTE_ADDR'];
	    }

	}

	public function getUseragent() {

	    return $_SERVER['HTTP_USER_AGENT'];
	    
	}

	public function getOs() {

	    $os = "Unknown OS";
	    $os_array = array(
	      '/windows nt 10/i'      =>  'Windows 10',
	      '/windows nt 6.3/i'     =>  'Windows 8.1',
	      '/windows nt 6.2/i'     =>  'Windows 8',
	      '/windows nt 6.1/i'     =>  'Windows 7',
	      '/windows nt 6.0/i'     =>  'Windows Vista',
	      '/windows nt 5.2/i'     =>  'Windows Server 2003/XP x64',
	      '/windows nt 5.1/i'     =>  'Windows XP',
	      '/windows xp/i'         =>  'Windows XP',
	      '/windows nt 5.0/i'     =>  'Windows 2000',
	      '/windows me/i'         =>  'Windows ME',
	      '/win98/i'              =>  'Windows 98',
	      '/win95/i'              =>  'Windows 95',
	      '/win16/i'              =>  'Windows 3.11',
	      '/macintosh|mac os x/i' =>  'Mac OS X',
	      '/mac_powerpc/i'        =>  'Mac OS 9',
	      '/linux/i'              =>  'Linux',
	      '/ubuntu/i'             =>  'Ubuntu',
	      '/iphone/i'             =>  'iPhone',
	      '/ipod/i'               =>  'iPod',
	      '/ipad/i'               =>  'iPad',
	      '/android/i'            =>  'Android',
	      '/blackberry/i'         =>  'BlackBerry',
	      '/webos/i'              =>  'Mobile'
	    );
	    foreach ($os_array as $regex => $value) {
	      if (preg_match($regex, $_SERVER['HTTP_USER_AGENT'])) {
	        $os = $value;
	      }
	    }
	    return $os;
	}

	public function getBrowser() {

	    $browser = "Unknown Browser";
	    $browser_array = array(
	      '/msie/i'       =>  'Internet Explorer',
	      '/firefox/i'    =>  'Firefox',
	      '/safari/i'     =>  'Safari',
	      '/chrome/i'     =>  'Chrome',
	      '/edge/i'       =>  'Edge',
	      '/opera/i'      =>  'Opera',
	      '/netscape/i'   =>  'Netscape',
	      '/maxthon/i'    =>  'Maxthon',
	      '/konqueror/i'  =>  'Konqueror',
	      '/mobile/i'     =>  'Handheld Browser'
	    );
	    foreach ($browser_array as $regex => $value) {
	      if (preg_match($regex, $_SERVER['HTTP_USER_AGENT'])) {
	        $browser = $value;
	      }
	    }
	    return $browser;
	}

    public function DateNow() {

      return date('d-m-Y g:i a');

    }

 	public function save($file, $text, $type) {

	    $fp = fopen($file, $type);
	    return fwrite($fp, $text);
	    fclose($fp);
	    chmod($file, 0666);
  	}


	public function get($url) {

	    $curl = curl_init();
	    $option = [
	      CURLOPT_SSL_VERIFYPEER  => false,
	      CURLOPT_RETURNTRANSFER  => true,
	      CURLOPT_URL             => $url,
	      CURLOPT_USERAGENT       => $this->getUseragent(),
	      CURLOPT_COOKIEJAR       => $this->dir_logs.'/cookie.txt',
	      CURLOPT_COOKIEFILE      => $this->dir_logs.'/cookie.txt'
	    ];
	    curl_setopt_array($curl, $option);
	    $data = curl_exec($curl);
	    $type = curl_getinfo($curl, CURLINFO_CONTENT_TYPE);
	    $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
	    curl_close($curl);
	    return array(
	      'data'      => $data,
	      'type'      => $type,
	      'decode'    => json_decode($data, true),
	      'httpcode'  => $httpcode
	    );

	}

    public function getGeo() {

      $data   = $this->get('http://www.geoplugin.net/json.gp?ip='.$this->getIp().'')['decode'];
      
      $country        = $data["geoplugin_countryName"];
      $countryCode    = $data["geoplugin_countryCode"];

      return array(
        'country'           => $country,
        'country_code'      => $countryCode
      );
      

    }

    public function detected(){

        $ip = $this->getIp();
	    $country = $this->getGeo()['country'];    
        $useragent = $this->getUseragent();
        $os = $this->getOs();
        $br = $this->getBrowser();
        $date = $this->DateNow();

        $message = "[BANNED] IP: {$ip} | COUNTRY : {$country} | USER-AGENT : {$useragent} | VISITOR: {$os} | {$br}  DATE: {$date} \r\n";

        $this->save($this->dir_logs.'/'.$this->logs_block,$message,"a+"); 

        header('HTTP/1.0 403 Forbidden');
    	die("<html><head> <title>403 Forbidden</title> </head><body> <h1>Forbidden</h1> <p>You don't have permission to access this resource.</p> <p>Additionally, a 403 Forbidden error was encountered while trying to use an ErrorDocument to handle the request.</p> </body></html>");


    }


	public function CheckForBOTS_CRAWLERS() {

	      if (preg_match('/bot|crawl|curl|Semrush|sucuri|dataprovider|search|get|spider|Xovibot|Sogou|TelegramBot|SEOkicks|SemrushBot-BA|Crawler|masscan|linkdexbot|netcraft|NetcraftSurveyAgent|Netcraft|find|java|majesticsEO|teoma|contaxe|libwww-perl|008|ABACHOBot|Accoona-AI-Agent|AddSugarSpiderBot|AnyApexBot|Arachmo|B-l-i-t-z-B-O-T|Baiduspider|BecomeBot|BeslistBot|BillyBobBot|Bimbot|BlitzBOT|boitho.com-dc|boitho.com-robot|btbot|CatchBot|Cerberian Drtrs|Charlotte|ConveraCrawler|cosmos|Covario IDS|DataparkSearch|DiamondBot|Discobot|Dotbot|EARTHCOM.info|EmeraldShield.com WebBot|envolk|EsperanzaBot|SiftScience|Awex|Exabot|FAST Enterprise Crawler|FAST-WebCrawler|FDSE robot|FindLinks|FurlBot|FyberSpider|g2crawler|Gaisbot|symantec|GalaxyBot|genieBot|Gigabot|Girafabot|GurujiBot|HappyFunBot|hl_ftien_spider|Holmes|htdig|iaskspider|ia_archiver|iCCrawler|ichiro|igdeSpyder|IRLbot|IssueCrawler|Jaxified Bot|Jyxobot|KoepaBot|L.webis|LapozzBot|Larbin|LDSpider|LexxeBot|Linguee Bot|LinkWalker|lmspider|lwp-trivial|mabontland|magpie-crawler|Mediapartners-Google|MJ12bot|MLBot|Mnogosearch|mogimogi|MojeekBot|Moreoverbot|Morning Paper|msnbot|MSRBot|MVAClient|mxbot|NetResearchServer|NetSeer Crawler|NewsGator|NG-Search|nicebot|noxtrumbot|Nusearch Spider|NutchCVS|Nymesis|obot|oegp|omgilibot|OmniExplorer_Bot|OOZBOT|Orbiter|PageBitesHyperBot|Peew|polybot|Pompos|PostPost|Psbot|PycURL|Qseero|Radian6|RAMPyBot|safe|RufusBot|HeadlessChrome|DigitalOcean|SandCrawler|SBIder|ScoutJet|Scrubby|SearchSight|Seekbot|semanticdiscovery|Sensis Web Crawler|SEOChat::Bot|SeznamBot|Shim-Crawler|ShopWiki|Shoula robot|silk|Sitebot|Snappy|sogou spider|Sosospider|Speedy Spider|Sqworm|StackRambler|suggybot|SurveyBot|SynooBot|Teoma|TerrawizBot|TheSuBot|Thumbnail.CZ robot|TinEye|truwoGPS|TurnitinBot|TweetedTimes Bot|TwengaBot|updated|Urlfilebot|Vagabondo|VoilaBot|Vortex|voyager|VYU2|webcollage|Websquash.com|wf84|WoFindeIch Robot|WomlpeFactory|Xaldon_WebSpider|yacy|sqlmap|sql|crawler|Yahoo! Slurp|Yahoo! Slurp China|YahooSeeker|YahooSeeker-Testing|YandexMetrika|Yasaklibot|Yeti|YodaoBot|Netcraft|yoogliFetchAgent|YoudaoBot|Zao|Zealbot|zspider|ZyBorg/i', $this->getUseragent())) {

	      			$this->detected();

	        }

	}


	public function Check_Blacklisted($data){


			$this->CheckForBOTS_CRAWLERS();

	        $blocked_sqli = array(
	          "UNION",
	          "SELECT",
	          "NULL,NULL,",
	          "%20",
	          "%27",
	          "CONCAT",
	          "0X",
	          "--",
	          "'",
	          "SCRIPT",
	          "XSS",
	          "ALERT",
	          "COOKIE",
	          "-- +",
	          "BENCHMARK",
	          "CMD/",
	          "BIN/",
	          "SYSTEM(",
	          "ORDER BY",
	          "GROUP_CONTACT",
	          "INFORMATION_SCHEMA",
	          "0X0A",
	          "EXEC",
	          "'or'",
	          '"or"',
	          "or 1=1",
	          "1=1",
	          "2=2",
	          "or a=a",
	          '"'
	            );

	          foreach($blocked_sqli as $word) {

	              if (substr_count(strtoupper($data), $word) > 0) {


	              		$this->detected();

	              }  
	          } 



	}


	public function Clean_FromXSS($data){

		$data = htmlspecialchars($data);
		$data = stripcslashes($data);
		$data = strip_tags($data);

		return $data;

	}





}




?>