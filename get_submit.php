<?php


include __DIR__."/protector.php";


$PROTECTOR = new PROTECTOR;


//CHECK FOR MALICIOUS DATA
if( isset($_GET) && !empty($_GET) ){


	foreach ($_GET as $key => $data) {


			$PROTECTOR->Check_Blacklisted($data);


	}


}



$servername = "localhost";
$username = "root";
$password = "toor";
$dbname = "dbstore";

if( isset($_GET['id']) ){


		$id = $PROTECTOR->Clean_FromXSS($_GET['id']);

		$conn = new mysqli($servername, $username, $password, $dbname);

		if ($conn->connect_error) {
		  die("Connection failed: " . $conn->connect_error);
		}


		$sql = "SELECT * FROM transactions__histories WHERE id=".$id."";
		$result = $conn->query($sql);

		if ($result->num_rows > 0) {

		  while($row = $result->fetch_assoc()) {

		    	print_r($row);

		  }

		} else {

		  echo "0 results";

		}

		$conn->close();


}

?>