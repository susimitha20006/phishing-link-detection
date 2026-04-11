<?php
session_start();
$con = new mysqli("localhost", "root", "", "susiii");

if ($con->connect_error) {
    die("DB connection failed: " . $con->connect_error);
}



$input = strtolower($_POST['inputText']);
$score = 0;
$reason = array();

// Rule 1: Length check
if (strlen($input) > 75) {
    $score += 35;
    $reason []= "The length of the link is large";
}

// Rule 2: Special characters
if (preg_match("/@|-/i", $input)) {
    $score += 35;
    $reason [] = "The link has suspicious characters";
}

// Rule 3: Urgent words
$urgentWords = array("urgent", "verify", "login", "blocked", "account", "password", "confirm");
foreach ($urgentWords as $word) {
    if (strpos($input, $word) !== false) {
        $score += 75;
        $reason [] = "It has urgent words";
        break;
    }
}

// Rule 4: Fake domain words
$fakeDomain = array("microsoft", "python", "google", "facebook");
foreach ($fakeDomain as $w) {
    if (strpos($input, $w) !== false) {
        $score += 75;
        $reason  = "It has wrong domain words";
        break;
    }
}

// Limit score to 100
if ($score > 100) {
    $score = 100;
}

// Decide status
if ($score >= 60) {
    $status = "High risk-Likely phishing";
    $color = "red";
} elseif ($score >= 30) {
    $status = "Medium risk-Suspicious";
    $color = "yellow";
}elseif ($score >0) {
    $status = "low risk-some issues";
    $color = "yellow";
} else {
    $status = "Likely safe";
    $color = "green";
}

// Save to DB
$stmt = $con->prepare("INSERT INTO ss(input_text, score, status) VALUES (?, ?, ?)");
$stmt->bind_param("sis", $input, $score, $status);
$stmt->execute();
$stmt->close();
$con->close();

// Store in session
$_SESSION['status'] = $status;
$_SESSION['color'] = $color;
$_SESSION['score'] = $score;
$_SESSION['reason'] = $reason;

header("Location: result.php");
exit();
?>