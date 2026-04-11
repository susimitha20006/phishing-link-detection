<?php
session_start();

$status = isset($_SESSION['status']) ? $_SESSION['status'] : 'Unknown';
$color  = isset($_SESSION['color']) ? $_SESSION['color'] : 'gray';
$score  = isset($_SESSION['score']) ? $_SESSION['score'] : 0;
$reason = isset($_SESSION['reason']) ? $_SESSION['reason'] : array();
?>

<!DOCTYPE html>
<html>
<head>
<title>Detection Result</title>
<style>
body {
    margin:0;
    font-family: Arial, sans-serif;
    background: #0f172a;
    color: white;
    display:flex;
    justify-content:center;
    align-items:center;
    height:100vh;
}

.card {
    width: 500px;
    padding: 30px;
    border-radius: 15px;
    background: #1e293b;
    box-shadow: 0 0 25px <?php echo $color; ?>;
    text-align:center;
}

h1 {
    margin-bottom:20px;
}

.status {
    font-size:22px;
    font-weight:bold;
    color: <?php echo $color; ?>;
}

.progress-container {
    background:#334155;
    border-radius:20px;
    overflow:hidden;
    margin:20px 0;
}

.progress-bar {
    height:20px;
    width:0;
    background: <?php echo $color; ?>;
    transition: width 1.5s ease-in-out;
}

ul {
    text-align:left;
}

.btn {
    display:inline-block;
    margin-top:20px;
    padding:10px 20px;
    background:#2563eb;
    color:white;
    text-decoration:none;
    border-radius:8px;
    transition:0.3s;
}

.btn:hover {
    background:#1d4ed8;
}
</style>
</head>

<body>

<div class="card">
    <h1>🔎 Detection Result</h1>

    <p class="status"><?php echo $status; ?></p>

    <div class="progress-container">
        <div class="progress-bar" id="bar"></div>
    </div>
    <p>Confidence Score: <?php echo $score; ?>%</p>

    <h3>Reasons:</h3>
    <ul>
        <?php
        if(!empty($reason)){
            foreach($reason as $r){
                echo "<li>⚠ $r</li>";
            }
        } else {
            echo "<li>✅ No suspicious patterns detected</li>";
        }
        ?>
    </ul>

    <a href="index.html" class="btn">Check Another Link</a>
</div>

<script>
window.onload = function() {
    document.getElementById("bar").style.width = "<?php echo $score; ?>%";
};
</script>

</body>
</html>