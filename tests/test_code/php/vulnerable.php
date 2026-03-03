<?php
// PHP Test Case for DRSource

// 1. SQL Injection (VULNERABLE)
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $query);

// 2. Command Injection (VULNERABLE)
$cmd = $_POST['cmd'];
system("ping -c 1 " . $cmd);

// 3. XSS (VULNERABLE)
$name = $_REQUEST['name'];
echo "<h1>Hello " . $name . "</h1>";

// 4. Constant Propagation (SAFE - Should be ignored)
$safe_table = "logs";
$safe_query = "SELECT * FROM " . $safe_table;
mysqli_query($conn, $safe_query);

// 5. Boolean Engine Test ($X == $X bug)
if ($a == $a) {
    echo "Logical error";
}
?>
