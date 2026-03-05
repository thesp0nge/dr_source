<?php
// VULNERABLE: INSECURE_DESERIALIZATION
$data = $_GET['data'];
unserialize($data);

// VULNERABLE: SSTI (Twig example)
$loader = new \Twig\Loader\ArrayLoader();
$twig = new \Twig\Environment($loader);
$template = $twig->createTemplate("Hello " . $_GET['name']);
echo $template->render();
?>
