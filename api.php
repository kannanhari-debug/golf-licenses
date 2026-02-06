<?php
// api.php - Secure server-side handler
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

$github_token = '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';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $action = $data['action'] ?? '';
    
    switch($action) {
        case 'save_license':
            $response = saveLicenseToGitHub($data, $github_token);
            break;
        case 'track_access':
            $response = saveTrackingData($data, $github_token);
            break;
        case 'load_licenses':
            $response = loadLicensesFromGitHub($github_token);
            break;
        default:
            $response = ['error' => 'Invalid action'];
    }
    
    echo json_encode($response);
}

function saveLicenseToGitHub($data, $token) {
    $license = $data['license'];
    $deviceId = $license['device_id'];
    
    $url = "https://api.github.com/repos/kannanhari-debug/golf-licenses/contents/licenses/{$deviceId}.json";
    
    $content = json_encode($license, JSON_PRETTY_PRINT);
    $sha = $data['sha'] ?? null;
    
    $payload = [
        'message' => $data['message'] ?? "Update license for {$license['username']}",
        'content' => base64_encode($content)
    ];
    
    if ($sha) {
        $payload['sha'] = $sha;
    }
    
    return makeGitHubRequest($url, $token, $payload);
}

function saveTrackingData($data, $token) {
    $type = $data['type']; // unauthorized, expired, authorized
    $date = date('Y-m-d');
    
    $url = "https://api.github.com/repos/kannanhari-debug/golf-licenses/contents/tracking/{$type}/{$date}.json";
    
    // Try to get existing data
    $existing = getExistingFile($url, $token);
    $trackingData = $data['data'];
    
    if ($existing && isset($existing['content'])) {
        $currentData = json_decode(base64_decode($existing['content']), true);
        if (!is_array($currentData)) {
            $currentData = [];
        }
        $currentData[] = $trackingData;
        $content = json_encode($currentData, JSON_PRETTY_PRINT);
        $sha = $existing['sha'];
    } else {
        $content = json_encode([$trackingData], JSON_PRETTY_PRINT);
        $sha = null;
    }
    
    $payload = [
        'message' => "Track {$type} access: {$trackingData['device_id']}",
        'content' => base64_encode($content),
        'sha' => $sha
    ];
    
    return makeGitHubRequest($url, $token, $payload);
}

function loadLicensesFromGitHub($token) {
    $url = "https://api.github.com/repos/kannanhari-debug/golf-licenses/contents/licenses";
    
    $response = makeGitHubRequest($url, $token, null, 'GET');
    
    if (isset($response['error'])) {
        return ['licenses' => []];
    }
    
    $licenses = [];
    foreach ($response as $file) {
        if (strpos($file['name'], '.json') !== false) {
            $licenseUrl = $file['download_url'];
            $licenseData = json_decode(file_get_contents($licenseUrl), true);
            if ($licenseData) {
                $licenses[] = $licenseData;
            }
        }
    }
    
    return ['licenses' => $licenses];
}

function getExistingFile($url, $token) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: token ' . $token,
            'User-Agent: PHP-Script',
            'Accept: application/vnd.github.v3+json'
        ]
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

function makeGitHubRequest($url, $token, $payload = null, $method = 'PUT') {
    $ch = curl_init($url);
    
    $headers = [
        'Authorization: token ' . $token,
        'User-Agent: PHP-Script',
        'Accept: application/vnd.github.v3+json'
    ];
    
    if ($payload) {
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    }
    
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $headers
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    return json_decode($response, true) ?: ['error' => 'Request failed', 'code' => $httpCode];
}
?>
