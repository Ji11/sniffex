<?php
return [
    'db' => [
        'driver' => 'Pdo_Mysql',
        'hostname' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => (int)(getenv('DB_PORT') ?: 3306),
        'database' => getenv('DB_NAME') ?: 'packet_capture',
        'username' => getenv('DB_USER') ?: 'root',
        'password' => getenv('DB_PASS') ?: '',
        'charset' => 'utf8mb4',
    ],
    'payload_log' => realpath(__DIR__ . '/../../../data/payload.log') ?: (__DIR__ . '/../../../data/payload.log'),
];
