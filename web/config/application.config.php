<?php
return [
    'modules' => [
        'Laminas\\Router',
        'Laminas\\Validator',
        'Packet',
    ],
    'module_listener_options' => [
        'config_glob_paths' => [
            __DIR__ . '/autoload/{,*.}{global,local}.php',
        ],
        'module_paths' => [
            realpath(__DIR__ . '/../module'),
            realpath(__DIR__ . '/../vendor'),
        ],
    ],
];
