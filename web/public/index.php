<?php
chdir(dirname(__DIR__));

require 'vendor/autoload.php';

$appConfig = require 'config/application.config.php';
Laminas\Mvc\Application::init($appConfig)->run();
