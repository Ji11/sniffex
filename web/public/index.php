<?php
// 切到web根目录，保证后续相对路径可用
chdir(dirname(__DIR__));

// 加载自动加载器
require 'vendor/autoload.php';

// 读取应用配置并启动MVC
$appConfig = require 'config/application.config.php';
Laminas\Mvc\Application::init($appConfig)->run();
