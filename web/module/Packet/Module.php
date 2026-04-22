<?php
namespace Packet;

class Module
{
    // 返回Packet模块的配置数组
    public function getConfig(): array
    {
        return include __DIR__ . '/config/module.config.php';
    }
}
