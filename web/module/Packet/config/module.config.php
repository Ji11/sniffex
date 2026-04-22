<?php

use Laminas\Db\Adapter\Adapter;
use Laminas\Db\ResultSet\ResultSet;
use Packet\Controller\IndexController;
use Packet\Model\FeatureTable;
use Packet\Model\FeatureTableGateway;
use Packet\Model\PayloadTable;
use Packet\Model\PayloadTableGateway;
use Packet\Service\PayloadReader;

return [
    // 配置首页路由，把根路径交给IndexController
    'router' => [
        'routes' => [
            'home' => [
                'type' => 'Literal',
                'options' => [
                    'route' => '/',
                    'defaults' => [
                        'controller' => IndexController::class,
                        'action' => 'index',
                    ],
                ],
            ],
        ],
    ],
    // 注册控制器工厂，注入查询表和payload读取服务
    'controllers' => [
        'factories' => [
            IndexController::class => function ($container) {
                return new IndexController(
                    $container->get(FeatureTable::class),
                    $container->get(PayloadReader::class)
                );
            },
        ],
    ],
    // 注册数据库适配器、TableGateway和业务服务
    'service_manager' => [
        'factories' => [
            Adapter::class => function ($container) {
                return new Adapter($container->get('config')['db']);
            },
            FeatureTableGateway::class => function ($container) {
                return new FeatureTableGateway(
                    'feature',
                    $container->get(Adapter::class),
                    null,
                    new ResultSet()
                );
            },
            PayloadTableGateway::class => function ($container) {
                return new PayloadTableGateway(
                    'payload',
                    $container->get(Adapter::class),
                    null,
                    new ResultSet()
                );
            },
            FeatureTable::class => function ($container) {
                return new FeatureTable(
                    $container->get(FeatureTableGateway::class),
                    $container->get(Adapter::class)
                );
            },
            PayloadTable::class => function ($container) {
                return new PayloadTable($container->get(PayloadTableGateway::class));
            },
            PayloadReader::class => function () {
                return new PayloadReader();
            },
        ],
    ],
    // 配置错误页和Packet模块视图目录
    'view_manager' => [
        'display_not_found_reason' => true,
        'display_exceptions' => true,
        'not_found_template' => 'error/404',
        'exception_template' => 'error/index',
        'template_map' => [
            'layout/layout' => __DIR__ . '/../../Application/view/layout/layout.phtml',
            'error/404' => __DIR__ . '/../../Application/view/error/404.phtml',
            'error/index' => __DIR__ . '/../../Application/view/error/index.phtml',
        ],
        'template_path_stack' => [
            __DIR__ . '/../view',
        ],
    ],
];
