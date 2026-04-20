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
