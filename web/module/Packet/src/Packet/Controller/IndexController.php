<?php
namespace Packet\Controller;

use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use Packet\Model\FeatureTable;
use Packet\Service\PayloadReader;

class IndexController extends AbstractActionController
{
    private FeatureTable $featureTable;
    private PayloadReader $payloadReader;

    public function __construct(FeatureTable $featureTable, PayloadReader $payloadReader)
    {
        $this->featureTable = $featureTable;
        $this->payloadReader = $payloadReader;
    }

    // 查询抓包记录并补齐页面展示需要的payload内容
    public function indexAction(): ViewModel
    {
        // 联表查询feature和payload，返回页面展示所需字段查询结果
        $rows = $this->featureTable->fetchAllWithPayloads();

        // 按content-type补出图片预览或文本正文
        foreach ($rows as &$row) {
            // 对于数据库中每一行，都按照file路径和offset从payload.log读报文块
            $row['payload_content'] = $this->payloadReader->readBlock($row['file_path'], (int) $row['file_offset']);
            $row['image_data_uri'] = null;
            $row['text_body'] = null;
            // 如果是图片，就从报文块里提取图片数据并转换成URI解析；如果是文本，就提取文本正文内容
            if ($row['content_type'] === 'image/png') {
                $row['image_data_uri'] = $this->payloadReader->extractImageDataUri($row['payload_content'], $row['content_type']);
            } elseif ($row['content_type'] === 'text/plain') {
                $row['text_body'] = $this->payloadReader->extractTextBody($row['payload_content']);
            }
        }
        unset($row);

        // 把整理好的抓包数据交给视图模板
        return new ViewModel([
            'packets' => $rows,
        ]);
    }
}
