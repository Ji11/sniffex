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

    public function indexAction(): ViewModel
    {
        $rows = $this->featureTable->fetchAllWithPayloads();

        foreach ($rows as &$row) {
            $row['payload_content'] = $this->payloadReader->readBlock($row['file_path'], (int) $row['file_offset']);
            $row['image_data_uri'] = null;
            $row['text_body'] = null;
            if ($row['content_type'] === 'image/png') {
                $row['image_data_uri'] = $this->payloadReader->extractImageDataUri($row['payload_content'], $row['content_type']);
            } elseif ($row['content_type'] === 'text/plain') {
                $row['text_body'] = $this->payloadReader->extractTextBody($row['payload_content']);
            }
        }
        unset($row);

        return new ViewModel([
            'packets' => $rows,
        ]);
    }
}
