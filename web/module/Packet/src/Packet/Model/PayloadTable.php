<?php
namespace Packet\Model;

class PayloadTable
{
    private PayloadTableGateway $tableGateway;

    public function __construct(PayloadTableGateway $tableGateway)
    {
        $this->tableGateway = $tableGateway;
    }

    // 按feature_id查询一条payload索引记录
    public function fetchByFeatureId(int $featureId): ?array
    {
        $rowset = $this->tableGateway->select(['feature_id' => $featureId]);
        $row = $rowset->current();

        return $row ? (array) $row : null;
    }
}
