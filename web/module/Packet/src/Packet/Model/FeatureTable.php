<?php
namespace Packet\Model;

use Laminas\Db\Adapter\AdapterInterface;
use Laminas\Db\Sql\Sql;

class FeatureTable
{
    private FeatureTableGateway $tableGateway;
    private AdapterInterface $adapter;

    public function __construct(FeatureTableGateway $tableGateway, AdapterInterface $adapter)
    {
        $this->tableGateway = $tableGateway;
        $this->adapter = $adapter;
    }

    // 联表查询feature和payload，返回页面展示所需字段
    public function fetchAllWithPayloads(): array
    {
        $sql = new Sql($this->adapter);
        $select = $sql->select(['f' => $this->tableGateway->getTable()]);
        $select->columns([
            'id',
            'src_ip',
            'dst_ip',
            'src_port',
            'dst_port',
            'content_type',
            'payload_size',
        ]);
        $select->join(
            ['p' => 'payload'],
            'p.feature_id = f.id',
            ['file_path', 'file_offset', 'data_type'],
            $select::JOIN_INNER
        );
        $select->order('f.id ASC');

        $statement = $sql->prepareStatementForSqlObject($select);
        $result = $statement->execute();

        // 把查询结果整理成普通数组返回给控制器
        $rows = [];
        foreach ($result as $row) {
            $rows[] = $row;
        }

        return $rows;
    }
}
