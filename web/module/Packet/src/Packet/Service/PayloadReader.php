<?php
namespace Packet\Service;

class PayloadReader
{
    // 从payload.log指定偏移开始读取一整个报文块
    public function readBlock(string $filePath, int $offset): string
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return 'Payload file is missing or unreadable.';
        }

        $fp = fopen($filePath, 'rb');
        if ($fp === false) {
            return 'Failed to open payload file.';
        }

        // 报文块以=== End Packet x ===的分隔符结尾，所以从offset开始读，直到遇到下一个分隔符为止
        if (fseek($fp, $offset) !== 0) {
            fclose($fp);
            return 'Failed to seek payload file.';
        }

        $buffer = '';
        while (!feof($fp)) {
            $line = fgets($fp);
            if ($line === false) {
                break;
            }

            $buffer .= $line;
            if (preg_match('/^=== End Packet \d+ ===$/', rtrim($line))) {
                break;
            }
        }

        fclose($fp);
        return trim($buffer);
    }

    // 从payload.log里的一整个报文块中还原HTTP响应体
    public function extractHttpBody(string $block): ?string
    {
        // 先定位十六进制原始数据区，后面的解析都只针对这部分内容
        $rawStart = strpos($block, "--- RAW DATA ---\n");
        if ($rawStart === false) {
            return null;
        }
        $rawStart += strlen("--- RAW DATA ---\n");

        // 再定位原始数据区的结束位置，通常到PARSED INFO前为止
        $rawEnd = strpos($block, "\n\n--- PARSED INFO ---", $rawStart);
        if ($rawEnd === false) {
            $rawEnd = strpos($block, "\n--- PARSED INFO ---", $rawStart);
        }
        if ($rawEnd === false) {
            $rawEnd = strlen($block);
        }

        // 截出纯十六进制打印区域，并按行拆开逐行处理
        $hexSection = substr($block, $rawStart, $rawEnd - $rawStart);
        $lines = explode("\n", $hexSection);

        // 把十六进制字节重新还原成原始二进制串
        $bytes = '';
        foreach ($lines as $line) {
            $line = rtrim($line);
            if ($line === '') {
                continue;
            }

            // 只处理 hexdump 数据行，跳过标题行和其他说明文字
            if (!preg_match('/^\d{5}\s/', $line)) {
                continue;
            }

            // 每行尾部有ASCII预览，用三个空格分隔，这里先找到分界点
            $asciiSep = strrpos($line, '   ');
            if ($asciiSep === false) {
                continue;
            }

            // 偏移量占前8个字符，截出中间的十六进制区域再按空白切成token
            $hexPart = substr($line, 8, $asciiSep - 8);
            $hexTokens = preg_split('/\s+/', trim($hexPart));
            foreach ($hexTokens as $hex) {
                // 只接受两位十六进制字节，避免把别的文本误当成数据
                if (preg_match('/^[0-9a-fA-F]{2}$/', $hex)) {
                    $bytes .= chr((int) hexdec($hex));
                }
            }
        }

        // 如果一字节都没还原出来，说明这个块里没有可用的原始HTTP数据
        if (strlen($bytes) === 0) {
            return null;
        }

        // HTTP头和body之间用空行分隔，也就是\r\n\r\n
        $headerEnd = strpos($bytes, "\r\n\r\n");
        if ($headerEnd === false) {
            return null;
        }

        // 跳过分隔符本身，返回真正的响应体内容
        $body = substr($bytes, $headerEnd + 4);
        return strlen($body) > 0 ? $body : null;
    }

    // 把图片body按照base64转成可直接嵌入页面的data URI
    public function extractImageDataUri(string $block, string $contentType): ?string
    {
        $body = $this->extractHttpBody($block);
        if ($body === null) {
            return null;
        }

        return 'data:' . $contentType . ';base64,' . base64_encode($body);
    }

    // 提取纯文本响应体给页面直接展示
    public function extractTextBody(string $block): ?string
    {
        return $this->extractHttpBody($block);
    }
}
