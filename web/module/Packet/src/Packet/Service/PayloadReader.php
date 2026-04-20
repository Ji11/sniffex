<?php
namespace Packet\Service;

class PayloadReader
{
    public function readBlock(string $filePath, int $offset): string
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return 'Payload file is missing or unreadable.';
        }

        $fp = fopen($filePath, 'rb');
        if ($fp === false) {
            return 'Failed to open payload file.';
        }

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

    public function extractHttpBody(string $block): ?string
    {
        $rawStart = strpos($block, "--- RAW DATA ---\n");
        if ($rawStart === false) {
            return null;
        }
        $rawStart += strlen("--- RAW DATA ---\n");

        $rawEnd = strpos($block, "\n\n--- PARSED INFO ---", $rawStart);
        if ($rawEnd === false) {
            $rawEnd = strpos($block, "\n--- PARSED INFO ---", $rawStart);
        }
        if ($rawEnd === false) {
            $rawEnd = strlen($block);
        }

        $hexSection = substr($block, $rawStart, $rawEnd - $rawStart);
        $lines = explode("\n", $hexSection);

        $bytes = '';
        foreach ($lines as $line) {
            $line = rtrim($line);
            if ($line === '') {
                continue;
            }

            if (!preg_match('/^\d{5}\s/', $line)) {
                continue;
            }

            $asciiSep = strrpos($line, '   ');
            if ($asciiSep === false) {
                continue;
            }

            $hexPart = substr($line, 8, $asciiSep - 8);
            $hexTokens = preg_split('/\s+/', trim($hexPart));
            foreach ($hexTokens as $hex) {
                if (preg_match('/^[0-9a-fA-F]{2}$/', $hex)) {
                    $bytes .= chr((int) hexdec($hex));
                }
            }
        }

        if (strlen($bytes) === 0) {
            return null;
        }

        $headerEnd = strpos($bytes, "\r\n\r\n");
        if ($headerEnd === false) {
            return null;
        }

        $body = substr($bytes, $headerEnd + 4);
        return strlen($body) > 0 ? $body : null;
    }

    public function extractImageDataUri(string $block, string $contentType): ?string
    {
        $body = $this->extractHttpBody($block);
        if ($body === null) {
            return null;
        }

        return 'data:' . $contentType . ';base64,' . base64_encode($body);
    }

    public function extractTextBody(string $block): ?string
    {
        return $this->extractHttpBody($block);
    }
}
