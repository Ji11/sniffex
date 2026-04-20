#!/bin/bash
mysql -h 127.0.0.1 -u root -p123456 -e "USE packet_capture; DELETE FROM payload; DELETE FROM feature; ALTER TABLE payload AUTO_INCREMENT=1; ALTER TABLE feature AUTO_INCREMENT=1;"
rm -f ~/sniffex/data/payload.log
echo "Cleared."
