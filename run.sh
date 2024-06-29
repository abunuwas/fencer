#! bin/bash
# 使用此腳本來執行fencer工具,所需輸入的指令
# python3 -m fencer.cli run --oas-file A --base-url B
file=$1
url=$2

python3 -m fencer.cli run --oas-file $file --base-url $url