#!/bin/bash
# 새 문제 폴더를 만든다.
# 사용법: ./new.sh 문제이름 http://대상 '플래그형식'
# 예:     ./new.sh babyweb http://chall.example.com:1337 'flag{...}'
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "사용법: $0 문제이름 http://대상 '플래그형식'" >&2
  echo "예:     $0 babyweb http://chall.example.com:1337 'flag{...}'" >&2
  exit 1
fi
name=$1; target=$2; fmt=$3

cd "$(dirname "$0")"

case "$name" in
  ""|*/*|.*|_template) echo "문제이름이 올바르지 않다: $name" >&2; exit 1 ;;
esac
case "$target" in
  http://*|https://*) ;;
  *) echo "대상 주소는 http:// 또는 https://로 시작해야 한다: $target" >&2; exit 1 ;;
esac
if [ -e "$name" ]; then
  echo "이미 있다: $name" >&2; exit 1
fi

cp -R _template "$name"
find "$name" -name .DS_Store -delete

# sed 치환 문자열에서 특수 문자(\ & |)를 이스케이프한다.
esc() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }
now=$(date '+%Y-%m-%d %H:%M %Z')

sed -i '' \
  -e "s|^- 대상 주소:.*|- 대상 주소: $(esc "$target")|" \
  -e "s|^- 플래그 형식:.*|- 플래그 형식: $(esc "$fmt")|" \
  -e "s|^- 시작 시각:.*|- 시작 시각: $(esc "$now")|" \
  "$name/scope.md"
chmod +x "$name/solve.py" "$name/check_hypotheses.py"

echo "만들었다: $name/"
echo "다음: $name/scope.md 나머지 칸(종류, 이름, 문제 페이지, 캡처, 규칙 원문)을 채우고, 받은 파일은 $name/src/에 넣는다."
