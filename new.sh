#!/usr/bin/env bash
# 사용: ./new.sh 문제이름 http://대상주소:포트 '플래그형식'
set -e
cd "$(dirname "$0")"
NAME="$1"; TARGET="$2"; DEF_FMT='Layer7{...}'; FMT="${3:-$DEF_FMT}"
[ -z "$NAME" ] || [ -z "$TARGET" ] && { echo "사용: ./new.sh 문제이름 http://대상:포트 '플래그형식'"; exit 1; }
[ -e "$NAME" ] && { echo "이미 있음: $NAME"; exit 1; }
cp -R _template "$NAME"
sed -i '' -e "s|^# 문제 이름|# $NAME|" -e "s|^대상: http://|대상: $TARGET|" -e "s|^플래그 형식:|플래그 형식: $FMT|" "$NAME/notes.md"
sed -i '' -e "s|^# 문제 이름|# $NAME|" -e "s|^시작 시각:|시작 시각: $(date '+%m-%d %H:%M')|" "$NAME/notes.md" "$NAME/writeup.md"
echo "만듦: $NAME  (소스는 $NAME/src/ 에 풀기)"
